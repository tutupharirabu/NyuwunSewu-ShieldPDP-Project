import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse

from app.core.config import get_settings
from app.services.policy_engine import PolicyEngine


@dataclass(slots=True)
class ScopeDecision:
    allowed: bool
    reason: str
    normalized_url: str
    host: str | None = None


class ScopeGuard:
    def __init__(self, base_url: str, allowed_domains: list[str], policy: PolicyEngine):
        self.base_url = self.normalize_url(base_url)
        self.base_host = urlparse(self.base_url).hostname or ""
        self.allowed_domains = {
            host
            for domain in policy.scoped_domains(allowed_domains or [self.base_host])
            if (host := self.normalize_domain(domain))
        }
        self.policy = policy
        self.settings = get_settings()

    @staticmethod
    def normalize_domain(entry: str) -> str:
        """Reduce a scope entry to a bare hostname.

        Accepts full URLs (``https://host/path``), host:port, leading-dot
        wildcards, or bare hosts, and always returns the lowercased hostname
        so scope matching never breaks on a stray scheme or path.
        """
        entry = (entry or "").strip().lower()
        if not entry:
            return ""
        # urlparse needs a scheme to populate .hostname; add one for bare hosts.
        if "://" not in entry:
            entry = "//" + entry
        host = urlparse(entry).hostname or ""
        return host.strip(".")

    @staticmethod
    def normalize_url(url: str, base_url: str | None = None) -> str:
        joined = urljoin(base_url or url, url)
        parsed = urlparse(joined)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        normalized = parsed._replace(
            scheme=scheme, netloc=netloc, path=path, fragment=""
        )
        return urlunparse(normalized)

    def host_in_scope(self, host: str | None) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        return any(
            host == domain or host.endswith("." + domain)
            for domain in self.allowed_domains
        )

    async def _resolves_to_blocked_ip(self, host: str) -> bool:
        if self.settings.allow_private_targets:
            return False

        def resolve() -> list[str]:
            try:
                return [item[4][0] for item in socket.getaddrinfo(host, None)]
            except socket.gaierror:
                return []

        addresses = await asyncio.to_thread(resolve)
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return True
        return False

    async def explain_url_allowed(self, url: str) -> ScopeDecision:
        normalized = self.normalize_url(url, self.base_url)
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"}:
            return ScopeDecision(
                False, "URL scheme is not http or https", normalized, parsed.hostname
            )
        if not self.host_in_scope(parsed.hostname):
            return ScopeDecision(
                False,
                f"Host '{parsed.hostname}' is outside configured scope boundaries",
                normalized,
                parsed.hostname,
            )
        if self.policy.is_path_excluded(normalized):
            return ScopeDecision(
                False,
                "Path is excluded or forbidden by scan policy",
                normalized,
                parsed.hostname,
            )
        if await self._resolves_to_blocked_ip(parsed.hostname or ""):
            return ScopeDecision(
                False,
                "Host resolves to a private, loopback, reserved, or link-local address. "
                "Set ALLOW_PRIVATE_TARGETS=true only for authorized local lab targets.",
                normalized,
                parsed.hostname,
            )
        return ScopeDecision(True, "URL is in scope", normalized, parsed.hostname)

    async def is_url_allowed(self, url: str) -> bool:
        return (await self.explain_url_allowed(url)).allowed
