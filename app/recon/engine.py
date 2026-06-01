import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from app.core.config import get_settings
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.utils.redaction import redact_text


@dataclass(slots=True)
class ExtractedForm:
    action: str
    method: str
    fields: list[dict[str, str]]


@dataclass(slots=True)
class CrawledEndpoint:
    url: str
    method: str = "GET"
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    query_parameters: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    js_routes: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    response_body_sample: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    request_headers: dict[str, str] = field(default_factory=dict)
    http_version: str = "HTTP/1.1"
    response_reason: str = ""
    guest_status_code: int | None = None
    guest_content_type: str | None = None
    guest_response_body_sample: str = ""
    guest_response_headers: dict[str, str] = field(default_factory=dict)
    guest_request_headers: dict[str, str] = field(default_factory=dict)
    guest_http_version: str = "HTTP/1.1"
    guest_response_reason: str = ""
    discovery_source: str = "crawl"

    @property
    def normalized_path(self) -> str:
        parsed = urlparse(self.url)
        return parsed.path or "/"


class AsyncReconEngine:
    STANDARD_DISCOVERY_PATHS = (
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
    )
    API_ROUTE_RE = re.compile(
        r"""(?:"|')((?:/|\.\./|https?://)[A-Za-z0-9_./?&=%:#\-{}]+)(?:"|')"""
    )
    API_HINT_RE = re.compile(
        r"(/(?:api|v[0-9]+|auth|admin|users?|customers?|orders?|payment|transfer|profile|reports?)[A-Za-z0-9_./?&=%:#\-{}]*)",
        re.I,
    )
    JS_REQUEST_RE = re.compile(
        r"""(?:fetch\s*\(\s*|axios\.(?:get|post|put|patch|delete)\s*\(\s*|"""
        r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*)["']([^"']+)["']""",
        re.I,
    )
    FETCH_ACTION_RE = re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.I)
    JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")

    def __init__(
        self,
        *,
        base_url: str,
        allowed_domains: list[str],
        policy: PolicyEngine,
        headers: dict[str, str] | None = None,
        cookie_jar: aiohttp.CookieJar | None = None,
        initial_paths: list[str] | None = None,
        credential_auth: dict[str, str] | None = None,
    ):
        self.settings = get_settings()
        self.policy = policy
        self.scope_guard = ScopeGuard(base_url, allowed_domains, policy)
        self.base_url = self.scope_guard.base_url
        self.headers = headers or {}
        self.cookie_jar = cookie_jar
        self.initial_paths = initial_paths or []
        self.credential_auth = credential_auth or {}
        self.authenticated_headers: dict[str, str] = {}
        self.authenticated_cookie_header = ""
        self.auth_tokens: list[str] = []
        self.authentication_observation: CrawledEndpoint | None = None
        self.rate_limiter = AdaptiveRateLimiter(policy.policy.max_requests_per_second)
        self.stop_requested = False
        self.visited: set[str] = set()
        self.results: dict[str, CrawledEndpoint] = {}
        self.context_results: dict[str, set[str]] = {}
        self.diagnostics: dict[str, Any] = {
            "blocked_urls": [],
            "fetch_errors": [],
            "crawl_errors": [],
            "parse_errors": [],
            "forms_discovered": 0,
            "links_discovered": 0,
            "js_routes_discovered": 0,
            "api_routes_discovered": 0,
            "parameters_discovered": 0,
            "standard_resources_checked": 0,
            "missing_resources": 0,
            "initial_paths_requested": len(self.initial_paths),
            "authentication": {"status": "not_configured"},
            "contexts": {},
            "current_context": "pending",
        }
        self._lock = asyncio.Lock()

    async def crawl(self) -> list[CrawledEndpoint]:
        timeout = aiohttp.ClientTimeout(total=self.settings.request_timeout_seconds)
        if self.credential_auth:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=40, limit_per_host=8, ttl_dns_cache=300),
                headers={"user-agent": self.settings.user_agent},
                cookie_jar=aiohttp.CookieJar(unsafe=self.settings.allow_private_targets),
                raise_for_status=False,
            ) as guest_session:
                await self._crawl_context(guest_session, "guest")

            if self.stop_requested:
                return [self.results[url] for url in sorted(self.results)]
            self.visited.clear()
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=40, limit_per_host=8, ttl_dns_cache=300),
                headers={"user-agent": self.settings.user_agent, **self.headers},
                cookie_jar=self.cookie_jar,
                raise_for_status=False,
            ) as authenticated_session:
                if await self._authenticate(authenticated_session):
                    await self._crawl_context(authenticated_session, "authenticated")
                else:
                    self.diagnostics["authenticated_crawl_skipped"] = True
        else:
            context = "primary_header" if self.headers else "guest"
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=40, limit_per_host=8, ttl_dns_cache=300),
                headers={"user-agent": self.settings.user_agent, **self.headers},
                cookie_jar=self.cookie_jar,
                raise_for_status=False,
            ) as session:
                await self._crawl_context(session, context)
        return [self.results[url] for url in sorted(self.results)]

    def request_stop(self) -> None:
        self.stop_requested = True

    async def _crawl_context(self, session: aiohttp.ClientSession, access_context: str) -> None:
        self.diagnostics["current_context"] = access_context
        queue: asyncio.Queue[tuple[str, int, str]] = asyncio.Queue()
        for path in self.initial_paths[:20]:
            await queue.put((self.scope_guard.normalize_url(path, self.base_url), 0, "initial_path"))
        await queue.put((self.base_url, 0, "target"))
        origin = f"{urlparse(self.base_url).scheme}://{urlparse(self.base_url).netloc}"
        if self.policy.policy.max_pages > 1:
            for path in self.STANDARD_DISCOVERY_PATHS:
                await queue.put((urljoin(origin, path), 0, "standard"))
            self.diagnostics["standard_resources_checked"] = len(self.STANDARD_DISCOVERY_PATHS)
        workers = [
            asyncio.create_task(self._worker(session, queue, access_context))
            for _ in range(min(8, max(2, int(self.policy.policy.max_requests_per_second * 2))))
        ]
        await queue.join()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        self.diagnostics["contexts"][access_context] = {
            "endpoints_observed": len(self.context_results.get(access_context, set()))
        }

    async def _worker(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue[tuple[str, int, str]],
        access_context: str,
    ) -> None:
        while True:
            url, depth, source = await queue.get()
            try:
                await self._crawl_one(session, queue, url, depth, source, access_context)
            except Exception as exc:
                async with self._lock:
                    self.diagnostics["crawl_errors"].append(
                        {"url": url, "error": type(exc).__name__, "detail": str(exc)[:300]}
                    )
            finally:
                queue.task_done()

    async def _crawl_one(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue[tuple[str, int, str]],
        url: str,
        depth: int,
        source: str,
        access_context: str,
    ) -> None:
        if self.stop_requested:
            return
        normalized = self.scope_guard.normalize_url(url, self.base_url)
        async with self._lock:
            if normalized in self.visited or (
                normalized not in self.results and len(self.results) >= self.policy.policy.max_pages
            ):
                return
            self.visited.add(normalized)

        if depth > self.policy.policy.max_depth:
            return
        decision = await self.scope_guard.explain_url_allowed(normalized)
        if not decision.allowed:
            async with self._lock:
                self.diagnostics["blocked_urls"].append(
                    {"url": decision.normalized_url, "reason": decision.reason}
                )
            return

        endpoint = await self._fetch(session, normalized, source, access_context)
        if endpoint is None:
            return
        if endpoint.status_code in {404, 410}:
            async with self._lock:
                self.diagnostics["missing_resources"] += 1
            return

        async with self._lock:
            self.context_results.setdefault(access_context, set()).add(endpoint.url)
            self._store_endpoint(endpoint, access_context)

        if depth >= self.policy.policy.max_depth:
            return

        discovered = set(endpoint.links + endpoint.api_routes + endpoint.js_routes)
        for form in endpoint.forms:
            action = form.get("action")
            if action:
                discovered.add(self._form_discovery_url(action, form))

        for candidate in discovered:
            candidate_url = self.scope_guard.normalize_url(candidate, endpoint.url)
            async with self._lock:
                should_enqueue = (
                    candidate_url not in self.visited
                    and (
                        candidate_url in self.results
                        or len(self.results) + queue.qsize() < self.policy.policy.max_pages
                    )
                )
            decision = await self.scope_guard.explain_url_allowed(candidate_url)
            if should_enqueue and decision.allowed:
                await queue.put((candidate_url, depth + 1, "discovered"))
            elif not decision.allowed:
                async with self._lock:
                    self.diagnostics["blocked_urls"].append(
                        {"url": decision.normalized_url, "reason": decision.reason}
                    )

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        discovery_source: str = "crawl",
        access_context: str = "guest",
    ) -> CrawledEndpoint | None:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                await self.rate_limiter.wait()
                async with session.get(url, allow_redirects=True) as response:
                    content = await self._read_limited(response)
                    text = content.decode(response.charset or "utf-8", errors="replace")
                    self.rate_limiter.record_stable()
                    final_url = str(response.url)
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    content_type = headers.get("content-type", "")
                    endpoint = CrawledEndpoint(
                        url=final_url,
                        status_code=response.status,
                        content_type=content_type,
                        query_parameters=sorted(parse_qs(urlparse(final_url).query).keys()),
                        response_body_sample=redact_text(text, max_length=12000),
                        response_headers=headers,
                        request_headers={
                            key.lower(): value for key, value in response.request_info.headers.items()
                        },
                        http_version=f"HTTP/{response.version.major}.{response.version.minor}",
                        response_reason=response.reason or "",
                        discovery_source=discovery_source,
                    )
                    try:
                        self._enrich_endpoint(endpoint, text, content_type)
                    except Exception as exc:
                        async with self._lock:
                            self.diagnostics["parse_errors"].append(
                                {
                                    "url": final_url,
                                    "error": type(exc).__name__,
                                    "detail": str(exc)[:300],
                                }
                            )
                    if discovery_source in {"initial_path", "authentication_entry", "standard"}:
                        endpoint.tech_stack = sorted(
                            set(endpoint.tech_stack + [f"discovery:{discovery_source}"])
                        )
                    endpoint.tech_stack = sorted(
                        set(endpoint.tech_stack + [f"access:{access_context}"])
                    )
                    if access_context == "guest":
                        endpoint.guest_status_code = endpoint.status_code
                        endpoint.guest_content_type = endpoint.content_type
                        endpoint.guest_response_body_sample = endpoint.response_body_sample
                        endpoint.guest_response_headers = endpoint.response_headers
                        endpoint.guest_request_headers = endpoint.request_headers
                        endpoint.guest_http_version = endpoint.http_version
                        endpoint.guest_response_reason = endpoint.response_reason
                    return endpoint
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_error = exc
                self.rate_limiter.record_anomaly()
                await asyncio.sleep(0.25 * (2**attempt))
        if last_error:
            async with self._lock:
                self.diagnostics["fetch_errors"].append(
                    {"url": url, "error": type(last_error).__name__}
                )
            return CrawledEndpoint(
                url=url,
                status_code=None,
                content_type=None,
                response_body_sample=f"Fetch failed: {type(last_error).__name__}",
                discovery_source="fetch_error",
            )
        return None

    def _store_endpoint(self, endpoint: CrawledEndpoint, access_context: str) -> None:
        existing = self.results.get(endpoint.url)
        if existing is None:
            self.results[endpoint.url] = endpoint
            return

        endpoint.tech_stack = sorted(set(existing.tech_stack + endpoint.tech_stack))
        endpoint.links = sorted(set(existing.links + endpoint.links))
        endpoint.api_routes = sorted(set(existing.api_routes + endpoint.api_routes))
        endpoint.js_routes = sorted(set(existing.js_routes + endpoint.js_routes))
        endpoint.query_parameters = sorted(
            set(existing.query_parameters + endpoint.query_parameters)
        )
        if not endpoint.forms:
            endpoint.forms = existing.forms
        if access_context in {"authenticated", "primary_header"}:
            endpoint.guest_status_code = getattr(existing, "guest_status_code", None)
            endpoint.guest_content_type = getattr(existing, "guest_content_type", None)
            endpoint.guest_response_body_sample = getattr(existing, "guest_response_body_sample", "")
            endpoint.guest_response_headers = getattr(existing, "guest_response_headers", {})
            endpoint.guest_request_headers = getattr(existing, "guest_request_headers", {})
            endpoint.guest_http_version = getattr(existing, "guest_http_version", "HTTP/1.1")
            endpoint.guest_response_reason = getattr(existing, "guest_response_reason", "")
            self.results[endpoint.url] = endpoint
            return
        existing.tech_stack = endpoint.tech_stack
        existing.links = endpoint.links
        existing.api_routes = endpoint.api_routes
        existing.js_routes = endpoint.js_routes
        existing.query_parameters = endpoint.query_parameters
        if not existing.forms:
            existing.forms = endpoint.forms

    async def _read_limited(self, response: aiohttp.ClientResponse) -> bytes:
        content = bytearray()
        limit = self.settings.max_response_bytes
        while len(content) < limit:
            chunk = await response.content.read(min(65_536, limit - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        return bytes(content)

    async def _authenticate(self, session: aiohttp.ClientSession) -> bool:
        username = self.credential_auth.get("username", "")
        password = self.credential_auth.get("password", "")
        if not username or not password:
            return False
        login_path = self.credential_auth.get("login_path") or (
            self.initial_paths[0] if self.initial_paths else "/login"
        )
        login_url = self.scope_guard.normalize_url(login_path, self.base_url)
        decision = await self.scope_guard.explain_url_allowed(login_url)
        if not decision.allowed:
            self.diagnostics["authentication"] = {
                "status": "blocked_by_scope",
                "login_path": urlparse(login_url).path,
                "reason": decision.reason,
            }
            return False

        login_endpoint = await self._fetch(
            session, login_url, "authentication_entry", "authentication"
        )
        if login_endpoint is None:
            self.diagnostics["authentication"] = {
                "status": "login_page_unreachable",
                "login_path": urlparse(login_url).path,
            }
            return False
        form = next(
            (
                item
                for item in login_endpoint.forms
                if any(str(field.get("type", "")).lower() == "password" for field in item.get("fields", []))
            ),
            None,
        )
        if form is None:
            self.diagnostics["authentication"] = {
                "status": "login_form_not_detected",
                "login_path": urlparse(login_url).path,
                "response_status": login_endpoint.status_code,
            }
            return False
        method = str(form.get("method") or "POST").upper()
        json_action = self._javascript_json_login_action(login_endpoint)
        if json_action:
            method = "POST"
            action = json_action
            strategy = "javascript_json_token"
        elif method == "POST":
            action = str(form.get("action") or login_url)
            strategy = "html_form_post"
        else:
            self.diagnostics["authentication"] = {
                "status": "unsupported_login_form_method",
                "login_path": urlparse(login_url).path,
                "method": method,
                "reason": "Only POST or detected JavaScript JSON-token login is submitted automatically.",
            }
            return False

        fields = form.get("fields", [])
        username_field = self._authentication_username_field(fields)
        password_field = next(
            (
                str(field.get("name"))
                for field in fields
                if str(field.get("type", "")).lower() == "password" and field.get("name")
            ),
            None,
        )
        if not username_field or not password_field:
            self.diagnostics["authentication"] = {
                "status": "login_fields_not_detected",
                "login_path": urlparse(login_url).path,
            }
            return False
        action_decision = await self.scope_guard.explain_url_allowed(action)
        if not action_decision.allowed:
            self.diagnostics["authentication"] = {
                "status": "form_action_blocked_by_scope",
                "login_path": urlparse(login_url).path,
            }
            return False
        form_data = {
            str(field.get("name")): str(field.get("value") or "")
            for field in fields
            if field.get("name")
        }
        form_data[username_field] = username
        form_data[password_field] = password
        try:
            await self.rate_limiter.wait()
            request_kwargs: dict[str, Any] = (
                {"json": form_data} if strategy == "javascript_json_token" else {"data": form_data}
            )
            async with session.post(action, allow_redirects=True, **request_kwargs) as response:
                content = await self._read_limited(response)
                response_text = content.decode(response.charset or "utf-8", errors="replace")
                self.authentication_observation = CrawledEndpoint(
                    url=str(response.url),
                    method="POST",
                    status_code=response.status,
                    content_type=response.headers.get("content-type", ""),
                    response_body_sample=redact_text(response_text, max_length=12000),
                    response_headers={k.lower(): v for k, v in response.headers.items()},
                    request_headers={
                        key.lower(): value for key, value in response.request_info.headers.items()
                    },
                    http_version=f"HTTP/{response.version.major}.{response.version.minor}",
                    response_reason=response.reason or "",
                    discovery_source="authentication_submission",
                    tech_stack=["access:authenticated", "discovery:authentication_submission"],
                )
                token = (
                    self._extract_json_token(response_text)
                    if strategy == "javascript_json_token"
                    else None
                )
                if token:
                    self.authenticated_headers = {"authorization": f"Bearer {token}"}
                    session.headers.update(self.authenticated_headers)
                session_cookie_received = bool(session.cookie_jar.filter_cookies(response.url))
                self._capture_auth_material(session, response.url, response_text, token)
                authenticated = bool(token or session_cookie_received)
                self.diagnostics["authentication"] = {
                    "status": "authenticated" if authenticated else "submitted_unverified",
                    "strategy": strategy,
                    "login_path": urlparse(login_url).path,
                    "form_action": urlparse(action).path,
                    "response_status": response.status,
                    "final_path": urlparse(str(response.url)).path,
                    "session_cookie_received": session_cookie_received,
                    "bearer_token_received": bool(token),
                }
                return authenticated
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.rate_limiter.record_anomaly()
            self.diagnostics["authentication"] = {
                "status": "submission_failed",
                "login_path": urlparse(login_url).path,
                "error": type(exc).__name__,
            }
            return False

    def _javascript_json_login_action(self, endpoint: CrawledEndpoint) -> str | None:
        text = endpoint.response_body_sample
        lowered = text.lower()
        if "json.stringify" not in lowered or "application/json" not in lowered:
            return None
        match = self.FETCH_ACTION_RE.search(text)
        if match is None:
            return None
        return urljoin(endpoint.url, match.group(1))

    def _extract_json_token(self, text: str) -> str | None:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        for name in ("token", "access_token", "jwt"):
            token = payload.get(name)
            if isinstance(token, str) and token:
                return token
        return None

    def _capture_auth_material(
        self,
        session: aiohttp.ClientSession,
        url: str,
        response_text: str,
        token: str | None,
    ) -> None:
        tokens = set(self.auth_tokens)
        if token:
            tokens.add(token)
        tokens.update(match.group(0) for match in self.JWT_RE.finditer(response_text))

        cookies = session.cookie_jar.filter_cookies(url)
        if cookies:
            cookie_pairs = []
            for name, morsel in cookies.items():
                value = morsel.value
                cookie_pairs.append(f"{name}={value}")
                if self.JWT_RE.fullmatch(value):
                    tokens.add(value)
            self.authenticated_cookie_header = "; ".join(cookie_pairs)
        self.auth_tokens = sorted(tokens)

    def _authentication_username_field(self, fields: list[dict[str, str]]) -> str | None:
        candidates: list[tuple[int, str]] = []
        for field in fields:
            name = str(field.get("name") or "")
            field_type = str(field.get("type") or "text").lower()
            if not name or field_type in {"password", "hidden", "submit", "button"}:
                continue
            score = 10
            lowered = name.lower()
            if any(token in lowered for token in ("user", "email", "login", "account")):
                score = 100
            candidates.append((score, name))
        return max(candidates, default=(0, ""))[1] or None

    def _enrich_endpoint(self, endpoint: CrawledEndpoint, text: str, content_type: str) -> None:
        endpoint.tech_stack = self._fingerprint(
            endpoint.response_headers, text, endpoint.url, content_type
        )
        parsed_path = urlparse(endpoint.url).path.lower()
        lowered_content_type = content_type.lower()
        if "html" in lowered_content_type or (
            "xml" not in lowered_content_type and "<html" in text[:1000].lower()
        ):
            soup = BeautifulSoup(text, "lxml")
            title = soup.find("title")
            endpoint.title = title.get_text(" ", strip=True)[:512] if title else None
            endpoint.links = self._extract_links(soup, endpoint.url)
            endpoint.forms = [
                {"action": form.action, "method": form.method, "fields": form.fields}
                for form in self._extract_forms(soup, endpoint.url)
            ]
            endpoint.js_routes = self._extract_js_routes(text, endpoint.url)
        if "javascript" in lowered_content_type or endpoint.url.endswith(".js"):
            endpoint.js_routes = self._extract_js_routes(text, endpoint.url)
        if parsed_path.endswith("/robots.txt"):
            endpoint.links = sorted(set(endpoint.links + self._extract_robots_routes(text, endpoint.url)))
        if "xml" in lowered_content_type or parsed_path.endswith((".xml", ".xml.gz")):
            endpoint.links = sorted(set(endpoint.links + self._extract_sitemap_routes(text)))
        endpoint.api_routes = self._extract_api_routes(text, endpoint.url)
        if "json" in lowered_content_type or parsed_path.endswith(".json"):
            api_fields, json_routes = self._profile_json_response(text, endpoint.url)
            endpoint.tech_stack = sorted(set(endpoint.tech_stack + api_fields))
            endpoint.api_routes = sorted(set(endpoint.api_routes + json_routes))
        self.diagnostics["forms_discovered"] += len(endpoint.forms)
        self.diagnostics["links_discovered"] += len(endpoint.links)
        self.diagnostics["js_routes_discovered"] += len(endpoint.js_routes)
        self.diagnostics["api_routes_discovered"] += len(endpoint.api_routes)
        self.diagnostics["parameters_discovered"] += len(endpoint.query_parameters)

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        links: set[str] = set()
        tag_attributes = {
            "a": "href",
            "link": "href",
            "script": "src",
            "img": "src",
            "iframe": "src",
            "source": "src",
            "object": "data",
            "form": "action",
        }
        for tag in soup.find_all(list(tag_attributes)):
            attr = tag_attributes[tag.name]
            value = tag.get(attr)
            if value and not value.lower().startswith(("javascript:", "mailto:", "tel:", "#")):
                links.add(urljoin(base_url, value))
        for tag in soup.find_all(True):
            for attr in ("data-url", "data-href", "data-endpoint", "data-api", "data-route"):
                value = tag.get(attr)
                if value and not value.lower().startswith(("#", "javascript:")):
                    links.add(urljoin(base_url, value))
        return sorted(links)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list[ExtractedForm]:
        forms: list[ExtractedForm] = []
        for form in soup.find_all("form"):
            fields: list[dict[str, str]] = []
            for field in form.find_all(["input", "select", "textarea"]):
                name = field.get("name")
                if not name:
                    continue
                field_type = (field.get("type") or field.name or "text")[:60]
                raw_value = field.get("value") or ""
                value_limit = 12000 if field_type.lower() == "hidden" else 120
                fields.append(
                    {
                        "name": name[:120],
                        "type": field_type,
                        "value": raw_value[:value_limit],
                    }
                )
            forms.append(
                ExtractedForm(
                    action=urljoin(base_url, form.get("action") or base_url),
                    method=(form.get("method") or "GET").upper(),
                    fields=fields,
                )
            )
        return forms

    def _form_discovery_url(self, action: str, form: dict[str, Any]) -> str:
        return action

    def _extract_api_routes(self, text: str, base_url: str) -> list[str]:
        routes = {urljoin(base_url, match.group(1)) for match in self.API_ROUTE_RE.finditer(text)}
        routes.update(urljoin(base_url, match.group(1)) for match in self.API_HINT_RE.finditer(text))
        return sorted(route for route in routes if len(route) < 2048)

    def _extract_js_routes(self, text: str, base_url: str) -> list[str]:
        routes = set()
        for match in self.API_ROUTE_RE.finditer(text):
            candidate = match.group(1)
            if any(marker in candidate.lower() for marker in ("/api", "/auth", "/admin", "/user", "/customer", "/order")):
                routes.add(urljoin(base_url, candidate))
        routes.update(urljoin(base_url, match.group(1)) for match in self.JS_REQUEST_RE.finditer(text))
        return sorted(route for route in routes if len(route) < 2048)

    def _extract_robots_routes(self, text: str, base_url: str) -> list[str]:
        routes: set[str] = set()
        for line in text.splitlines():
            key, separator, value = line.partition(":")
            if not separator or key.strip().lower() not in {"allow", "disallow", "sitemap"}:
                continue
            candidate = value.strip().split("#", 1)[0].strip()
            if candidate and candidate != "/":
                routes.add(urljoin(base_url, candidate))
        return sorted(routes)

    def _extract_sitemap_routes(self, text: str) -> list[str]:
        soup = BeautifulSoup(text, "xml")
        return sorted(
            {node.get_text(strip=True) for node in soup.find_all("loc") if node.get_text(strip=True)}
        )

    def _profile_json_response(self, text: str, base_url: str) -> tuple[list[str], list[str]]:
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            return [], []
        fields: set[str] = set()
        routes: set[str] = set()

        def inspect(value: Any, depth: int = 0) -> None:
            if depth > 3:
                return
            if isinstance(value, dict):
                for key, nested in list(value.items())[:30]:
                    fields.add(str(key)[:80])
                    inspect(nested, depth + 1)
            elif isinstance(value, list):
                for nested in value[:3]:
                    inspect(nested, depth + 1)
            elif isinstance(value, str) and value.startswith(("/", "http://", "https://")):
                routes.add(urljoin(base_url, value))

        inspect(document)
        tags = ["interface:JSON API"] + [f"api-field:{field}" for field in sorted(fields)[:20]]
        return tags, sorted(route for route in routes if len(route) < 2048)

    def _fingerprint(
        self, headers: dict[str, str], text: str, url: str, content_type: str
    ) -> list[str]:
        fingerprints: set[str] = set()
        server = headers.get("server")
        powered_by = headers.get("x-powered-by")
        if server:
            fingerprints.add(f"server:{server[:80]}")
        if powered_by:
            fingerprints.add(f"x-powered-by:{powered_by[:80]}")
        lowered = text[:20000].lower()
        markers = {
            "framework:WordPress": "wp-content",
            "framework:Laravel": "laravel_session",
            "framework:Django": "csrfmiddlewaretoken",
            "framework:React": "__react",
            "framework:Next.js": "__next",
            "framework:Vue": "__vue",
            "interface:GraphQL": "graphql",
            "interface:Swagger UI": "swagger-ui",
        }
        for name, marker in markers.items():
            if marker in lowered:
                fingerprints.add(name)
        header_text = " ".join(headers.values()).lower()
        if "asp.net" in header_text or "x-aspnet-version" in headers:
            fingerprints.update({"language:C#", "framework:ASP.NET"})
        if "php" in header_text or "phpsessid" in header_text:
            fingerprints.add("language:PHP")
        if "express" in header_text:
            fingerprints.update({"language:JavaScript", "framework:Express"})
        if "jsessionid" in header_text:
            fingerprints.add("language:Java")
        path = urlparse(url).path.lower()
        suffixes = {
            ".aspx": ("language:C#", "framework:ASP.NET"),
            ".php": ("language:PHP",),
            ".jsp": ("language:Java", "framework:JSP"),
            ".js": ("language:JavaScript", "resource:JavaScript"),
            ".css": ("resource:Stylesheet",),
            ".xml": ("resource:XML",),
            ".json": ("resource:JSON",),
        }
        for suffix, signals in suffixes.items():
            if path.endswith(suffix):
                fingerprints.update(signals)
        lowered_content_type = content_type.lower()
        if "json" in lowered_content_type:
            fingerprints.add("interface:JSON API")
        elif "html" in lowered_content_type:
            fingerprints.add("resource:HTML")
        return sorted(fingerprints)
