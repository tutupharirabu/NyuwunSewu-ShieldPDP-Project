from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urlparse

from app.core.config import get_settings


@dataclass(slots=True)
class ScanPolicyConfig:
    max_requests_per_second: float = 5.0
    allow_sqli_validation: bool = True
    allow_auth_validation: bool = True
    allow_timing_validation: bool = False
    excluded_paths: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)
    scope_boundaries: list[str] = field(default_factory=list)
    max_depth: int = 2
    max_pages: int = 500


class PolicyEngine:
    def __init__(self, policy: ScanPolicyConfig):
        settings = get_settings()
        self.policy = policy
        self.policy.max_requests_per_second = max(
            0.2, min(policy.max_requests_per_second, settings.max_requests_per_second)
        )
        self.policy.max_depth = max(0, min(policy.max_depth, settings.max_crawl_depth))
        self.policy.max_pages = max(1, min(policy.max_pages, settings.max_crawl_pages))

    def is_path_excluded(self, url: str) -> bool:
        path = urlparse(url).path or "/"
        patterns = self.policy.excluded_paths + self.policy.forbidden_paths
        return any(path == pattern or fnmatch(path, pattern) for pattern in patterns)

    def is_validation_allowed(self, validation_name: str) -> bool:
        if validation_name in {"sqli", "path_traversal", "reflected_html"}:
            return self.policy.allow_sqli_validation
        if validation_name in {"bola", "idor", "auth"}:
            return self.policy.allow_auth_validation
        if validation_name == "timing":
            return self.policy.allow_sqli_validation and self.policy.allow_timing_validation
        return False

    def scoped_domains(self, fallback_domains: list[str]) -> list[str]:
        return self.policy.scope_boundaries or fallback_domains
