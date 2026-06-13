import hashlib

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Paths (as the app sees them — a reverse proxy strips the "/api" prefix the
# browser uses, so match both forms) whose data tolerates brief staleness. The
# browser may serve these from disk for STABLE_MAX_AGE seconds without contacting
# the server at all. Everything else revalidates every time (a cheap 304 when the
# body is unchanged).
STABLE_PATHS: tuple[str, ...] = (
    "/reports",
    "/audit-logs",
    "/compliance",
    "/targets",
    "/projects",
    "/remediations",
)
STABLE_MAX_AGE = 30

_NOT_MODIFIED_PASSTHROUGH = ("etag", "cache-control", "vary")


def _strip_api_prefix(path: str) -> str:
    return path[4:] if path.startswith("/api/") else path


def _is_stable(path: str) -> bool:
    normalized = _strip_api_prefix(path)
    return any(normalized == sp or normalized.startswith(sp + "/") for sp in STABLE_PATHS)


def _normalize_tag(tag: str) -> str:
    tag = tag.strip()
    return tag[2:] if tag.startswith("W/") else tag


def _etag_matches(if_none_match: str, etag: str) -> bool:
    if if_none_match.strip() == "*":
        return True
    target = _normalize_tag(etag)
    return any(_normalize_tag(candidate) == target for candidate in if_none_match.split(","))


def _append_vary(headers: MutableHeaders, value: str) -> None:
    existing = headers.get("vary")
    if not existing:
        headers["vary"] = value
        return
    parts = {p.strip().lower() for p in existing.split(",")}
    if value.lower() not in parts:
        headers["vary"] = f"{existing}, {value}"


class HTTPCacheMiddleware(BaseHTTPMiddleware):
    """Add ETag + Cache-Control to JSON GET responses and answer conditional
    requests with 304 Not Modified.

    Data is per-user, so caching is always ``private`` and varies on
    Authorization. This sits inner to GZip so the ETag is computed over the
    uncompressed body — a stable weak validator regardless of Accept-Encoding.
    An endpoint that sets its own Cache-Control keeps it (override wins)."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.method != "GET" or response.status_code != 200:
            return response
        if not response.headers.get("content-type", "").startswith("application/json"):
            return response

        body = b"".join([chunk async for chunk in response.body_iterator])
        etag = 'W/"%s"' % hashlib.sha1(body).hexdigest()

        headers = MutableHeaders(raw=list(response.raw_headers))
        if "cache-control" not in headers:
            headers["cache-control"] = (
                f"private, max-age={STABLE_MAX_AGE}"
                if _is_stable(request.url.path)
                else "private, no-cache"
            )
        headers["etag"] = etag
        _append_vary(headers, "Authorization")

        if_none_match = request.headers.get("if-none-match")
        if if_none_match and _etag_matches(if_none_match, etag):
            not_modified = {k: headers[k] for k in _NOT_MODIFIED_PASSTHROUGH if k in headers}
            return Response(status_code=304, headers=not_modified, background=response.background)

        if "content-length" in headers:
            del headers["content-length"]  # Response recomputes it for the unchanged body
        return Response(
            content=body,
            status_code=200,
            headers=dict(headers),
            background=response.background,
        )
