"""HTTP caching middleware: ETag revalidation + per-endpoint Cache-Control.

Verifies that JSON GET responses become cheap to re-fetch (304 when unchanged)
and that "stable" endpoints advertise a short max-age, while keeping caching
private to each user.
"""

from fastapi.testclient import TestClient

from app.main import app


def _login(client: TestClient) -> str:
    resp = client.post(
        "/auth/login",
        json={
            "email": "admin@nyuwunsewu.local",
            "password": "ChangeMe123!",
            "organization_slug": "default-organization",
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_live_get_sets_private_no_cache_etag():
    with TestClient(app) as client:
        token = _login(client)
        resp = client.get("/dashboard", headers={"authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "private, no-cache"
        assert resp.headers["etag"].startswith('W/"')
        assert "authorization" in resp.headers["vary"].lower()


def test_conditional_get_returns_304_with_empty_body():
    with TestClient(app) as client:
        token = _login(client)
        auth = {"authorization": f"Bearer {token}"}
        first = client.get("/dashboard", headers=auth)
        etag = first.headers["etag"]

        second = client.get("/dashboard", headers={**auth, "if-none-match": etag})
        assert second.status_code == 304
        assert second.content == b""
        assert second.headers["etag"] == etag
        assert second.headers["cache-control"] == "private, no-cache"


def test_stable_endpoint_advertises_max_age():
    with TestClient(app) as client:
        token = _login(client)
        resp = client.get("/targets", headers={"authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        cache_control = resp.headers["cache-control"]
        assert "private" in cache_control
        assert "max-age=30" in cache_control
        assert resp.headers["etag"].startswith('W/"')


def test_non_get_is_not_etagged():
    with TestClient(app) as client:
        # The login POST must not be turned into a cacheable response.
        resp = client.post(
            "/auth/login",
            json={
                "email": "admin@nyuwunsewu.local",
                "password": "ChangeMe123!",
                "organization_slug": "default-organization",
            },
        )
        assert resp.status_code == 200
        assert "etag" not in resp.headers
