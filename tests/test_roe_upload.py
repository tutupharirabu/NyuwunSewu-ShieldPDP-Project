import io

from fastapi.testclient import TestClient

from app.main import app

LOGIN_BODY = {
    "email": "admin@nyuwunsewu.local",
    "password": "ChangeMe123!",
    "organization_slug": "default-organization",
}


def _auth_headers(client: TestClient) -> dict:
    resp = client.post("/auth/login", json=LOGIN_BODY)
    assert resp.status_code == 200, resp.text
    return {"authorization": f"Bearer {resp.json()['access_token']}"}


def test_roe_upload_external_returns_document_id():
    with TestClient(app) as client:
        headers = _auth_headers(client)
        resp = client.post(
            "/scan/roe",
            headers=headers,
            files={"file": ("scope.md", io.BytesIO(b"# Scope\nonly api.example.com\n"), "text/markdown")},
            data={"engagement_mode": "external"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["roe_document_id"]
        assert body["filename"] == "scope.md"
        assert body["char_count"] > 0
        assert body["extraction_warning"] is False


def test_roe_upload_rejected_for_internal_mode():
    with TestClient(app) as client:
        headers = _auth_headers(client)
        resp = client.post(
            "/scan/roe",
            headers=headers,
            files={"file": ("scope.md", io.BytesIO(b"x"), "text/markdown")},
            data={"engagement_mode": "internal"},
        )
        assert resp.status_code == 400
