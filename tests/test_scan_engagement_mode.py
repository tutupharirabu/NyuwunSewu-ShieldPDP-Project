from fastapi.testclient import TestClient

from app.main import app


def _auth_headers(client):
    resp = client.post(
        "/auth/login",
        json={
            "email": "admin@nyuwunsewu.local",
            "password": "ChangeMe123!",
            "organization_slug": "default-organization",
        },
    )
    assert resp.status_code == 200, resp.text
    return {"authorization": f"Bearer {resp.json()['access_token']}"}


def _base_payload(**over):
    payload = {
        "target_url": "http://127.0.0.1:9",
        "project_name": "Engagement Mode Test",
        "allowed_domains": [],
        "policy": {"name": "p", "max_requests_per_second": 1},
    }
    payload.update(over)
    return payload


def test_default_mode_is_internal():
    with TestClient(app) as client:
        headers = _auth_headers(client)
        resp = client.post("/scan/start", headers=headers, json=_base_payload())
        assert resp.status_code == 200, resp.text


def test_internal_with_roe_document_rejected():
    with TestClient(app) as client:
        headers = _auth_headers(client)
        resp = client.post(
            "/scan/start",
            headers=headers,
            json=_base_payload(engagement_mode="internal", roe_document_id="abc"),
        )
        assert resp.status_code == 400


def test_external_with_unknown_roe_document_rejected():
    with TestClient(app) as client:
        headers = _auth_headers(client)
        resp = client.post(
            "/scan/start",
            headers=headers,
            json=_base_payload(engagement_mode="external", roe_document_id="does-not-exist"),
        )
        assert resp.status_code == 400


def test_external_no_document_sets_default_basis():
    with TestClient(app) as client:
        headers = _auth_headers(client)
        resp = client.post(
            "/scan/start",
            headers=headers,
            json=_base_payload(engagement_mode="external"),
        )
        assert resp.status_code == 200, resp.text
        scan_id = resp.json()["scan_id"]
        detail = client.get(f"/scans/{scan_id}", headers=headers)
        assert detail.status_code == 200, detail.text
        assert detail.json()["engagement_mode"] == "external"
        assert detail.json()["roe_basis"] == "default_roe_v1"
