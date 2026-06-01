from app.recon.engine import AsyncReconEngine
from bs4 import BeautifulSoup
import pytest


class _ChunkedStream:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def read(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]


class _Response:
    def __init__(self, chunks: list[bytes]):
        self.content = _ChunkedStream(chunks)


def test_json_api_profile_collects_field_names_and_routes_without_values():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)

    tags, routes = engine._profile_json_response(
        '{"users":[{"id":1,"profile_url":"/api/users/1"}],"token":"secret"}',
        "https://example.com/api",
    )

    assert "interface:JSON API" in tags
    assert "api-field:users" in tags
    assert "https://example.com/api/users/1" in routes
    assert "secret" not in " ".join(tags)


def test_fingerprint_recognizes_aspnet_resource_and_language():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)

    tags = engine._fingerprint(
        {"x-powered-by": "ASP.NET", "server": "Microsoft-IIS/10.0"},
        "<html></html>",
        "http://example.com/login.aspx",
        "text/html",
    )

    assert "framework:ASP.NET" in tags
    assert "language:C#" in tags
    assert "resource:HTML" in tags


@pytest.mark.asyncio
async def test_limited_reader_collects_multiple_network_chunks():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)
    engine.settings = type("Settings", (), {"max_response_bytes": 20})()

    content = await engine._read_limited(_Response([b"<html>", b"<a href='/login'>", b"ignored"]))

    assert content == b"<html><a href='/logi"


def test_extract_links_includes_login_register_form_and_data_routes():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)
    soup = BeautifulSoup(
        """
        <a href="/login">Sign in</a>
        <a href="/register">Register</a>
        <form action="/session"></form>
        <button data-route="/dashboard">Open</button>
        """,
        "lxml",
    )

    links = engine._extract_links(soup, "https://example.com/")

    assert "https://example.com/login" in links
    assert "https://example.com/register" in links
    assert "https://example.com/session" in links
    assert "https://example.com/dashboard" in links


def test_form_discovery_does_not_submit_synthetic_get_values():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)

    url = engine._form_discovery_url(
        "https://example.com/login",
        {"method": "GET", "fields": [{"name": "username"}, {"name": "password"}]},
    )

    assert url == "https://example.com/login"


def test_javascript_json_login_action_is_detected_without_exposing_credentials():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)
    endpoint = type(
        "Endpoint",
        (),
        {
            "url": "https://example.com/login",
            "response_body_sample": """
                fetch("/login", {
                  method: "POST",
                  headers: {"Content-Type": "application/json"},
                  body: JSON.stringify(jsonData)
                })
            """,
        },
    )()

    assert engine._javascript_json_login_action(endpoint) == "https://example.com/login"
    assert engine._extract_json_token('{"status":"success","token":"secret-token"}') == "secret-token"


def test_authenticated_observation_replaces_status_and_keeps_both_access_tags():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)
    engine.results = {}
    guest = type(
        "Endpoint",
        (),
        {
            "url": "https://example.com/admin",
            "tech_stack": ["access:guest"],
            "links": [],
            "api_routes": [],
            "js_routes": [],
            "query_parameters": [],
            "forms": [],
        },
    )()
    authenticated = type(
        "Endpoint",
        (),
        {
            "url": "https://example.com/admin",
            "tech_stack": ["access:authenticated"],
            "links": [],
            "api_routes": [],
            "js_routes": [],
            "query_parameters": [],
            "forms": [],
        },
    )()

    engine._store_endpoint(guest, "guest")
    engine._store_endpoint(authenticated, "authenticated")

    assert engine.results[authenticated.url] is authenticated
    assert engine.results[authenticated.url].tech_stack == ["access:authenticated", "access:guest"]


def test_recon_stop_signal_is_recorded_for_workers():
    engine = AsyncReconEngine.__new__(AsyncReconEngine)
    engine.stop_requested = False

    engine.request_stop()

    assert engine.stop_requested is True
