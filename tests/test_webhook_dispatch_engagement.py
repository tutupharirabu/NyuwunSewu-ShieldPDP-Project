import asyncio

from app.models import RoeDocument, Scan
from app.services.scan_reporting import _ReportingMixin


class _FakeSession:
    """Minimal async session stub: returns a preset RoeDocument, None otherwise."""

    def __init__(self, roe_doc=None):
        self._roe = roe_doc

    async def get(self, model, pk):
        if model is RoeDocument:
            return self._roe
        return None  # Target / others not needed for these assertions


def _reporter(session):
    inst = _ReportingMixin.__new__(_ReportingMixin)
    inst.session = session
    return inst


def test_internal_payload_has_engagement_fields():
    reporter = _reporter(_FakeSession())
    scan = Scan(
        id="s-int",
        engagement_mode="internal",
        roe_document_id=None,
        roe_basis=None,
        target_id=None,
        project_id=None,
        status="completed",
    )
    payload = asyncio.run(reporter._build_webhook_payload(scan, "scan.completed"))
    assert payload["engagement_mode"] == "internal"
    assert payload["roe_basis"] is None
    assert payload["roe_text"] is None
    # existing keys still present
    assert payload["event"] == "scan.completed"
    assert payload["scan_id"] == "s-int"


def test_external_payload_includes_roe_text():
    doc = RoeDocument(
        id="r1", organization_id="o1", filename="roe.md",
        extracted_text="IN SCOPE: api.example.com ONLY", char_count=30,
        extraction_warning=False,
    )
    reporter = _reporter(_FakeSession(roe_doc=doc))
    scan = Scan(
        id="s-ext",
        engagement_mode="external",
        roe_document_id="r1",
        roe_basis="document",
        target_id=None,
        project_id=None,
        status="completed",
    )
    payload = asyncio.run(reporter._build_webhook_payload(scan, "scan.completed"))
    assert payload["engagement_mode"] == "external"
    assert payload["roe_basis"] == "document"
    assert payload["roe_text"] == "IN SCOPE: api.example.com ONLY"
