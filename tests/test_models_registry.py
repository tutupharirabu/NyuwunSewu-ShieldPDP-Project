"""Sanity guard for the split-model package (app/models/*).

Each model now lives in its own domain module and wires relationships via
string forward-refs (e.g. ``Mapped["Project"]``). Those resolve lazily through
SQLAlchemy's registry, so a model that is never imported — or a typo'd
forward-ref — fails only at runtime when the relationship is first resolved,
never at import time.

``configure_mappers()`` forces that resolution eagerly, turning such a latent
mistake into a fast, obvious test failure. Importing ``app.models`` first
guarantees every domain module (and thus every class) is registered.
"""

import app.models  # noqa: F401  # registers all model classes
from sqlalchemy.orm import configure_mappers


def test_all_mappers_configure():
    # Raises if any relationship/forward-ref cannot be resolved (e.g. a new
    # model was added to its own file but not wired into app/models/__init__).
    configure_mappers()


def test_engagement_mode_and_roe_document_registered():
    from app.models import EngagementMode, RoeDocument, Scan

    assert EngagementMode.INTERNAL.value == "internal"
    assert EngagementMode.EXTERNAL.value == "external"
    # Scan gained the engagement columns
    assert "engagement_mode" in Scan.__table__.columns
    assert "roe_document_id" in Scan.__table__.columns
    assert "roe_basis" in Scan.__table__.columns
    # RoeDocument table shape
    cols = RoeDocument.__table__.columns
    for name in ("id", "organization_id", "filename", "extracted_text",
                 "char_count", "extraction_warning", "created_at"):
        assert name in cols
