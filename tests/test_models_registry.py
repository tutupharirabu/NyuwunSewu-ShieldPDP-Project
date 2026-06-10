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
