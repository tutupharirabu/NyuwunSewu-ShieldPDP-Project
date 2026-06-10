"""Shared, dependency-free reporting primitives.

Lives below both ``engine`` and ``pdf_builder`` in the import graph so the two
can share severity constants and the datetime formatter without forming an
import cycle.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_COLORS = {
    "critical": (0.86, 0.15, 0.15),
    "high": (0.92, 0.31, 0.18),
    "medium": (0.86, 0.54, 0.13),
    "low": (0.08, 0.58, 0.53),
    "info": (0.15, 0.39, 0.92),
}


def format_datetime(value: Any) -> str:
    if not value:
        return "N/A"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(value)
