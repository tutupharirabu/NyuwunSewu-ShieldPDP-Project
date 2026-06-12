"""Extract plain text from an uploaded Rules-of-Engagement document.

Supports .md / .txt (decoded directly) and .pdf (via pypdf). Image-only or
unparseable PDFs yield an ``extraction_warning`` so the operator is not misled
into running the agent on an effectively empty RoE.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

ROE_MAX_CHARS = 40_000
ROE_MIN_CHARS = 50
ROE_IMAGE_PDF_BYTES = 10_240


class UnsupportedRoeFile(ValueError):
    """Raised when the uploaded RoE file extension is not supported."""


@dataclass
class ExtractedRoe:
    text: str
    char_count: int
    truncated: bool
    extraction_warning: bool


def _extract_pdf(raw: bytes) -> str:
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(raw))
        parts = [(page.extract_text() or "") for page in reader.pages]
        return "\n".join(parts)
    except Exception:
        # Corrupt / encrypted / image-only: treat as no extractable text.
        return ""


def extract_roe_text(filename: str, raw: bytes) -> ExtractedRoe:
    lower = filename.lower()
    if lower.endswith((".md", ".txt")):
        text = raw.decode("utf-8", errors="replace")
    elif lower.endswith(".pdf"):
        text = _extract_pdf(raw)
    else:
        raise UnsupportedRoeFile(
            "Unsupported RoE file type; use .pdf, .md, or .txt"
        )

    truncated = len(text) > ROE_MAX_CHARS
    if truncated:
        text = text[:ROE_MAX_CHARS]

    is_pdf = filename.lower().endswith(".pdf")
    near_empty = len(text.strip()) < ROE_MIN_CHARS
    substantive_input = is_pdf or len(raw) > ROE_IMAGE_PDF_BYTES
    warning = truncated or (near_empty and substantive_input)
    return ExtractedRoe(
        text=text,
        char_count=len(text),
        truncated=truncated,
        extraction_warning=warning,
    )
