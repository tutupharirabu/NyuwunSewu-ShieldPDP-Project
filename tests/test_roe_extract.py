import pytest

from app.utils.roe_extract import (
    ROE_MAX_CHARS,
    UnsupportedRoeFile,
    extract_roe_text,
)


def test_markdown_extracted_verbatim():
    result = extract_roe_text("roe.md", b"# Scope\nonly example.com\n")
    assert "only example.com" in result.text
    assert result.char_count == len(result.text)
    assert result.extraction_warning is False
    assert result.truncated is False


def test_text_over_limit_is_truncated_and_flagged():
    raw = ("a" * (ROE_MAX_CHARS + 500)).encode()
    result = extract_roe_text("roe.txt", raw)
    assert len(result.text) == ROE_MAX_CHARS
    assert result.truncated is True


def test_empty_large_pdf_triggers_extraction_warning():
    # An image-only / unparseable PDF: > 10 KB of bytes, no extractable text.
    fake_pdf = b"%PDF-1.4\n" + b"0" * 11000
    result = extract_roe_text("scope.pdf", fake_pdf)
    assert result.text.strip() == ""
    assert result.extraction_warning is True


def test_unsupported_extension_rejected():
    with pytest.raises(UnsupportedRoeFile):
        extract_roe_text("scope.docx", b"...")
