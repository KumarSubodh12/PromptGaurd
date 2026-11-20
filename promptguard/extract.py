"""Stage 1: turn an uploaded file into plain text, safely.

Files are only *parsed*: nothing is executed, rendered or opened by another
program. Every format is validated (type, magic bytes, size, empty content)
before parsing, and parsers are given hard limits.
"""
from __future__ import annotations

import email
import io
import re
import zipfile
from email import policy
from pathlib import PurePath

from .config import (ALLOWED_EXTENSIONS, MAX_DOCX_UNCOMPRESSED, MAX_PDF_PAGES, MAX_TEXT_CHARS, MAX_UPLOAD_BYTES)


class ExtractError(ValueError):
    """A problem the user can fix (wrong type, too big, empty, protected ...)."""


def safe_name(filename: str | None) -> str:
    name = PurePath((filename or "").replace("\\", "/")).name
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return name[:120] or "Pasted text"


def _decode(data: bytes) -> str:
    if data.count(b"\x00") > max(8, len(data) // 100) and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ExtractError("This looks like a binary file, not text. Upload a TXT, PDF or DOCX file instead.")
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeError:
            continue
    return data.decode("latin-1", errors="replace")


def _pdf(data: bytes) -> tuple[str, list[str]]:
    notes: list[str] = []
    if not data.startswith(b"%PDF-"):
        raise ExtractError("This file does not look like a PDF (missing the %PDF header).")
    try:
        import fitz  # PyMuPDF, preferred when installed
        doc = fitz.open(stream=data, filetype="pdf")
        if doc.needs_pass:
            raise ExtractError("This PDF is password protected. Remove the password and upload it again.")
        pages = min(doc.page_count, MAX_PDF_PAGES)
        if doc.page_count > pages:
            notes.append(f"Only the first {pages} of {doc.page_count} pages were read.")
        return "\n\n".join(doc[i].get_text() for i in range(pages)), notes
    except ImportError:
        pass
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise ExtractError("This PDF is password protected. Remove the password and upload it again.")
        n = len(reader.pages)
        pages = min(n, MAX_PDF_PAGES)
        if n > pages:
            notes.append(f"Only the first {pages} of {n} pages were read.")
        notes.append("Read with pypdf (PyMuPDF is not installed).")
        return "\n\n".join((reader.pages[i].extract_text() or "") for i in range(pages)), notes
    except PdfReadError as e:
        raise ExtractError(f"The PDF could not be read: {e}") from e


def _docx(data: bytes) -> tuple[str, list[tuple[int, int]], list[str]]:
    if not data.startswith(b"PK\x03\x04"):
        raise ExtractError("This file does not look like a DOCX (it is not a zip archive).")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if len(infos) > 3000 or sum(i.file_size for i in infos) > MAX_DOCX_UNCOMPRESSED:
                raise ExtractError("This DOCX expands to an unsafe size and was not opened.")
            if "word/document.xml" not in z.namelist():
                raise ExtractError("This zip file is not a Word document.")
    except zipfile.BadZipFile as e:
        raise ExtractError("The DOCX file is damaged.") from e

    from docx import Document
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    doc = Document(io.BytesIO(data))
    buf: list[str] = []
    pos = 0
    hidden: list[tuple[int, int]] = []

    def add_par(par) -> None:
        nonlocal pos
        for run in par.runs:
            t = run.text
            if not t:
                continue
            if run.font.hidden:
                hidden.append((pos, pos + len(t)))
            buf.append(t)
            pos += len(t)
        buf.append("\n")
        pos += 1

    for child in doc.element.body.iterchildren():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "p":
            add_par(Paragraph(child, doc))
        elif tag == "tbl":
            for row in Table(child, doc).rows:
                for cell in row.cells:
                    for par in cell.paragraphs:
                        add_par(par)
    for sec in doc.sections:
        for part in (sec.header, sec.footer):
            for par in part.paragraphs:
                add_par(par)
    notes = []
    if hidden:
        notes.append(f"{len(hidden)} piece(s) of text are formatted as hidden in this document.")
    return "".join(buf), hidden, notes


def _eml(data: bytes) -> tuple[str, list[str]]:
    msg = email.message_from_bytes(data, policy=policy.default)
    head = "\n".join(f"{h}: {msg[h]}" for h in ("From", "To", "Subject", "Date") if msg[h])
    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body is not None else ""
    n_att = sum(1 for _ in msg.iter_attachments())
    notes = [f"{n_att} attachment(s) were not analysed."] if n_att else []
    return f"{head}\n\n{text}", notes


def _html(data: bytes) -> tuple[str, list[str]]:
    src = _decode(data)
    src = re.sub(r"<(script|style)\b[^>]*>.*?</\1\s*>", "", src, flags=re.S | re.I)
    return src, ["HTML is analysed as source so comments and hidden elements stay visible to the detectors."]


def extract(filename: str, data: bytes) -> dict:
    """Return ``{"text", "kind", "notes", "hidden_spans", "name"}`` or raise ExtractError."""
    name = safe_name(filename)
    ext = PurePath(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ExtractError(f"{ext or 'This file type'} is not supported. Use one of: " + ", ".join(sorted(ALLOWED_EXTENSIONS)) + ".")
    if not data:
        raise ExtractError("The file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ExtractError(f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")

    hidden: list[tuple[int, int]] = []
    notes: list[str] = []
    if ext == ".pdf":
        text, notes = _pdf(data)
    elif ext == ".docx":
        text, hidden, notes = _docx(data)
    elif ext == ".eml":
        text, notes = _eml(data)
    elif ext in (".html", ".htm"):
        text, notes = _html(data)
    else:
        text = _decode(data)

    if not text.strip():
        raise ExtractError("No text could be extracted. A scanned PDF needs OCR first.")
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        hidden = [(a, min(b, MAX_TEXT_CHARS)) for a, b in hidden if a < MAX_TEXT_CHARS]
        notes.append(f"Text was cut at {MAX_TEXT_CHARS:,} characters.")
    return {"text": text, "kind": ext.lstrip("."), "notes": notes, "hidden_spans": hidden, "name": name}


def validate_pasted(text: str) -> str:
    if not text or not text.strip():
        raise ExtractError("Paste some text or upload a file first.")
    if len(text) > MAX_TEXT_CHARS:
        raise ExtractError(f"The text is longer than {MAX_TEXT_CHARS:,} characters. Split it into parts.")
    return text
