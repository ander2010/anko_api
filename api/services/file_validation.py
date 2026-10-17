"""
Centralized validation for user-uploaded documents.

Every document upload path (multipart uploads, enterprise knowledge sources,
direct-to-S3 uploads registered afterwards) must call ``validate_document`` /
``validate_uploaded_file`` before a Document becomes visible to anyone.

The validator never trusts the client: the file name is only used to pick the
expected type, the declared Content-Type is ignored, and the bytes themselves
decide whether the file is really a PDF / Office Open XML / plain text file.

Configuration (settings or environment):
    UPLOAD_ALLOWED_EXTENSIONS  comma-separated, default "pdf,docx,xlsx,pptx,txt,md,markdown"
    UPLOAD_MAX_FILE_SIZE_MB    default 400
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import unicodedata
import uuid
import zipfile
from dataclasses import dataclass
from typing import BinaryIO, Optional

from django.conf import settings

from api.utils.logging import get_logger

logger = get_logger(__name__)

# ─── Configuration ───────────────────────────────────────────────────────────

DEFAULT_ALLOWED_EXTENSIONS = ("pdf", "docx", "xlsx", "pptx", "txt", "md", "markdown")
DEFAULT_MAX_FILE_SIZE_MB = 400

# Extension -> Document.type stored in the DB (matches the values already in use).
EXTENSION_TO_TYPE = {
    "pdf": "PDF",
    "docx": "DOCX",
    "xlsx": "XLSX",
    "pptx": "PPTX",
    "txt": "TXT",
    "md": "MD",
    "markdown": "MARKDOWN",
}

# Never accepted, not even as an inner extension ("manual.pdf.exe", "invoice.exe.pdf").
DANGEROUS_EXTENSIONS = {
    "exe", "com", "scr", "pif", "cpl", "msi", "msp", "msc", "dll", "sys", "drv", "ocx",
    "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "mjs", "cjs", "wsf", "wsh", "hta",
    "sh", "bash", "zsh", "ksh", "csh", "command", "app", "dmg", "pkg", "deb", "rpm", "run", "bin",
    "jar", "apk", "elf", "so", "dylib", "lnk", "reg", "inf", "gadget", "url", "scf",
    "html", "htm", "xhtml", "shtml", "svg", "svgz", "php", "phtml", "asp", "aspx", "jsp", "py", "pl", "rb",
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
}

OOXML_MAIN_PARTS = {
    "DOCX": ("word/document.xml", "wordprocessingml.document.main+xml"),
    "XLSX": ("xl/workbook.xml", "spreadsheetml.sheet.main+xml"),
    "PPTX": ("ppt/presentation.xml", "presentationml.presentation.main+xml"),
}

# Zip-bomb guards for Office files.
OOXML_MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
OOXML_MAX_ENTRIES = 10000
OOXML_MAX_RATIO = 200

# Binary signatures of executables / containers that are never valid uploads.
EXECUTABLE_SIGNATURES = (
    (b"MZ", "windows_executable"),
    (b"\x7fELF", "elf_executable"),
    (b"\xfe\xed\xfa\xce", "macho_executable"),
    (b"\xfe\xed\xfa\xcf", "macho_executable"),
    (b"\xce\xfa\xed\xfe", "macho_executable"),
    (b"\xcf\xfa\xed\xfe", "macho_executable"),
    (b"\xca\xfe\xba\xbe", "macho_or_java_class"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_compound_file"),  # .msi, legacy .doc/.xls/.ppt
    (b"#!", "script_shebang"),
)

ACTIVE_TEXT_MARKERS = re.compile(
    rb"^\s*(<!doctype\s+html|<html|<script|<svg|<\?php|<\?xml[^>]*>\s*<svg)",
    re.IGNORECASE,
)

def unsupported_type_message(extension: str) -> str:
    shown = f".{extension}" if extension else "(no extension)"
    return f"Unsupported file type: {shown}. Allowed: {', '.join(allowed_extensions())}."


def allowed_extensions() -> tuple[str, ...]:
    raw = getattr(settings, "UPLOAD_ALLOWED_EXTENSIONS", None) or os.getenv("UPLOAD_ALLOWED_EXTENSIONS")
    if not raw:
        return DEFAULT_ALLOWED_EXTENSIONS
    if isinstance(raw, str):
        raw = raw.split(",")
    exts = tuple(e.strip().lower().lstrip(".") for e in raw if e and e.strip())
    # Only extensions this module knows how to verify can be enabled.
    return tuple(e for e in exts if e in EXTENSION_TO_TYPE) or DEFAULT_ALLOWED_EXTENSIONS


def max_file_size_bytes() -> int:
    raw = getattr(settings, "UPLOAD_MAX_FILE_SIZE_MB", None) or os.getenv("UPLOAD_MAX_FILE_SIZE_MB")
    try:
        mb = float(raw) if raw else DEFAULT_MAX_FILE_SIZE_MB
    except (TypeError, ValueError):
        mb = DEFAULT_MAX_FILE_SIZE_MB
    return int(mb * 1024 * 1024)


def size_limit_message() -> str:
    mb = max_file_size_bytes() / (1024 * 1024)
    return f"File exceeds the maximum allowed size of {mb:g} MB."


# ─── Errors ──────────────────────────────────────────────────────────────────

class FileValidationError(Exception):
    """Raised when an upload is rejected. ``status_code`` is the HTTP code to return."""

    def __init__(self, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def as_response_data(self) -> dict:
        return {"file": self.message, "detail": self.message, "error_code": self.code}


def _reject(code: str, message: str, status_code: int):
    raise FileValidationError(code, message, status_code)


# ─── Result ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ValidatedDocument:
    original_name: str      # sanitized display name
    extension: str          # "pdf", "docx", ...
    document_type: str      # value for Document.type
    size: int
    sha256: str


# ─── Filename checks ─────────────────────────────────────────────────────────

def sanitize_display_name(filename: str) -> str:
    """Return a safe display name (no paths, no control chars), max 200 chars."""
    name = unicodedata.normalize("NFC", str(filename or ""))
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")
    name = name.strip().strip(".")
    if len(name) > 200:
        stem, dot, ext = name.rpartition(".")
        name = (stem[: 200 - len(ext) - 1] + "." + ext) if dot else name[:200]
    return name


def check_filename(filename: str) -> tuple[str, str]:
    """Validate the client-supplied name. Returns (display_name, extension)."""
    raw = str(filename or "")
    if not raw.strip():
        _reject("missing_filename", "A file name is required.", 400)
    if "\x00" in raw:
        _reject("invalid_filename", "Invalid file name.", 400)

    # Directory parts are dropped; the name is only used for display, never for storage paths.
    name = sanitize_display_name(raw)
    if not name:
        _reject("invalid_filename", "Invalid file name.", 400)
    parts = [p.lower() for p in name.split(".")]
    if len(parts) < 2 or not parts[-1]:
        _reject("unsupported_extension", unsupported_type_message(""), 415)

    ext = parts[-1]
    inner = set(parts[1:-1])
    if ext in DANGEROUS_EXTENSIONS or inner & DANGEROUS_EXTENSIONS:
        bad = ext if ext in DANGEROUS_EXTENSIONS else sorted(inner & DANGEROUS_EXTENSIONS)[0]
        _reject("dangerous_extension", unsupported_type_message(bad), 415)
    if ext not in allowed_extensions():
        _reject("unsupported_extension", unsupported_type_message(ext), 415)
    return name, ext


# ─── Content checks (streaming: files can be up to the size limit, never fully loaded) ─

CHUNK_SIZE = 1024 * 1024
HEAD_SIZE = 4096
TAIL_SIZE = 4096


def _reject_executable(head: bytes):
    for signature, kind in EXECUTABLE_SIGNATURES:
        if head.startswith(signature):
            _reject(f"content_{kind}", "The file content is not allowed.", 415)


def _stream_size(fileobj: BinaryIO) -> int:
    fileobj.seek(0, io.SEEK_END)
    size = fileobj.tell()
    fileobj.seek(0)
    return size


def _read_at(fileobj: BinaryIO, offset: int, length: int) -> bytes:
    fileobj.seek(max(0, offset))
    return fileobj.read(length)


def _check_pdf_frame(head: bytes, tail: bytes):
    header_zone = head[:1024]
    idx = header_zone.find(b"%PDF-")
    if idx == -1:
        _reject("content_mismatch", "The file is not a valid PDF.", 422)
    # Anything before the header must be harmless whitespace / BOM (blocks polyglots).
    if header_zone[:idx].strip(b"\x00\t\n\r\x0c \xef\xbb\xbf"):
        _reject("content_mismatch", "The file is not a valid PDF.", 422)
    if not re.match(rb"[12]\.\d", head[idx + 5: idx + 8]):
        _reject("content_mismatch", "The file is not a valid PDF.", 422)
    if b"%%EOF" not in tail[-2048:] or b"startxref" not in tail:
        _reject("corrupt_file", "The PDF file is damaged or incomplete.", 422)


def _check_ooxml(fileobj: BinaryIO, document_type: str):
    fileobj.seek(0)
    if not zipfile.is_zipfile(fileobj):
        _reject("content_mismatch", "The file is not a valid Office document.", 422)
    fileobj.seek(0)
    try:
        with zipfile.ZipFile(fileobj) as zf:
            infos = zf.infolist()
            if len(infos) > OOXML_MAX_ENTRIES:
                _reject("corrupt_file", "The Office document is malformed.", 422)
            total = 0
            names = set()
            for info in infos:
                n = info.filename
                if n.startswith("/") or "\\" in n or ".." in n.split("/"):
                    _reject("corrupt_file", "The Office document is malformed.", 422)
                total += info.file_size
                if info.compress_size and info.file_size / max(info.compress_size, 1) > OOXML_MAX_RATIO:
                    _reject("corrupt_file", "The Office document is malformed.", 422)
                names.add(n)
            if total > OOXML_MAX_UNCOMPRESSED_BYTES:
                _reject("corrupt_file", "The Office document is malformed.", 422)

            main_part, main_content_type = OOXML_MAIN_PARTS[document_type]
            if "[Content_Types].xml" not in names or main_part not in names:
                _reject("content_mismatch", "The file is not a valid Office document.", 422)
            # Macro-enabled content is never accepted in docx/xlsx/pptx.
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                _reject("macro_content", "Documents with macros are not allowed.", 415)

            content_types = zf.read("[Content_Types].xml")
            if main_content_type.encode() not in content_types:
                _reject("content_mismatch", "The file is not a valid Office document.", 422)
            if b"macroEnabled" in content_types:
                _reject("macro_content", "Documents with macros are not allowed.", 415)
            # Reading the main part verifies its CRC and that it decompresses cleanly.
            with zf.open(main_part) as part:
                while part.read(CHUNK_SIZE):
                    pass
    except FileValidationError:
        raise
    except (zipfile.BadZipFile, KeyError, ValueError, OSError, RuntimeError, NotImplementedError, EOFError):
        _reject("corrupt_file", "The Office document is damaged or malformed.", 422)


class _TextScanner:
    """Incremental checks for plain text: no NUL bytes and decodable as UTF-8 (or cp1252)."""

    def __init__(self):
        import codecs
        self._utf8 = codecs.getincrementaldecoder("utf-8-sig")()
        self._cp1252 = codecs.getincrementaldecoder("cp1252")()
        self.utf8_ok = True
        self.cp1252_ok = True
        self.has_nul = False

    def feed(self, chunk: bytes, final: bool = False):
        if b"\x00" in chunk:
            self.has_nul = True
        if self.utf8_ok:
            try:
                self._utf8.decode(chunk, final)
            except UnicodeDecodeError:
                self.utf8_ok = False
        if self.cp1252_ok:
            try:
                self._cp1252.decode(chunk, final)
            except UnicodeDecodeError:
                self.cp1252_ok = False


def _scan_stream(fileobj: BinaryIO, document_type: str) -> str:
    """Single pass over the file: sha256 + per-type streaming checks. Returns the hex digest."""
    hasher = hashlib.sha256()
    text = _TextScanner() if document_type in ("TXT", "MD", "MARKDOWN") else None
    pdf_has_object = document_type != "PDF"
    carry = b""
    fileobj.seek(0)
    while True:
        chunk = fileobj.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)
        if text is not None:
            text.feed(chunk)
        if not pdf_has_object:
            window = carry + chunk
            if b" obj" in window or b"\nobj" in window or b"\robj" in window:
                pdf_has_object = True
            carry = chunk[-8:]
    if text is not None:
        text.feed(b"", final=True)
        if text.has_nul or not (text.utf8_ok or text.cp1252_ok):
            _reject("content_mismatch", "The file is not a valid text file.", 422)
    if not pdf_has_object:
        _reject("corrupt_file", "The PDF file is damaged or incomplete.", 422)
    fileobj.seek(0)
    return hasher.hexdigest()


def validate_stream(filename: str, fileobj: BinaryIO) -> ValidatedDocument:
    """Validate a seekable binary file object. Raises FileValidationError on rejection."""
    name, ext = check_filename(filename)
    size = _stream_size(fileobj)
    if size > max_file_size_bytes():
        _reject("file_too_large", size_limit_message(), 413)
    if size == 0:
        _reject("empty_file", "The file is empty.", 422)

    document_type = EXTENSION_TO_TYPE[ext]
    head = _read_at(fileobj, 0, HEAD_SIZE)
    _reject_executable(head)
    if document_type == "PDF":
        _check_pdf_frame(head, _read_at(fileobj, size - TAIL_SIZE, TAIL_SIZE))
    elif document_type in OOXML_MAIN_PARTS:
        _check_ooxml(fileobj, document_type)
    elif ACTIVE_TEXT_MARKERS.match(head[:2048]):
        _reject("active_content", "The file content is not allowed.", 415)

    sha256 = _scan_stream(fileobj, document_type)
    return ValidatedDocument(
        original_name=name,
        extension=ext,
        document_type=document_type,
        size=size,
        sha256=sha256,
    )


# ─── Public API ──────────────────────────────────────────────────────────────

def validate_document(filename: str, data: bytes) -> ValidatedDocument:
    """Validate a document given its bytes. Raises FileValidationError on rejection."""
    return validate_stream(filename, io.BytesIO(data))


def validate_uploaded_file(uploaded_file) -> ValidatedDocument:
    """Validate a Django UploadedFile (multipart upload) without loading it fully in memory."""
    name, _ = check_filename(getattr(uploaded_file, "name", ""))
    declared_size = getattr(uploaded_file, "size", None)
    if declared_size is not None and declared_size > max_file_size_bytes():
        _reject("file_too_large", size_limit_message(), 413)
    try:
        return validate_stream(name, uploaded_file)
    finally:
        try:
            uploaded_file.seek(0)
        except Exception:
            pass


def random_storage_name(extension: str) -> str:
    """Internal storage name: random, never derived from the client's file name."""
    ext = re.sub(r"[^a-z0-9]", "", str(extension or "").lower())[:10]
    return f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex


def log_rejected_upload(request, error: FileValidationError, *, filename: str = "", size: Optional[int] = None, source: str = ""):
    """Record a rejected upload (no file content is stored)."""
    from api.services.audit import log_audit_event

    user = getattr(request, "user", None)
    user_id = getattr(user, "id", None) if getattr(user, "is_authenticated", False) else None
    safe_name = sanitize_display_name(filename)[:120]
    logger.warning(
        "upload_rejected source=%s user_id=%s code=%s status=%s name=%r size=%s",
        source, user_id, error.code, error.status_code, safe_name, size,
    )
    log_audit_event(
        operation="upload_rejected",
        success=False,
        user_id=user_id,
        resource_type="document",
        status_code=error.status_code,
        error_message=error.code,
        method=getattr(request, "method", "") or "",
        path=getattr(request, "path", "") or "",
        ip_address=(request.META.get("REMOTE_ADDR") if getattr(request, "META", None) else None),
        metadata={"source": source, "filename": safe_name, "size": size, "reason": error.code},
    )


# ─── DRF helpers ─────────────────────────────────────────────────────────────

def rejection_response(request, error: FileValidationError, *, filename: str = "", size: Optional[int] = None, source: str = ""):
    """Log the rejection and build the DRF Response for it."""
    from rest_framework.response import Response

    log_rejected_upload(request, error, filename=filename, size=size, source=source)
    return Response(error.as_response_data(), status=error.status_code)


def oversize_error() -> FileValidationError:
    return FileValidationError("file_too_large", size_limit_message(), 413)


def as_api_exception(error: FileValidationError):
    from rest_framework.exceptions import APIException

    exc = APIException(detail=error.message, code=error.code)
    exc.status_code = error.status_code
    return exc
