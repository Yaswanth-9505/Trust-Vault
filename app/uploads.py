"""Validation of uploaded files.

Allow-list, not deny-list: a file is accepted only if its extension is on the
list AND its bytes look like that type. The browser-supplied Content-Type is
ignored entirely - it is whatever the client says it is.

Whatever passes is still always served back as an attachment with
`application/octet-stream`, so even a file that slips past these checks is
never rendered by the browser on our origin.
"""
import io
import re
import unicodedata
import zipfile

from .errors import ApiError

ALLOWED = {
    # ext:   (served mime type recorded for display,                         checker)
    "pdf":  ("application/pdf", "pdf"),
    "png":  ("image/png", "png"),
    "jpg":  ("image/jpeg", "jpeg"),
    "jpeg": ("image/jpeg", "jpeg"),
    "txt":  ("text/plain", "text"),
    "csv":  ("text/csv", "text"),
    "md":   ("text/markdown", "text"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "ooxml:word/document.xml"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "ooxml:xl/workbook.xml"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "ooxml:ppt/presentation.xml"),
}

# Active content inside PDFs that runs in the reader when the file is opened.
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFile|RichMedia|XFA)\b")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_filename(raw: str | None) -> str:
    if not raw:
        raise ApiError(400, "The file has no name.")
    name = unicodedata.normalize("NFC", raw)
    name = name.replace("\\", "/").split("/")[-1]       # drop any path, Windows or POSIX
    name = _CONTROL.sub("", name)
    name = re.sub(r"[‪-‮⁦-⁩]", "", name)  # bidi overrides ("gpj.exe")
    name = name.strip().lstrip(".")
    if not name or "." not in name:
        raise ApiError(400, "The file name must have an extension.")
    stem, ext = name.rsplit(".", 1)
    return f"{stem[:150].strip() or 'file'}.{ext.lower()}"


def validate_upload(filename: str | None, data: bytes, max_bytes: int) -> dict:
    name = sanitize_filename(filename)
    ext = name.rsplit(".", 1)[1]
    if ext not in ALLOWED:
        raise ApiError(415, f"Files of type .{ext} are not accepted. Allowed: "
                            + ", ".join(sorted(ALLOWED)) + ".")
    if len(data) == 0:
        raise ApiError(400, "The file is empty.")
    if len(data) > max_bytes:
        raise ApiError(413, f"The file is larger than {max_bytes // (1024 * 1024)} MB.")

    mime, checker = ALLOWED[ext]
    if checker == "pdf":
        if not data.startswith(b"%PDF-"):
            raise ApiError(415, "This is not a valid PDF file.")
        if _PDF_ACTIVE.search(data):
            raise ApiError(415, "PDFs containing scripts, launch actions or embedded files are not accepted.")
    elif checker == "png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ApiError(415, "This is not a valid PNG image.")
    elif checker == "jpeg":
        if not data.startswith(b"\xff\xd8\xff"):
            raise ApiError(415, "This is not a valid JPEG image.")
    elif checker == "text":
        if b"\x00" in data:
            raise ApiError(415, "Text files must not contain binary data.")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ApiError(415, "Text files must be UTF-8.") from None
    elif checker.startswith("ooxml:"):
        _check_ooxml(data, checker.split(":", 1)[1])
    return {"filename": name, "ext": ext, "mime": mime}


def _check_ooxml(data: bytes, required_part: str):
    if not data.startswith(b"PK\x03\x04"):
        raise ApiError(415, "This is not a valid Office document.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()  # reads the central directory only; nothing is decompressed
    except zipfile.BadZipFile:
        raise ApiError(415, "This is not a valid Office document.") from None
    lowered = {n.lower() for n in names}
    if "[content_types].xml" not in lowered or required_part.lower() not in lowered:
        raise ApiError(415, "The file's contents do not match its extension.")
    if any(n.endswith("vbaproject.bin") for n in lowered):
        raise ApiError(415, "Documents containing macros are not accepted.")
    if len(names) > 5000:
        raise ApiError(415, "The document has too many parts.")
