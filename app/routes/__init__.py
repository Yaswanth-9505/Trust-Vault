"""Shared helpers for route modules."""
import re
from datetime import datetime, timezone

from flask import request

from ..errors import ApiError

CATEGORIES = ("HR", "Legal", "Finance", "Engineering", "Audit", "General")
_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def json_body(allowed: set[str], required: set[str] = frozenset()) -> dict:
    """Parse a JSON object body. Unknown fields are refused rather than ignored,
    so nobody can slip `owner_id` or `role` into a request (mass assignment)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "Expected a JSON object.")
    unknown = set(data) - allowed
    if unknown:
        raise ApiError(400, f"Unexpected field(s): {', '.join(sorted(unknown))}.")
    missing = {k for k in required if data.get(k) in (None, "")}
    if missing:
        raise ApiError(400, f"Missing field(s): {', '.join(sorted(missing))}.")
    return data


def text_field(value, name: str, max_len: int, required=True) -> str:
    if value is None:
        if required:
            raise ApiError(400, f"{name} is required.")
        return ""
    if not isinstance(value, str):
        raise ApiError(400, f"{name} must be text.")
    value = value.strip()
    if required and not value:
        raise ApiError(400, f"{name} is required.")
    if len(value) > max_len:
        raise ApiError(400, f"{name} must be at most {max_len} characters.")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ApiError(400, f"{name} contains control characters.")
    return value


def category_field(value) -> str:
    if value not in CATEGORIES:
        raise ApiError(400, f"category must be one of: {', '.join(CATEGORIES)}.")
    return value


def id_param(value, name="id") -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise ApiError(400, f"Invalid {name}.")
    return value


def parse_date(value: str | None, name: str, end_of_day=False) -> str | None:
    """Accept YYYY-MM-DD or a full ISO timestamp; return our fixed-width UTC string."""
    if not value:
        return None
    try:
        if len(value) == 10:
            dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        else:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise ApiError(400, f"{name} must be a date like 2026-10-19.") from None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def page_params(max_size=100) -> tuple[int, int]:
    try:
        page = max(1, int(request.args.get("page", 1)))
        size = min(max_size, max(1, int(request.args.get("page_size", 25))))
    except ValueError:
        raise ApiError(400, "page and page_size must be numbers.") from None
    return page, size


def like_escape(term: str) -> str:
    """Make user input literal inside LIKE ... ESCAPE '\\'."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
