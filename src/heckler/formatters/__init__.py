"""Output formatters for heckler findings."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..scanner import Finding

from .json_fmt import format_json
from .sarif import format_sarif
from .text import format_text

__all__ = ["format_text", "format_json", "format_sarif", "get_formatter"]


def get_formatter(name: str):  # type: ignore[return]
    """Get a formatter function by name."""
    formatters = {
        "text": format_text,
        "json": format_json,
        "sarif": format_sarif,
    }
    return formatters[name]
