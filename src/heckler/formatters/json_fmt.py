"""JSON formatter for heckler findings."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..scanner import Finding


def format_json(findings: list[Finding], **kwargs: object) -> str:
    """Format findings as a JSON array."""
    return json.dumps(
        [_finding_to_dict(f) for f in findings],
        indent=2,
        ensure_ascii=False,
    )


def _finding_to_dict(f: Finding) -> dict[str, object]:
    return {
        "file": f.file,
        "line": f.line,
        "column": f.column,
        "codepoint": f.codepoint_hex,
        "name": f.char_name,
        "category": f.category.value,
        "severity": f.severity.value,
        "source": f.source,
        "package": f.package,
    }
