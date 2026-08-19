from __future__ import annotations

import re
from typing import Any


ERROR_RE = re.compile(r"\b(FATAL EXCEPTION|AndroidRuntime|E/|Exception|ANR)\b")
SENSITIVE_RE = re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\b")


def summarize_logcat(text: str, max_lines: int = 200) -> dict[str, Any]:
    lines = text.splitlines()
    errors = [line for line in lines if ERROR_RE.search(line)]
    sensitive_markers = [redact_sensitive(line) for line in lines if SENSITIVE_RE.search(line)]
    return {
        "line_count": len(lines),
        "error_count": len(errors),
        "errors_tail": errors[-max_lines:],
        "sensitive_marker_count": len(sensitive_markers),
        "sensitive_markers_tail": sensitive_markers[-50:],
        "status": "observed" if lines else "unknown",
    }


def redact_sensitive(line: str) -> str:
    return SENSITIVE_RE.sub("[REDACTED_KEYWORD]", line)
