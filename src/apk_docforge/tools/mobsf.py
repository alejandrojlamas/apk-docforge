from __future__ import annotations

from apk_docforge.tools.command_runner import which


def mobsfscan_available() -> bool:
    return bool(which("mobsfscan"))
