from __future__ import annotations

import subprocess

from apk_docforge.tools.command_runner import run_command


def test_run_command_timeout_outputs_are_text(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["fake"],
            timeout=1,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )

    monkeypatch.setattr("apk_docforge.tools.command_runner.subprocess.run", fake_run)
    result = run_command(["fake"], timeout=1)
    assert result.timed_out is True
    assert result.stdout == "partial stdout"
    assert result.stderr == "partial stderr"
