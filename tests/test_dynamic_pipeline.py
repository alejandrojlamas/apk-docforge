from __future__ import annotations

import json
from pathlib import Path

from apk_docforge.pipeline import run_analysis
from apk_docforge.tools.command_runner import CommandResult


class FakeADBCommand:
    def __init__(self, name: str, ok: bool = True, stdout: str = "", stderr: str = ""):
        self.name = name
        self.result = CommandResult(
            command=["fake-adb", name],
            returncode=0 if ok else 1,
            stdout=stdout,
            stderr=stderr,
        )

    def to_json(self):
        return {
            "name": self.name,
            "command": self.result.command,
            "returncode": self.result.returncode,
            "ok": self.result.ok,
            "stdout_tail": self.result.stdout,
            "stderr_tail": self.result.stderr,
            "timed_out": False,
        }


class FakeADBClient:
    def __init__(self, device: str):
        self.device = device
        self.dump_count = 0

    @property
    def available(self) -> bool:
        return True

    def device_connected(self):
        return True, FakeADBCommand("devices", stdout=f"List of devices attached\n{self.device}\tdevice\n")

    def install(self, apk_path: Path):
        return FakeADBCommand("install", stdout="Success")

    def clear_logcat(self):
        return FakeADBCommand("logcat_clear")

    def resolve_activity(self, package_name: str):
        return FakeADBCommand("resolve_activity", stdout=f"{package_name}/.MainActivity\n")

    def launch(self, package_name: str, activity: str | None = None):
        return FakeADBCommand("launch", stdout="Starting")

    def dump_ui(self):
        self.dump_count += 1
        if self.dump_count == 1:
            xml = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy>
  <node text="Continue" resource-id="app:id/continue" class="android.widget.Button" clickable="true" enabled="true" password="false" bounds="[0,0][100,100]" />
  <node text="Login" resource-id="app:id/login" class="android.widget.Button" clickable="true" enabled="true" password="false" bounds="[0,120][100,220]" />
  <node text="Pay now" resource-id="app:id/pay" class="android.widget.Button" clickable="true" enabled="true" password="false" bounds="[0,240][100,340]" />
</hierarchy>"""
        else:
            xml = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy>
  <node text="Home" resource-id="app:id/home" class="android.widget.TextView" clickable="false" enabled="true" password="false" bounds="[0,0][200,100]" />
</hierarchy>"""
        return FakeADBCommand("uiautomator_dump", stdout=xml)

    def screenshot(self, output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"\x89PNG\r\n\x1a\n")
        return FakeADBCommand("screenshot", stdout="<8 screenshot bytes>")

    def tap(self, x: int, y: int):
        return FakeADBCommand("tap", stdout=f"tap {x} {y}")

    def dump_logcat(self):
        return FakeADBCommand("logcat_dump", stdout="I/App: ok")

    def crash_logcat(self):
        return FakeADBCommand("logcat_crash", stdout="")


class UnavailableADBClient:
    def __init__(self, device: str):
        self.device = device

    @property
    def available(self) -> bool:
        return False


def test_dynamic_pipeline_blocks_without_adb(sample_apk, tmp_path, isolated_app_env, monkeypatch) -> None:
    monkeypatch.setattr("apk_docforge.agents.dynamic_runner.ADBClient", UnavailableADBClient)
    out = tmp_path / "dynamic-blocked"
    summary = run_analysis(sample_apk, out=out, mode="dynamic", device="emulator-5554")
    assert summary["status"] == "completed"
    assert summary["dynamic_status"] == "blocked"
    session = json.loads((out / "dynamic_session.json").read_text())
    assert session["status"] == "blocked"
    assert "adb" in session["reason"]


def test_dynamic_pipeline_with_fake_adb(sample_apk, tmp_path, isolated_app_env, monkeypatch) -> None:
    monkeypatch.setattr("apk_docforge.agents.dynamic_runner.ADBClient", FakeADBClient)
    out = tmp_path / "dynamic-completed"
    summary = run_analysis(sample_apk, out=out, mode="dynamic", device="emulator-5554")
    assert summary["dynamic_status"] == "completed"

    session = json.loads((out / "dynamic_session.json").read_text())
    assert session["status"] == "completed"
    assert session["steps"][0]["action_taken"]["label"] == "Continue"
    assert any(item["type"] == "destructive_or_transactional_action" for item in session["blocked_flows"])

    screens = json.loads((out / "screens_dynamic.json").read_text())
    assert screens["status"] == "completed"
    assert len(screens["screens"]) >= 2

    nav = json.loads((out / "navigation_graph.json").read_text())
    assert nav["edges"][0]["action"] == "Continue"

    elements = json.loads((out / "ui_elements_dynamic.json").read_text())
    assert any(item["visible_text"] == "Login" for item in elements["ui_elements"])
