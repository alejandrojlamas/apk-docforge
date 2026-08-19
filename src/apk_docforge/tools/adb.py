from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apk_docforge.tools.command_runner import CommandResult, run_command, which


PACKAGE_RE = re.compile(r"package:\s*name='([^']+)'")
ACTIVITY_RE = re.compile(r"<activity[^>]+android:name=\"([^\"]+)\"")


@dataclass(frozen=True)
class ADBCommand:
    name: str
    result: CommandResult

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.result.command,
            "returncode": self.result.returncode,
            "ok": self.result.ok,
            "stdout_tail": self.result.stdout[-4000:],
            "stderr_tail": self.result.stderr[-4000:],
            "timed_out": self.result.timed_out,
        }


class ADBClient:
    def __init__(self, device: str):
        self.device = device

    @property
    def available(self) -> bool:
        return bool(which("adb"))

    def base(self) -> list[str]:
        return ["adb", "-s", self.device]

    def devices(self) -> ADBCommand:
        return ADBCommand("devices", run_command(["adb", "devices"], timeout=30))

    def device_connected(self) -> tuple[bool, ADBCommand]:
        command = self.devices()
        connected = False
        for line in command.result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == self.device and parts[1] == "device":
                connected = True
                break
        return connected, command

    def install(self, apk_path: Path) -> ADBCommand:
        return ADBCommand(
            "install",
            run_command([*self.base(), "install", "-r", "--no-streaming", str(apk_path)], timeout=300),
        )

    def resolve_activity(self, package_name: str) -> ADBCommand:
        return ADBCommand(
            "resolve_activity",
            run_command(
                [*self.base(), "shell", "cmd", "package", "resolve-activity", "--brief", package_name],
                timeout=60,
            ),
        )

    def launch(self, package_name: str, activity: str | None = None) -> ADBCommand:
        if activity:
            component = f"{package_name}/{activity}"
            command = [*self.base(), "shell", "am", "start", "-n", component]
        else:
            command = [
                *self.base(),
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]
        return ADBCommand("launch", run_command(command, timeout=60))

    def dump_ui(self) -> ADBCommand:
        return ADBCommand(
            "uiautomator_dump",
            run_command([*self.base(), "exec-out", "uiautomator", "dump", "/dev/tty"], timeout=60),
        )

    def screenshot(self, output_path: Path) -> ADBCommand:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        command = [*self.base(), "exec-out", "screencap", "-p"]
        try:
            completed = subprocess.run(command, timeout=60, check=False, capture_output=True)
            if completed.returncode == 0:
                output_path.write_bytes(completed.stdout)
            result = CommandResult(
                command=command,
                returncode=completed.returncode,
                stdout=f"<{len(completed.stdout)} screenshot bytes>",
                stderr=completed.stderr.decode("utf-8", errors="replace"),
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                command=command,
                returncode=124,
                stdout="",
                stderr=f"Screenshot command timed out: {exc}",
                timed_out=True,
            )
        return ADBCommand("screenshot", result)

    def tap(self, x: int, y: int) -> ADBCommand:
        return ADBCommand("tap", run_command([*self.base(), "shell", "input", "tap", str(x), str(y)], timeout=30))

    def back(self) -> ADBCommand:
        return ADBCommand("back", run_command([*self.base(), "shell", "input", "keyevent", "4"], timeout=30))

    def clear_logcat(self) -> ADBCommand:
        return ADBCommand("logcat_clear", run_command([*self.base(), "logcat", "-c"], timeout=30))

    def dump_logcat(self) -> ADBCommand:
        return ADBCommand("logcat_dump", run_command([*self.base(), "logcat", "-d"], timeout=60))

    def crash_logcat(self) -> ADBCommand:
        return ADBCommand("logcat_crash", run_command([*self.base(), "logcat", "-b", "crash", "-d"], timeout=60))


def package_from_manifest(manifest: dict[str, Any]) -> str | None:
    package = manifest.get("package_name")
    return str(package) if package else None


def launch_activity_from_resolve(package_name: str, stdout: str) -> str | None:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith(package_name + "/"):
            return line.split("/", 1)[1]
    return None
