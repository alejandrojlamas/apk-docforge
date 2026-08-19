from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.tools.adb import ADBClient, launch_activity_from_resolve, package_from_manifest
from apk_docforge.tools.archive import ensure_dir
from apk_docforge.tools.logcat import summarize_logcat
from apk_docforge.tools.policy import PolicyEngine
from apk_docforge.tools.uiautomator import (
    classify_blocked_flows,
    parse_uiautomator_dump,
    safe_tap_candidates,
)


class DynamicRunnerAgent(BaseAgent):
    name = "DynamicRunnerAgent"
    output_files = (
        "dynamic_session.json",
        "logcat_summary.json",
        "screenshots/",
        "ui_dumps/",
        "runtime_errors.json",
    )

    def run(self) -> AgentContext:
        screenshots_dir = ensure_dir(self.context.output_dir / "screenshots")
        ui_dumps_dir = ensure_dir(self.context.output_dir / "ui_dumps")
        tool_outputs = ensure_dir(self.context.artifacts_dir / "tool_outputs")

        decision = PolicyEngine().validate_dynamic(
            own_or_authorized=True,
            explicit_enabled=self.context.mode == "dynamic",
        )
        if not decision.allowed:
            payload = self._blocked_payload(decision.to_json(), "Dynamic analysis was not enabled.")
            self._write_blocked_outputs(payload)
            return self.context

        device = self.context.device
        if not device:
            payload = self._blocked_payload(
                decision.to_json(),
                "Dynamic mode requires --device with an authorized emulator/test device serial.",
            )
            self._write_blocked_outputs(payload)
            return self.context

        package_name = package_from_manifest(self.context.data.get("manifest", {}))
        if not package_name:
            payload = self._blocked_payload(
                decision.to_json(),
                "Package name is unknown; cannot install or launch dynamically.",
            )
            self._write_blocked_outputs(payload)
            return self.context

        adb = ADBClient(device)
        commands: list[dict[str, Any]] = []
        if not adb.available:
            payload = self._blocked_payload(
                decision.to_json(),
                "adb is not installed or not on PATH.",
            )
            self._write_blocked_outputs(payload)
            return self.context

        connected, devices_command = adb.device_connected()
        commands.append(devices_command.to_json())
        if not connected:
            payload = self._blocked_payload(
                decision.to_json(),
                f"Device `{device}` was not listed by `adb devices` as ready.",
                commands,
            )
            self._write_blocked_outputs(payload)
            return self.context

        apk_path = Path(self.context.data.get("primary_apk_path", self.context.input_path))
        install = adb.install(apk_path)
        commands.append(install.to_json())
        if not install.result.ok:
            payload = self._blocked_payload(
                decision.to_json(),
                "adb install failed. Split APK/APKS installation is not implemented.",
                commands,
            )
            self._write_blocked_outputs(payload)
            return self.context

        commands.append(adb.clear_logcat().to_json())
        resolve = adb.resolve_activity(package_name)
        commands.append(resolve.to_json())
        launch_activity = launch_activity_from_resolve(package_name, resolve.result.stdout)
        launch = adb.launch(package_name, launch_activity)
        commands.append(launch.to_json())
        time.sleep(1.0)

        steps = []
        blocked_flows: list[dict[str, Any]] = []
        runtime_errors: list[dict[str, Any]] = []
        for step_index in range(4):
            step = self._capture_step(
                adb=adb,
                step_index=step_index,
                screenshots_dir=screenshots_dir,
                ui_dumps_dir=ui_dumps_dir,
                commands=commands,
            )
            steps.append(step)
            blocked_flows.extend(step.get("blocked_flows", []))
            if step_index >= 3:
                break
            candidate = step.get("safe_tap_candidate")
            if not candidate:
                break
            center = candidate.get("center")
            if not center:
                break
            tap = adb.tap(int(center[0]), int(center[1]))
            commands.append(tap.to_json())
            steps[-1]["action_taken"] = {
                "type": "tap",
                "label": candidate.get("label"),
                "uiautomator_node_id": candidate.get("node_id"),
                "x": center[0],
                "y": center[1],
                "safety": "non_destructive_candidate",
            }
            time.sleep(0.8)

        logcat = adb.dump_logcat()
        commands.append(logcat.to_json())
        crash_logcat = adb.crash_logcat()
        commands.append(crash_logcat.to_json())
        (tool_outputs / "logcat.txt").write_text(logcat.result.stdout, encoding="utf-8", errors="replace")
        (tool_outputs / "logcat_crash.txt").write_text(
            crash_logcat.result.stdout,
            encoding="utf-8",
            errors="replace",
        )
        logcat_summary = summarize_logcat(logcat.result.stdout)
        crash_summary = summarize_logcat(crash_logcat.result.stdout)
        if logcat_summary["error_count"]:
            runtime_errors.append(
                {
                    "source": "logcat",
                    "severity": "medium",
                    "count": logcat_summary["error_count"],
                    "evidence_refs": [self.evidence(path=tool_outputs / "logcat.txt", kind="logcat")],
                }
            )
        if crash_summary["error_count"]:
            runtime_errors.append(
                {
                    "source": "logcat_crash",
                    "severity": "high",
                    "count": crash_summary["error_count"],
                    "evidence_refs": [self.evidence(path=tool_outputs / "logcat_crash.txt", kind="logcat")],
                }
            )

        dynamic_session = {
            "schema_version": "1.0",
            "status": "completed",
            "device": device,
            "package_name": package_name,
            "launch_activity": launch_activity,
            "apk_path": str(apk_path),
            "policy_decision": decision.to_json(),
            "safe_navigation_policy": {
                "login": "blocked",
                "payments_purchases_subscriptions": "blocked",
                "destructive_actions": "blocked",
                "publishing_sending_sharing": "blocked",
                "credential_entry": "blocked; this runner never enters credentials",
            },
            "steps": steps,
            "blocked_flows": blocked_flows,
            "commands": commands,
        }
        self.write_json("dynamic_session.json", dynamic_session)
        self.write_json(
            "logcat_summary.json",
            {"schema_version": "1.0", "logcat": logcat_summary, "crash": crash_summary},
        )
        self.write_json(
            "runtime_errors.json",
            {"schema_version": "1.0", "status": "completed", "runtime_errors": runtime_errors},
        )
        self.context.data["dynamic_session"] = dynamic_session
        self.context.data["blocked_flows_dynamic"] = blocked_flows
        self.context.data["runtime_errors"] = runtime_errors
        return self.context

    def _capture_step(
        self,
        *,
        adb: ADBClient,
        step_index: int,
        screenshots_dir: Path,
        ui_dumps_dir: Path,
        commands: list[dict[str, Any]],
    ) -> dict[str, Any]:
        dump_command = adb.dump_ui()
        commands.append(dump_command.to_json())
        dump_path = ui_dumps_dir / f"step_{step_index:02d}.xml"
        dump_path.write_text(dump_command.result.stdout, encoding="utf-8", errors="replace")

        screenshot_path = screenshots_dir / f"step_{step_index:02d}.png"
        screenshot_command = adb.screenshot(screenshot_path)
        commands.append(screenshot_command.to_json())

        nodes = parse_uiautomator_dump(dump_command.result.stdout)
        blocked = classify_blocked_flows(nodes)
        candidates = safe_tap_candidates(nodes, limit=3)
        chosen = candidates[0] if candidates else None
        return {
            "step_index": step_index,
            "uiautomator_dump": str(dump_path),
            "screenshot": str(screenshot_path) if screenshot_path.exists() else None,
            "node_count": len(nodes),
            "clickable_count": sum(1 for node in nodes if node.clickable),
            "safe_tap_candidate": self._candidate_json(chosen) if chosen else None,
            "blocked_flows": [
                {
                    **item,
                    "evidence_refs": [
                        self.evidence(
                            path=dump_path,
                            uiautomator_node_id=item.get("uiautomator_node_id"),
                            kind="uiautomator",
                        )
                    ],
                }
                for item in blocked
            ],
            "ui_nodes": [
                {
                    **node.to_json(),
                    "evidence_refs": [
                        self.evidence(path=dump_path, uiautomator_node_id=node.node_id, kind="uiautomator")
                    ],
                }
                for node in nodes
            ],
        }

    def _candidate_json(self, node: Any) -> dict[str, Any]:
        return {
            **node.to_json(),
            "label": node.label,
            "safety": "candidate_label_is_non_destructive_and_enabled",
        }

    def _blocked_payload(
        self,
        decision: dict[str, Any],
        reason: str,
        commands: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "status": "blocked",
            "policy_decision": decision,
            "reason": reason,
            "device": self.context.device,
            "commands": commands or [],
        }

    def _write_blocked_outputs(self, payload: dict[str, Any]) -> None:
        self.write_json("dynamic_session.json", payload)
        self.write_json(
            "logcat_summary.json",
            {"schema_version": "1.0", "status": "not_collected", "reason": payload["reason"]},
        )
        self.write_json("runtime_errors.json", {"schema_version": "1.0", "status": "not_collected", "runtime_errors": []})
        self.context.data["dynamic_session"] = payload
        self.context.data["blocked_flows_dynamic"] = []
        self.context.data["runtime_errors"] = []
