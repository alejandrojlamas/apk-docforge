from __future__ import annotations

from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent


class UIExplorerAgent(BaseAgent):
    name = "UIExplorerAgent"
    output_files = (
        "navigation_graph.json",
        "ui_elements_dynamic.json",
        "screens_dynamic.json",
        "blocked_flows.json",
    )

    def run(self) -> AgentContext:
        session = self.context.data.get("dynamic_session") or self.read_json("dynamic_session.json", {})
        if session.get("status") != "completed":
            payload = {
                "schema_version": "1.0",
                "status": "not_executed",
                "reason": session.get("reason") or "Dynamic session did not complete.",
            }
            self.write_json("navigation_graph.json", {**payload, "edges": []})
            self.write_json("ui_elements_dynamic.json", {**payload, "ui_elements": []})
            self.write_json("screens_dynamic.json", {**payload, "screens": []})
            self.write_json("blocked_flows.json", {**payload, "blocked_flows": []})
            self.context.data["navigation_graph_dynamic"] = []
            self.context.data["ui_elements_dynamic"] = []
            self.context.data["screens_dynamic"] = []
            self.context.data["blocked_flows_dynamic"] = session.get("blocked_flows", [])
            return self.context

        screens = self._screens(session)
        ui_elements = self._ui_elements(session)
        edges = self._edges(session, screens)
        blocked = session.get("blocked_flows", [])

        self.write_json(
            "navigation_graph.json",
            {
                "schema_version": "1.0",
                "status": "completed",
                "nodes": [{"id": screen["id"], "label": screen["name"]} for screen in screens],
                "edges": edges,
            },
        )
        self.write_json(
            "ui_elements_dynamic.json",
            {"schema_version": "1.0", "status": "completed", "ui_elements": ui_elements},
        )
        self.write_json(
            "screens_dynamic.json",
            {"schema_version": "1.0", "status": "completed", "screens": screens},
        )
        self.write_json(
            "blocked_flows.json",
            {"schema_version": "1.0", "status": "completed", "blocked_flows": blocked},
        )
        self.context.data["navigation_graph_dynamic"] = edges
        self.context.data["ui_elements_dynamic"] = ui_elements
        self.context.data["screens_dynamic"] = screens
        self.context.data["blocked_flows_dynamic"] = blocked
        return self.context

    def _screens(self, session: dict[str, Any]) -> list[dict[str, Any]]:
        screens = []
        for step in session.get("steps", []):
            step_index = int(step.get("step_index", len(screens)))
            visible_text = self._visible_texts(step)
            name = self._screen_name(step_index, visible_text)
            screens.append(
                {
                    "id": f"dynamic_step_{step_index:02d}",
                    "name": name,
                    "source": "dynamic",
                    "description": "Screen observed through UIAutomator dump during controlled dynamic analysis.",
                    "screenshot": step.get("screenshot"),
                    "uiautomator_dump": step.get("uiautomator_dump"),
                    "ui_element_count": len(step.get("ui_nodes", [])),
                    "status": "observed",
                    "confidence": 0.85 if step.get("ui_nodes") else 0.4,
                    "evidence_refs": [
                        self.evidence(
                            path=step.get("uiautomator_dump"),
                            screenshot_path=step.get("screenshot"),
                            kind="dynamic_screen",
                        )
                    ],
                }
            )
        return screens

    def _ui_elements(self, session: dict[str, Any]) -> list[dict[str, Any]]:
        elements = []
        for step in session.get("steps", []):
            step_index = int(step.get("step_index", 0))
            dump_path = step.get("uiautomator_dump")
            screen_id = f"dynamic_step_{step_index:02d}"
            for node in step.get("ui_nodes", []):
                visible_text = node.get("text") or node.get("content_desc")
                elements.append(
                    {
                        "screen_id": screen_id,
                        "screen_step": step_index,
                        "element_type": self._element_type(node),
                        "visible_text": visible_text,
                        "resource_id": node.get("resource_id"),
                        "class_name": node.get("class_name"),
                        "clickable": node.get("clickable"),
                        "enabled": node.get("enabled"),
                        "bounds": node.get("bounds"),
                        "center": node.get("center"),
                        "action_guess": self._action_guess(node),
                        "status": "observed",
                        "confidence": 0.85,
                        "evidence_refs": [
                            self.evidence(
                                path=dump_path,
                                uiautomator_node_id=node.get("node_id"),
                                kind="uiautomator",
                            )
                        ],
                    }
                )
        return elements

    def _edges(self, session: dict[str, Any], screens: list[dict[str, Any]]) -> list[dict[str, Any]]:
        edges = []
        screen_by_step = {index: screen for index, screen in enumerate(screens)}
        for step in session.get("steps", []):
            action = step.get("action_taken")
            if not action:
                continue
            source_step = int(step.get("step_index", 0))
            target_step = source_step + 1
            if target_step not in screen_by_step:
                continue
            edges.append(
                {
                    "source": screen_by_step[source_step]["id"],
                    "target": screen_by_step[target_step]["id"],
                    "action": action.get("label") or action.get("type"),
                    "uiautomator_node_id": action.get("uiautomator_node_id"),
                    "status": "observed",
                    "confidence": 0.7,
                    "evidence_refs": [
                        self.evidence(
                            path=screen_by_step[source_step].get("uiautomator_dump"),
                            screenshot_path=screen_by_step[source_step].get("screenshot"),
                            uiautomator_node_id=action.get("uiautomator_node_id"),
                            kind="navigation",
                        )
                    ],
                }
            )
        return edges

    def _visible_texts(self, step: dict[str, Any]) -> list[str]:
        texts = []
        for node in step.get("ui_nodes", []):
            label = node.get("text") or node.get("content_desc")
            if label:
                texts.append(str(label))
        return texts[:5]

    def _screen_name(self, step_index: int, visible_texts: list[str]) -> str:
        if visible_texts:
            first = "".join(ch if ch.isalnum() else " " for ch in visible_texts[0]).strip()
            if first:
                return f"Dynamic {step_index}: {first[:40]}"
        return f"Dynamic Step {step_index}"

    def _element_type(self, node: dict[str, Any]) -> str:
        class_name = str(node.get("class_name") or "").lower()
        if "button" in class_name:
            return "button"
        if "edittext" in class_name:
            return "input"
        if "checkbox" in class_name:
            return "checkbox"
        if "switch" in class_name:
            return "switch"
        if node.get("clickable"):
            return "clickable"
        return "text"

    def _action_guess(self, node: dict[str, Any]) -> str | None:
        if not node.get("clickable"):
            return None
        label = " ".join(
            str(value)
            for value in [node.get("text"), node.get("content_desc"), node.get("resource_id")]
            if value
        ).lower()
        if any(word in label for word in ["login", "sign in", "ingresar", "entrar"]):
            return "blocked_login"
        if any(word in label for word in ["pay", "buy", "subscribe", "pagar", "comprar"]):
            return "blocked_transaction"
        if any(word in label for word in ["delete", "remove", "borrar", "eliminar"]):
            return "blocked_destructive"
        return "tap"
