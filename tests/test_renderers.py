from __future__ import annotations

from apk_docforge.renderers.codex_prompt import render_codex_prompt
from apk_docforge.renderers.markdown import render_report


def test_render_report_and_codex_prompt() -> None:
    data = {
        "identity": {"app_name": "Example", "package_name": "com.example", "mode": "static"},
        "features": [
            {
                "name": "login/auth",
                "category": "auth",
                "status": "inferred",
                "confidence": 0.8,
                "confidence_score": 0.8,
                "evidence_refs": [{"path": "res/layout/main.xml"}],
            }
        ],
        "app_understanding": {
            "app_name": "Example",
            "what_it_is": "Example app",
            "purpose": "Demo purpose",
            "how_it_works": [
                {
                    "step": "Opens a main screen.",
                    "status": "inferred",
                    "confidence_score": 0.7,
                    "evidence_refs": [{"path": "res/layout/main.xml"}],
                }
            ],
            "primary_users": ["test users"],
            "core_flows": [
                {
                    "name": "Main flow",
                    "description": "Open the app.",
                    "status": "inferred",
                    "confidence_score": 0.7,
                    "evidence_refs": [{"path": "res/layout/main.xml"}],
                }
            ],
            "confidence_score": 0.7,
            "evidence_refs": [{"path": "source_metadata.json"}],
        },
        "source_metadata": {"source": "local_file", "app_name": "Example"},
        "reconstruction_brief": {
            "codex_goal": "Rebuild Example",
            "recommended_mvp_scope": ["Main screen"],
            "screen_blueprint": [{"name": "Main", "description": "Home", "source": "layout"}],
            "core_data_models": ["AppState"],
            "out_of_scope": ["No bypasses"],
            "evidence_refs": [{"path": "app_understanding.json"}],
        },
        "screens": [
            {
                "name": "Main",
                "source": "layout",
                "description": "Main screen",
                "confidence": 0.7,
                "evidence_refs": [{"path": "res/layout/main.xml"}],
            }
        ],
        "ui_elements": [],
        "endpoints": [],
        "permissions": [],
        "components": {},
        "findings": [],
        "tools": {},
    }
    report = render_report(data)
    prompt = render_codex_prompt(data)
    assert "# apk-docforge static analysis report" in report
    assert "## What It Is And How It Works" in report
    assert "# Master prompt for documenting Android reverse engineering" in prompt
    assert "Write the reverse-engineering record in natural language" in prompt
    assert "## Evidence package for this app" in prompt
    assert "Do not invent features without evidence" in prompt
