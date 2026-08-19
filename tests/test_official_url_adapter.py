from __future__ import annotations

from apk_docforge.adapters.official_url import OfficialURLAdapter


def test_official_url_allowlist(isolated_app_env) -> None:
    result = OfficialURLAdapter().search("https://example.com/releases/app.apk")
    assert result.policy_decision["allowed"] is True
    assert result.candidates[0]["download_url"] == "https://example.com/releases/app.apk"


def test_official_url_blocks_non_artifact(isolated_app_env) -> None:
    result = OfficialURLAdapter().search("https://example.com/releases/")
    assert result.policy_decision["allowed"] is False
    assert result.candidates == []
