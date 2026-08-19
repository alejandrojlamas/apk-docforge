from __future__ import annotations

from apk_docforge.services.source_registry import list_sources, save_candidates, upsert_source


def test_default_sources_and_candidate_persistence(isolated_app_env) -> None:
    sources = list_sources()
    assert any(item["type"] == "fdroid" for item in sources)
    assert any(item["type"] == "third_party_mirror" and not item["enabled"] for item in sources)

    custom = upsert_source({"type": "custom", "name": "Custom", "policy_status": "UNKNOWN"})
    assert custom["type"] == "custom"

    saved = save_candidates(
        [
            {
                "id": "fdroid:org.example.app",
                "source": "fdroid",
                "package_name": "org.example.app",
                "app_name": "Example",
                "version_name": "1.0",
                "version_code": "1",
                "license": "Apache-2.0",
                "source_url": "https://example.org/src",
                "download_url": "https://f-droid.org/repo/org.example.app.apk",
                "checksum": "abc",
                "policy_status": "ALLOWED",
            }
        ]
    )
    assert saved[0]["id"] > 0
    assert saved[0]["source"] == "fdroid"


def test_upsert_source_coerces_enabled_string(isolated_app_env) -> None:
    disabled = upsert_source({"type": "custom_bool", "name": "Custom Bool", "enabled": "false"})
    assert disabled["enabled"] is False

    enabled = upsert_source({"type": "custom_bool", "enabled": "true"})
    assert enabled["enabled"] is True


def test_default_sources_do_not_overwrite_user_updates(isolated_app_env) -> None:
    updated = upsert_source({"type": "official_url", "enabled": "false", "notes": "custom allowlist note"})
    assert updated["enabled"] is False
    assert updated["notes"] == "custom allowlist note"

    sources = list_sources()
    official = next(item for item in sources if item["type"] == "official_url")
    assert official["enabled"] is False
    assert official["notes"] == "custom allowlist note"
