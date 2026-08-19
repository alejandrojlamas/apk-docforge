from __future__ import annotations

import stat
from pathlib import Path

import pytest

from apk_docforge.services.settings_store import _write_env_updates, update_local_settings


def test_settings_file_is_private_and_public_response_hides_secrets(
    isolated_app_env: Path,
) -> None:
    response = update_local_settings(
        {
            "deepseek_api_key": "private-key",
            "google_play_credentials_json": "/private/credentials.json",
        }
    )
    env_path = isolated_app_env / ".env"

    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert "private-key" in env_path.read_text(encoding="utf-8")
    assert response["deepseek_api_key_configured"] is True
    assert response["google_play_credentials_configured"] is True
    assert "deepseek_api_key" not in response
    assert "google_play_credentials_json" not in response


def test_settings_reject_control_characters_without_writing(isolated_app_env: Path) -> None:
    env_path = isolated_app_env / ".env"
    with pytest.raises(ValueError, match="CR, LF, or NUL"):
        update_local_settings({"deepseek_api_key": "secret\nINJECTED=value"})
    assert not env_path.exists()


def test_settings_reject_invalid_existing_environment_name(isolated_app_env: Path) -> None:
    env_path = isolated_app_env / ".env"
    env_path.write_text("INVALID-NAME=value\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid environment name"):
        _write_env_updates(env_path, {"allow_dynamic": "true"})
