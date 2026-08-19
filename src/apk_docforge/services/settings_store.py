from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from apk_docforge.config import ENV_NAME_RE, get_settings, normalize_official_url_allowlist


ENV_KEY_MAP = {
    "documentation_provider": "APK_DOCFORGE_DOCUMENTATION_PROVIDER",
    "deepseek_api_key": "APK_DOCFORGE_DEEPSEEK_API_KEY",
    "official_url_allowlist": "APK_DOCFORGE_OFFICIAL_URL_ALLOWLIST",
    "google_play_credentials_json": "APK_DOCFORGE_GOOGLE_PLAY_CREDENTIALS_JSON",
    "allow_dynamic": "APK_DOCFORGE_ALLOW_DYNAMIC",
}


def public_settings() -> dict[str, Any]:
    settings = get_settings()
    return {
        "documentation_provider": settings.documentation_provider,
        "deepseek_model": settings.deepseek_model,
        "deepseek_api_key_configured": bool(settings.deepseek_api_key),
        "official_url_allowlist": settings.official_url_allowlist,
        "official_url_hosts": sorted(settings.official_url_hosts),
        "google_play_credentials_configured": bool(settings.google_play_credentials_json),
        "allow_dynamic": settings.allow_dynamic,
    }


def update_local_settings(payload: dict[str, Any]) -> dict[str, Any]:
    updates: dict[str, str | None] = {}
    if "documentation_provider" in payload:
        updates["documentation_provider"] = str(payload["documentation_provider"] or "deepseek")
    if payload.get("clear_deepseek_api_key"):
        updates["deepseek_api_key"] = None
    elif payload.get("deepseek_api_key"):
        updates["deepseek_api_key"] = str(payload["deepseek_api_key"])
    if "official_url_allowlist" in payload:
        updates["official_url_allowlist"] = normalize_official_url_allowlist(
            str(payload["official_url_allowlist"] or "")
        )
    if "google_play_credentials_json" in payload:
        updates["google_play_credentials_json"] = str(payload["google_play_credentials_json"] or "")
    if "allow_dynamic" in payload:
        updates["allow_dynamic"] = "true" if bool(payload["allow_dynamic"]) else "false"

    if updates:
        env_path = get_settings().local_env_path.expanduser()
        _write_env_updates(env_path, updates)
        _apply_to_process_env(updates)
        get_settings.cache_clear()
    return public_settings()


def _write_env_updates(env_path: Path, updates: dict[str, str | None]) -> None:
    env_path.parent.mkdir(parents=True, exist_ok=True)
    current = _read_env(env_path)
    for key, value in updates.items():
        if key not in ENV_KEY_MAP:
            raise ValueError(f"Unsupported settings name: {key}")
        env_key = ENV_KEY_MAP[key]
        _validate_env_name(env_key)
        if value is None:
            current.pop(env_key, None)
        else:
            current[env_key] = _validate_env_value(value)
    lines = [f"{key}={_quote_env_value(value)}" for key, value in current.items()]
    _write_private_env(env_path, "\n".join(lines) + ("\n" if lines else ""))


def _read_env(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_path.exists():
        return values
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env_key = key.strip()
        _validate_env_name(env_key)
        if env_key in values:
            raise ValueError(f"Duplicate environment name in {env_path}: {env_key}")
        values[env_key] = _validate_env_value(_unquote_env_value(value.strip()))
    return values


def _apply_to_process_env(updates: dict[str, str | None]) -> None:
    for key, value in updates.items():
        env_key = ENV_KEY_MAP[key]
        if value is None:
            os.environ.pop(env_key, None)
            if env_key == "APK_DOCFORGE_DEEPSEEK_API_KEY":
                os.environ.pop("DEEPSEEK_API_KEY", None)
        else:
            os.environ[env_key] = value


def _quote_env_value(value: str) -> str:
    value = _validate_env_value(value)
    if not value:
        return '""'
    if any(char.isspace() for char in value) or any(marker in value for marker in ['"', "'", "#", "="]):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _unquote_env_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _validate_env_name(name: str) -> str:
    if not ENV_NAME_RE.fullmatch(name):
        raise ValueError(f"Invalid environment name: {name}")
    return name


def _validate_env_value(value: str) -> str:
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError("Setting values cannot contain CR, LF, or NUL characters")
    return value


def _write_private_env(env_path: Path, content: str) -> None:
    if env_path.exists() and (env_path.is_symlink() or not env_path.is_file()):
        raise ValueError(f"Local settings path must be a regular file: {env_path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{env_path.name}.",
        suffix=".tmp",
        dir=env_path.parent,
    )
    temporary_path = Path(temporary_name)
    descriptor_open = True
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor_open = False
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, env_path)
        os.chmod(env_path, 0o600)
    except Exception:
        if descriptor_open:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise
