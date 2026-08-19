from __future__ import annotations

import re
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_API_ALLOWED_ORIGINS = (
    "http://127.0.0.1:8765",
    "http://localhost:8765",
)
LOCAL_TRUSTED_HOSTS = ("127.0.0.1", "localhost")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APK_DOCFORGE_", env_file=".env", extra="ignore")

    db_url: str = "sqlite:///./apk_docforge.db"
    output_root: Path = Field(default_factory=lambda: Path("outputs"))
    cache_dir: Path = Field(default_factory=lambda: Path("cache"))
    quarantine_dir: Path = Field(default_factory=lambda: Path("quarantine"))
    local_env_path: Path = Field(default_factory=lambda: Path(".env"))
    allow_dynamic: bool = False
    api_allowed_origins: str = ",".join(DEFAULT_API_ALLOWED_ORIGINS)
    max_upload_bytes: int = Field(default=256 * 1024 * 1024, gt=0, le=8 * 1024 * 1024 * 1024)
    max_download_bytes: int = Field(default=512 * 1024 * 1024, gt=0, le=8 * 1024 * 1024 * 1024)
    max_nested_artifact_bytes: int = Field(
        default=256 * 1024 * 1024,
        gt=0,
        le=8 * 1024 * 1024 * 1024,
    )
    max_archive_members: int = Field(default=10_000, gt=0, le=100_000)
    max_archive_uncompressed_bytes: int = Field(
        default=1024 * 1024 * 1024,
        gt=0,
        le=16 * 1024 * 1024 * 1024,
    )
    max_download_redirects: int = Field(default=5, ge=0, le=10)
    documentation_provider: str = "deepseek"
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("DEEPSEEK_API_KEY", "APK_DOCFORGE_DEEPSEEK_API_KEY"),
    )
    official_url_allowlist: str = ""
    google_play_credentials_json: str | None = None

    @field_validator("api_allowed_origins")
    @classmethod
    def validate_api_allowed_origins(cls, value: str) -> str:
        origins = [_normalize_local_origin(item) for item in value.split(",") if item.strip()]
        if not origins:
            raise ValueError("api_allowed_origins must contain at least one exact loopback origin")
        return ",".join(dict.fromkeys(origins))

    @field_validator("official_url_allowlist")
    @classmethod
    def validate_official_url_allowlist(cls, value: str) -> str:
        return normalize_official_url_allowlist(value)

    @property
    def api_allowed_origin_list(self) -> list[str]:
        return [item for item in self.api_allowed_origins.split(",") if item]

    @property
    def official_url_hosts(self) -> set[str]:
        return {item.strip().lower() for item in self.official_url_allowlist.split(",") if item.strip()}


def _normalize_local_origin(value: str) -> str:
    origin = value.strip()
    if "\r" in origin or "\n" in origin or origin == "*":
        raise ValueError("API origins must be exact loopback origins without control characters")
    parsed = urlsplit(origin)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("API origins must use http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("API origins cannot contain credentials, paths, queries, or fragments")
    host = (parsed.hostname or "").lower()
    if host != "localhost":
        try:
            address = ip_address(host)
        except ValueError as exc:
            raise ValueError("API origins must use localhost or a loopback IP address") from exc
        if not address.is_loopback:
            raise ValueError("API origins must use localhost or a loopback IP address")
        if str(address) != "127.0.0.1":
            raise ValueError("API origins currently support only localhost or 127.0.0.1")
        host = str(address)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("API origin contains an invalid port") from exc
    rendered_host = f"[{host}]" if ":" in host else host
    rendered_port = f":{port}" if port is not None else ""
    return f"{parsed.scheme.lower()}://{rendered_host}{rendered_port}"


def _normalize_host(value: str) -> str:
    host = value.strip().lower()
    if "\r" in host or "\n" in host or any(character.isspace() for character in host):
        raise ValueError("Official URL allowlist entries cannot contain whitespace or control characters")
    if any(marker in host for marker in ("*", "://", "/", "@", ":")):
        raise ValueError("Official URL allowlist entries must be exact host names without schemes or ports")
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Official URL allowlist entries must be DNS host names, not IP literals")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid official URL host: {value}") from exc
    labels = ascii_host.rstrip(".").split(".")
    if not labels or any(not HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"Invalid official URL host: {value}")
    return ".".join(labels)


def normalize_official_url_allowlist(value: str) -> str:
    hosts = [_normalize_host(item) for item in value.split(",") if item.strip()]
    return ",".join(dict.fromkeys(hosts))


@lru_cache
def get_settings() -> Settings:
    return Settings()
