from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from apk_docforge.config import Settings, get_settings


FDROID_DOWNLOAD_HOSTS = frozenset({"f-droid.org"})
GITHUB_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)


class PolicyStatus(str, Enum):
    ALLOWED = "ALLOWED"
    REQUIRES_EXPLICIT_AUTH = "REQUIRES_EXPLICIT_AUTH"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PolicyDecision:
    status: PolicyStatus
    reason: str
    allowed: bool

    def to_json(self) -> dict[str, str | bool]:
        return {"status": self.status.value, "reason": self.reason, "allowed": self.allowed}


class PolicyEngine:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    def validate_local_file(self, declared_authorized: bool = True) -> PolicyDecision:
        if declared_authorized:
            return PolicyDecision(
                PolicyStatus.ALLOWED,
                "Local file analysis is allowed when the user declares ownership or authorization.",
                True,
            )
        return PolicyDecision(
            PolicyStatus.REQUIRES_EXPLICIT_AUTH,
            "Local app analysis requires ownership, open-source status, or explicit permission.",
            False,
        )

    def validate_source(self, source_type: str, url: str | None = None) -> PolicyDecision:
        normalized = source_type.lower().strip()
        if normalized in {"fdroid", "f-droid"}:
            if url:
                return self._validate_https_download_host(
                    url,
                    FDROID_DOWNLOAD_HOSTS,
                    "F-Droid downloads must remain on an approved F-Droid host.",
                )
            return PolicyDecision(
                PolicyStatus.ALLOWED,
                "F-Droid repository metadata and public APK downloads are allowed for open-source apps.",
                True,
            )
        if normalized in {"github", "github_releases"}:
            if url:
                return self._validate_https_download_host(
                    url,
                    GITHUB_DOWNLOAD_HOSTS,
                    "GitHub release downloads must remain on an approved GitHub asset host.",
                )
            return PolicyDecision(
                PolicyStatus.ALLOWED,
                "Public GitHub Releases are allowed when license/authorization is recorded.",
                True,
            )
        if normalized in {"official_url", "official"}:
            return self.validate_official_url(url)
        if normalized in {"google_play", "google_play_developer"}:
            if self.settings.google_play_credentials_json:
                return PolicyDecision(
                    PolicyStatus.REQUIRES_EXPLICIT_AUTH,
                    "Google Play Developer API may be used only for apps owned or explicitly authorized; scraping is not allowed.",
                    False,
                )
            return PolicyDecision(
                PolicyStatus.BLOCKED,
                "Google Play access requires explicit Developer API credentials and ownership proof; scraping is not allowed.",
                False,
            )
        if normalized in {"mirror", "third_party_mirror", "apk_mirror", "apkpure"}:
            return PolicyDecision(
                PolicyStatus.DISABLED_BY_POLICY,
                "Third-party APK mirrors are disabled by default to avoid restricted, paid, or unauthorized APK downloads.",
                False,
            )
        return PolicyDecision(
            PolicyStatus.UNKNOWN,
            "Unknown source type; blocked until a specific policy adapter allows it.",
            False,
        )

    def validate_official_url(self, url: str | None) -> PolicyDecision:
        if not url:
            return PolicyDecision(
                PolicyStatus.REQUIRES_EXPLICIT_AUTH,
                "Official URL downloads require an allowlisted URL.",
                False,
            )
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if (
            parsed.scheme.lower() != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
        ):
            return PolicyDecision(
                PolicyStatus.BLOCKED,
                "Official URL downloads require HTTPS without embedded credentials.",
                False,
            )
        if host.lower() in self.settings.official_url_hosts:
            return PolicyDecision(
                PolicyStatus.ALLOWED,
                "Official URL host is allowlisted.",
                True,
            )
        return PolicyDecision(
            PolicyStatus.REQUIRES_EXPLICIT_AUTH,
            "Official URL host is not allowlisted; configure APK_DOCFORGE_OFFICIAL_URL_ALLOWLIST first.",
            False,
        )

    def _validate_https_download_host(
        self,
        url: str,
        allowed_hosts: frozenset[str],
        blocked_reason: str,
    ) -> PolicyDecision:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme.lower() != "https"
            or host not in allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
        ):
            return PolicyDecision(PolicyStatus.BLOCKED, blocked_reason, False)
        return PolicyDecision(
            PolicyStatus.ALLOWED,
            "Download URL uses HTTPS and an approved source host.",
            True,
        )

    def validate_dynamic(self, own_or_authorized: bool, explicit_enabled: bool) -> PolicyDecision:
        if not own_or_authorized:
            return PolicyDecision(
                PolicyStatus.BLOCKED,
                "Dynamic analysis requires an owned test app or explicit authorization.",
                False,
            )
        if not (explicit_enabled or self.settings.allow_dynamic):
            return PolicyDecision(
                PolicyStatus.DISABLED_BY_POLICY,
                "Dynamic analysis is disabled by default and must be explicitly enabled with --mode dynamic or APK_DOCFORGE_ALLOW_DYNAMIC=true.",
                False,
            )
        return PolicyDecision(
            PolicyStatus.ALLOWED,
            "Dynamic analysis may run only on a test emulator/device with non-destructive navigation.",
            True,
        )
