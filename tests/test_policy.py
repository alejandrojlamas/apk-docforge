from __future__ import annotations

from apk_docforge.tools.policy import PolicyEngine, PolicyStatus


def test_mirrors_are_disabled_by_default() -> None:
    decision = PolicyEngine().validate_source("third_party_mirror")
    assert decision.status == PolicyStatus.DISABLED_BY_POLICY
    assert decision.allowed is False


def test_fdroid_is_allowed() -> None:
    decision = PolicyEngine().validate_source("fdroid")
    assert decision.status == PolicyStatus.ALLOWED
    assert decision.allowed is True


def test_google_play_scraping_blocked_without_credentials() -> None:
    decision = PolicyEngine().validate_source("google_play")
    assert decision.allowed is False
    assert "scraping" in decision.reason.lower()


def test_dynamic_mode_explicit_opt_in_allowed() -> None:
    decision = PolicyEngine().validate_dynamic(own_or_authorized=True, explicit_enabled=True)
    assert decision.allowed is True


def test_download_policies_require_https_and_approved_hosts(isolated_app_env) -> None:
    policy = PolicyEngine()
    assert policy.validate_official_url("http://example.com/app.apk").allowed is False
    assert policy.validate_source("github", "https://attacker.example/app.apk").allowed is False
    assert policy.validate_source(
        "github", "https://release-assets.githubusercontent.com/app.apk"
    ).allowed is True
