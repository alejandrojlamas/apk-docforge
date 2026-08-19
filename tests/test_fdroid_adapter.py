from __future__ import annotations

from apk_docforge.adapters.fdroid import FDroidAdapter


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_fdroid_adapter_maps_index(monkeypatch) -> None:
    index = {
        "packages": {
            "org.example.app": {
                "metadata": {
                    "name": {"en-US": "Example App"},
                    "summary": {"en-US": "Demo"},
                    "description": {"en-US": "Demo app for tests."},
                    "categories": ["Development"],
                    "license": "Apache-2.0",
                    "sourceCode": "https://example.org/src",
                    "webSite": "https://example.org",
                },
                "versions": {
                    "1": {
                        "manifest": {"versionName": "1.0", "versionCode": 1},
                        "file": {"name": "org.example.app_1.apk", "sha256": "abc"},
                    },
                    "2": {
                        "manifest": {"versionName": "2.0", "versionCode": 2},
                        "file": {"name": "org.example.app_2.apk", "sha256": "def"},
                    },
                }
            }
        },
    }

    def fake_get(*args, **kwargs):
        return FakeResponse(index)

    monkeypatch.setattr("apk_docforge.adapters.fdroid.httpx.get", fake_get)
    result = FDroidAdapter().search("example")
    assert result.policy_decision["allowed"] is True
    assert result.candidates[0]["package_name"] == "org.example.app"
    assert result.candidates[0]["app_name"] == "Example App"
    assert result.candidates[0]["summary"] == "Demo"
    assert result.candidates[0]["categories"] == ["Development"]
    assert result.candidates[0]["version_name"] == "2.0"
    assert result.candidates[0]["download_url"].endswith("org.example.app_2.apk")


def test_fdroid_adapter_supports_legacy_apps_shape(monkeypatch) -> None:
    index = {
        "apps": {
            "org.example.legacy": {
                "localized": {"en-US": {"name": "Legacy App", "summary": "Old index"}},
                "license": "Apache-2.0",
                "sourceCode": "https://example.org/src",
            }
        },
        "packages": {
            "org.example.legacy": {
                "metadata": {
                    "localized": {"en-US": {"name": "Legacy App", "summary": "Old index"}},
                    "license": "Apache-2.0",
                    "sourceCode": "https://example.org/src",
                },
                "versions": {
                    "1": {
                        "manifest": {"versionName": "1.0", "versionCode": 1},
                        "file": {"name": "org.example.legacy_1.apk", "sha256": "abc"},
                    },
                },
            }
        },
    }

    def fake_get(*args, **kwargs):
        return FakeResponse(index)

    monkeypatch.setattr("apk_docforge.adapters.fdroid.httpx.get", fake_get)
    result = FDroidAdapter().search("legacy")
    assert result.candidates[0]["app_name"] == "Legacy App"
