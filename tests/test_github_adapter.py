from __future__ import annotations

from apk_docforge.adapters.github_releases import GitHubReleasesAdapter


class FakeResponse:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_github_adapter_maps_search(monkeypatch) -> None:
    def fake_get(url, *args, **kwargs):
        if url == "https://api.github.com/search/repositories":
            return FakeResponse(
                {
                    "items": [
                        {
                            "full_name": "owner/app",
                            "name": "app",
                            "owner": {"login": "owner"},
                            "license": {"spdx_id": "MIT"},
                            "html_url": "https://github.com/owner/app",
                        }
                    ]
                }
            )
        if url == "https://api.github.com/repos/owner/app/releases":
            return FakeResponse(
                [
                    {
                        "id": 10,
                        "tag_name": "v1.0.0",
                        "name": "v1.0.0",
                        "html_url": "https://github.com/owner/app/releases/tag/v1.0.0",
                        "assets": [
                            {
                                "id": 20,
                                "name": "app-release.apk",
                                "browser_download_url": "https://github.com/owner/app/releases/download/v1/app-release.apk",
                                "digest": "sha256:abc",
                                "size": 123,
                                "content_type": "application/vnd.android.package-archive",
                            },
                            {"id": 21, "name": "readme.txt"},
                        ],
                    }
                ]
            )
        raise AssertionError(url)

    monkeypatch.setattr("apk_docforge.adapters.github_releases.httpx.get", fake_get)
    result = GitHubReleasesAdapter().search("app")
    assert result.policy_decision["allowed"] is True
    assert result.candidates[0]["id"] == "github:owner/app:10:20"
    assert result.candidates[0]["license"] == "MIT"
    assert result.candidates[0]["download_url"].endswith("app-release.apk")


def test_github_adapter_direct_owner_repo(monkeypatch) -> None:
    def fake_get(url, *args, **kwargs):
        if url == "https://api.github.com/repos/owner/app":
            return FakeResponse(
                {
                    "full_name": "owner/app",
                    "name": "app",
                    "owner": {"login": "owner"},
                    "license": {"spdx_id": "MIT"},
                    "html_url": "https://github.com/owner/app",
                }
            )
        if url == "https://api.github.com/repos/owner/app/releases":
            return FakeResponse([])
        raise AssertionError(url)

    monkeypatch.setattr("apk_docforge.adapters.github_releases.httpx.get", fake_get)
    result = GitHubReleasesAdapter().search("owner/app")
    assert result.policy_decision["allowed"] is True
    assert result.candidates == []
