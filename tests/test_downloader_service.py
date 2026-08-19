from __future__ import annotations

import hashlib
from pathlib import Path

import httpx
import pytest
import respx

from apk_docforge.config import get_settings
from apk_docforge.services.downloader import download_candidate
from apk_docforge.services.source_registry import save_candidates


@respx.mock
def test_download_candidate_quarantine_and_provenance(isolated_app_env: Path, tmp_path: Path) -> None:
    body = b"fake apk bytes"
    digest = hashlib.sha256(body).hexdigest()
    url = "https://example.com/releases/app.apk"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            content=body,
            headers={"Content-Type": "application/vnd.android.package-archive", "ETag": '"abc"'},
        )
    )
    candidate = save_candidates(
        [
            {
                "id": "official:https://example.com/releases/app.apk",
                "source": "official_url",
                "app_name": "Official App",
                "source_url": "https://example.com/releases",
                "download_url": url,
                "checksum": digest,
                "policy_status": "ALLOWED",
            }
        ]
    )[0]

    result = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")
    assert result["status"] == "completed"
    assert result["sha256"] == digest
    assert result["checksum_matches"] is True
    assert Path(result["quarantine_path"]).exists()
    assert Path(result["local_path"]).exists()
    assert Path(result["cache_path"]).exists()
    assert Path(result["local_path"] + ".provenance.json").exists()
    assert result["artifact_id"] > 0

    second = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")
    assert second["status"] == "completed"
    assert second["cache_hit"] is True
    assert second["sha256"] == digest


@respx.mock
def test_download_candidate_blocks_checksum_mismatch(isolated_app_env: Path, tmp_path: Path) -> None:
    url = "https://example.com/releases/app.apk"
    respx.get(url).mock(return_value=httpx.Response(200, content=b"bad bytes"))
    candidate = save_candidates(
        [
            {
                "id": "official:https://example.com/releases/app.apk",
                "source": "official_url",
                "app_name": "Official App",
                "download_url": url,
                "checksum": "0" * 64,
                "policy_status": "ALLOWED",
            }
        ]
    )[0]

    result = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")
    assert result["status"] == "blocked_checksum_mismatch"
    assert result["local_path"] is None


@respx.mock
def test_download_revalidates_redirect_before_request(
    isolated_app_env: Path,
    tmp_path: Path,
) -> None:
    url = "https://example.com/releases/app.apk"
    blocked_url = "https://attacker.example/app.apk"
    respx.get(url).mock(return_value=httpx.Response(302, headers={"Location": blocked_url}))
    blocked_request = respx.get(blocked_url).mock(return_value=httpx.Response(200, content=b"bad"))
    candidate = save_candidates(
        [{"source": "official_url", "app_name": "App", "download_url": url}]
    )[0]

    result = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")

    assert result["status"] == "blocked_policy"
    assert result["final_url"] == blocked_url
    assert result["redirect_chain"][0]["to_url"] == blocked_url
    assert blocked_request.called is False


@respx.mock
def test_download_accepts_allowlisted_redirect_and_records_final_url(
    isolated_app_env: Path,
    tmp_path: Path,
) -> None:
    url = "https://example.com/releases/app.apk"
    final_url = "https://downloads.example.org/assets/app.apk"
    respx.get(url).mock(return_value=httpx.Response(302, headers={"Location": final_url}))
    respx.get(final_url).mock(return_value=httpx.Response(200, content=b"redirected apk"))
    candidate = save_candidates(
        [{"source": "official_url", "app_name": "App", "download_url": url}]
    )[0]

    result = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")

    assert result["status"] == "completed"
    assert result["final_url"] == final_url
    assert result["final_policy_decision"]["allowed"] is True
    assert len(result["redirect_chain"]) == 1


@pytest.mark.parametrize("declared_length", ["9", "invalid"])
@respx.mock
def test_download_rejects_invalid_or_oversized_content_length(
    isolated_app_env: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declared_length: str,
) -> None:
    monkeypatch.setenv("APK_DOCFORGE_MAX_DOWNLOAD_BYTES", "8")
    get_settings.cache_clear()
    url = "https://example.com/releases/app.apk"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Length": declared_length},
            stream=httpx.ByteStream(b"x"),
        )
    )
    candidate = save_candidates(
        [{"source": "official_url", "app_name": "App", "download_url": url}]
    )[0]

    result = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")

    assert result["status"] == "blocked_size_limit"
    assert not list((isolated_app_env / "quarantine").glob("download-*"))


@respx.mock
def test_download_stream_enforces_limit_without_content_length(
    isolated_app_env: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APK_DOCFORGE_MAX_DOWNLOAD_BYTES", "8")
    get_settings.cache_clear()
    url = "https://example.com/releases/app.apk"
    respx.get(url).mock(return_value=httpx.Response(200, stream=httpx.ByteStream(b"123456789")))
    candidate = save_candidates(
        [{"source": "official_url", "app_name": "App", "download_url": url}]
    )[0]

    result = download_candidate(str(candidate["id"]), out=tmp_path / "downloads")

    assert result["status"] == "blocked_size_limit"
    assert not list((isolated_app_env / "quarantine").glob("download-*"))
