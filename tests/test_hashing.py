from __future__ import annotations

import hashlib
import zipfile

import pytest

from apk_docforge.tools.archive import (
    extract_zip_member_limited,
    inspect_zip_limited,
    read_zip_member,
    safe_extract_zip,
)
from apk_docforge.tools.hashing import checksum_matches, file_size, sha256_file


def test_sha256_file(tmp_path) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"apk-docforge")
    assert sha256_file(path) == hashlib.sha256(b"apk-docforge").hexdigest()
    assert file_size(path) == len(b"apk-docforge")
    assert checksum_matches(path, f"sha256:{sha256_file(path)}") is True
    assert checksum_matches(path, "deadbeef") is False
    assert checksum_matches(path, None) is None


def test_read_zip_member_without_limit(tmp_path) -> None:
    archive_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest-bytes")
    assert read_zip_member(archive_path, "AndroidManifest.xml") == b"manifest-bytes"
    assert read_zip_member(archive_path, "AndroidManifest.xml", limit=8) == b"manifest"


def test_safe_extract_zip_blocks_sibling_prefix_traversal(tmp_path) -> None:
    archive_path = tmp_path / "unsafe.zip"
    destination = tmp_path / "extract"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(f"../{destination.name}_evil/file.txt", "blocked")

    with pytest.raises(ValueError, match="Blocked unsafe archive path"):
        safe_extract_zip(archive_path, destination)

    assert not (tmp_path / "extract_evil" / "file.txt").exists()


def test_archive_limits_reject_members_before_extraction(tmp_path) -> None:
    archive_path = tmp_path / "nested.xapk"
    destination = tmp_path / "nested.apk"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("base.apk", b"123456789")
        archive.writestr("extra.txt", b"x")

    with pytest.raises(ValueError, match="Nested artifact exceeds"):
        extract_zip_member_limited(archive_path, "base.apk", destination, max_bytes=8)
    assert not destination.exists()

    with pytest.raises(ValueError, match="contains 2 members"):
        inspect_zip_limited(archive_path, max_members=1, max_total_uncompressed_bytes=100)
    with pytest.raises(ValueError, match="uncompressed size"):
        inspect_zip_limited(archive_path, max_members=2, max_total_uncompressed_bytes=9)
