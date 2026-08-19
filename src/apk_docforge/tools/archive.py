from __future__ import annotations

import mimetypes
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from apk_docforge.tools.hashing import sha256_file


@dataclass(frozen=True)
class ZipEntry:
    path: str
    size: int
    compressed_size: int
    crc: str
    is_dir: bool


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_to_quarantine(source: Path, quarantine_dir: Path) -> Path:
    ensure_dir(quarantine_dir)
    digest = sha256_file(source)
    target = quarantine_dir / f"{source.stem}-{digest[:12]}{source.suffix}"
    if not target.exists():
        shutil.copy2(source, target)
    return target


def guess_mime_type(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed:
        return guessed
    if zipfile.is_zipfile(path):
        return "application/zip"
    return "application/octet-stream"


def inspect_zip(path: Path) -> list[ZipEntry]:
    if not zipfile.is_zipfile(path):
        return []
    entries: list[ZipEntry] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            entries.append(
                ZipEntry(
                    path=info.filename,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    crc=f"{info.CRC:08x}",
                    is_dir=info.is_dir(),
                )
            )
    return entries


def inspect_zip_limited(
    path: Path,
    *,
    max_members: int,
    max_total_uncompressed_bytes: int,
) -> list[ZipEntry]:
    entries = inspect_zip(path)
    if len(entries) > max_members:
        raise ValueError(f"Archive contains {len(entries)} members; configured limit is {max_members}.")
    total_uncompressed = sum(entry.size for entry in entries if not entry.is_dir)
    if total_uncompressed > max_total_uncompressed_bytes:
        raise ValueError(
            "Archive uncompressed size exceeds the configured limit "
            f"({total_uncompressed} > {max_total_uncompressed_bytes} bytes)."
        )
    return entries


def read_zip_member(path: Path, member: str, limit: int | None = None) -> bytes | None:
    if not zipfile.is_zipfile(path):
        return None
    with zipfile.ZipFile(path) as archive:
        try:
            with archive.open(member) as handle:
                if limit is None:
                    return handle.read()
                return handle.read(limit)
        except KeyError:
            return None


def extract_zip_member_limited(
    path: Path,
    member: str,
    destination: Path,
    *,
    max_bytes: int,
) -> Path:
    ensure_dir(destination.parent)
    with zipfile.ZipFile(path) as archive:
        try:
            info = archive.getinfo(member)
        except KeyError as exc:
            raise ValueError(f"Archive member was not found: {member}") from exc
        if info.is_dir():
            raise ValueError(f"Archive member is a directory: {member}")
        if info.file_size > max_bytes:
            raise ValueError(
                f"Nested artifact exceeds the configured limit ({info.file_size} > {max_bytes} bytes)."
            )
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        try:
            with archive.open(info) as source, temporary.open("xb") as target:
                _copy_stream_limited(source, target, max_bytes)
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    return destination


def safe_extract_zip(
    path: Path,
    destination: Path,
    max_members: int = 10000,
    max_member_bytes: int = 256 * 1024 * 1024,
    max_total_bytes: int = 1024 * 1024 * 1024,
) -> list[Path]:
    ensure_dir(destination)
    extracted: list[Path] = []
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > max_members:
            raise ValueError(f"Archive contains {len(infos)} members; configured limit is {max_members}.")
        total_bytes = sum(info.file_size for info in infos if not info.is_dir())
        if total_bytes > max_total_bytes:
            raise ValueError(
                f"Archive exceeds the configured extraction limit ({total_bytes} > {max_total_bytes} bytes)."
            )
        for info in infos:
            target = (destination / info.filename).resolve()
            try:
                target.relative_to(destination_resolved)
            except ValueError:
                raise ValueError(f"Blocked unsafe archive path: {info.filename}")
            if info.file_size > max_member_bytes:
                raise ValueError(
                    f"Archive member exceeds the configured limit: {info.filename} "
                    f"({info.file_size} > {max_member_bytes} bytes)."
                )

        for info in infos:
            target = (destination / info.filename).resolve()
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("wb") as dst:
                _copy_stream_limited(src, dst, max_member_bytes)
            extracted.append(target)
    return extracted


def _copy_stream_limited(source: BinaryIO, target: BinaryIO, max_bytes: int) -> int:
    written = 0
    while chunk := source.read(64 * 1024):
        written += len(chunk)
        if written > max_bytes:
            raise ValueError(f"Stream exceeds the configured limit of {max_bytes} bytes.")
        target.write(chunk)
    return written


def classify_android_artifact(path: Path, entries: list[ZipEntry] | None = None) -> str:
    if path.is_dir():
        apk_count = len(list(path.glob("*.apk")))
        return "split_apk_directory" if apk_count else "directory"
    if not zipfile.is_zipfile(path):
        return "unknown"
    names = {entry.path for entry in (entries or inspect_zip(path))}
    suffix = path.suffix.lower()
    nested_apks = [name for name in names if name.endswith(".apk")]
    if "AndroidManifest.xml" in names and any(name.startswith("classes") for name in names):
        return "apk"
    if suffix == ".apks" or "toc.pb" in names:
        return "apks"
    if suffix == ".xapk" or ("manifest.json" in names and nested_apks):
        return "xapk"
    if nested_apks:
        return "apk_container"
    return "zip"
