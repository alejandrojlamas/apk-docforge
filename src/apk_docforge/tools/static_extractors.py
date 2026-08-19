from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
URL_RE = re.compile(
    r"\b(?:https?://|wss?://)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|co|ai|me|mx|edu|gov|info|biz)\b",
    re.IGNORECASE,
)
HTTP_METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD)\b")
IGNORED_URL_PREFIXES = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://www.w3.org/",
    "https://www.w3.org/",
)
IGNORED_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
}
IGNORED_SIGNAL_PATH_PARTS = {
    "bouncycastle",
    "certpathreviewermessages.properties",
    "license.txt",
    "most_downloaded_apps.json",
    "notice.txt",
    "publicsuffixdatabase.list",
    "public_suffix_list",
    "publicsuffixes",
    "swap-icon.svg",
}

TEXT_SUFFIXES = {
    ".xml",
    ".json",
    ".txt",
    ".js",
    ".html",
    ".htm",
    ".properties",
    ".graphql",
    ".gql",
    ".conf",
    ".cfg",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class ExtractedString:
    value: str
    path: str
    line_number: int | None = None
    source: str = "archive"


def printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    values: list[str] = []
    for match in PRINTABLE_RE.finditer(data):
        value = match.group().decode("utf-8", errors="ignore").strip()
        if len(value) >= min_length:
            values.append(value)
    return values


def iter_archive_text(apk_path: Path, max_member_size: int = 2_000_000) -> Iterator[ExtractedString]:
    if not zipfile.is_zipfile(apk_path):
        return
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > max_member_size:
                continue
            suffix = Path(info.filename).suffix.lower()
            try:
                raw = archive.read(info)
            except RuntimeError:
                continue
            if suffix in TEXT_SUFFIXES:
                text = raw.decode("utf-8", errors="replace")
                for number, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped:
                        yield ExtractedString(stripped, info.filename, number)
            elif suffix in {".dex", ".so", ".arsc", ".bundle"} or info.filename.startswith("assets/"):
                for value in printable_strings(raw):
                    yield ExtractedString(value, info.filename)


def iter_files_text(root: Path, max_file_size: int = 2_000_000) -> Iterator[ExtractedString]:
    if not root.exists():
        return
    for file_path in root.rglob("*"):
        if not file_path.is_file() or file_path.stat().st_size > max_file_size:
            continue
        suffix = file_path.suffix.lower()
        if suffix not in TEXT_SUFFIXES and suffix not in {".java", ".kt", ".smali"}:
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped:
                yield ExtractedString(stripped, str(file_path), number, source="file")


def find_urls(strings: list[ExtractedString]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, int | None]] = set()
    results: list[dict[str, object]] = []
    for item in strings:
        if ignored_signal_source(item.path):
            continue
        for match in URL_RE.finditer(item.value):
            url = match.group(0).rstrip('".,);]')
            if _ignored_url(url):
                continue
            key = (url, item.path, item.line_number)
            if key in seen:
                continue
            seen.add(key)
            method = _nearby_http_method(item.value, match.start())
            results.append(
                {
                    "url": url,
                    "method_hint": method,
                    "source": item.source,
                    "evidence_refs": [
                        {
                            "path": item.path,
                            "line_number": item.line_number,
                            "kind": "string",
                            "description": "URL string extracted from static artifact.",
                        }
                    ],
                    "confidence": 0.9 if url.startswith(("http://", "https://")) else 0.75,
                    "status": "observed",
                }
            )
    return results


def find_domains(strings: list[ExtractedString]) -> list[dict[str, object]]:
    seen: set[str] = set()
    results: list[dict[str, object]] = []
    for item in strings:
        if ignored_signal_source(item.path):
            continue
        for match in DOMAIN_RE.finditer(item.value):
            domain = match.group(0).lower()
            if domain in IGNORED_DOMAINS:
                continue
            if domain in seen:
                continue
            seen.add(domain)
            results.append(
                {
                    "domain": domain,
                    "source": item.source,
                    "evidence_refs": [
                        {
                            "path": item.path,
                            "line_number": item.line_number,
                            "kind": "string",
                            "description": "Domain-like string extracted from static artifact.",
                        }
                    ],
                    "confidence": 0.65,
                    "status": "observed",
                }
            )
    return results


def _nearby_http_method(text: str, index: int) -> str | None:
    window = text[max(index - 80, 0) : index + 80]
    match = HTTP_METHOD_RE.search(window)
    return match.group(1) if match else None


def _ignored_url(url: str) -> bool:
    lowered = url.lower()
    return any(lowered.startswith(prefix) for prefix in IGNORED_URL_PREFIXES)


def ignored_signal_source(path: str) -> bool:
    lowered = path.lower()
    return any(part in lowered for part in IGNORED_SIGNAL_PATH_PARTS)
