from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "sources.json"
SOURCES_TXT = ROOT / "sources.txt"
OUTPUT_PATH = ROOT / "configs.txt"

# Deliberately match complete proxy URI tokens, while stopping before HTML/YAML punctuation.
PROXY_RE = re.compile(
    r"(?i)(?:vless|vmess|trojan|ss|ssr|socks|socks5|socks5h|socks4|http|https|hysteria2|hy2|tuic|wireguard|wg)://[^\s\"'<>]+"
)
DEFAULT_UA = "Mozilla/5.0 (compatible; LIKVID-Web-Parser/1.0; +https://github.com/cheesyx-rudy/web-parser)"
MAX_BODY_BYTES = 8 * 1024 * 1024


@dataclass
class Source:
    name: str
    url: str
    mode: str = "direct"
    user_agent: str | None = None
    os_name: str = "android"
    hwid: str | None = None
    headers: dict[str, str] | None = None
    timeout_seconds: int = 30
    retries: int = 2
    proxy_base: str = "https://p.kfwl.lol"


def safe_host(url: str) -> str:
    """Return a host label for logs without exposing query tokens or credentials."""
    try:
        return urlparse(url).hostname or "unknown-host"
    except Exception:
        return "unknown-host"


def read_source_urls() -> list[str]:
    """Read the source-of-truth list from sources.txt, preserving order and removing duplicates."""
    if not SOURCES_TXT.exists():
        raise FileNotFoundError(
            "sources.txt is missing. It is the source of truth; restore it before running the parser."
        )

    urls: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(SOURCES_TXT.read_text(encoding="utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            print(f"[WARN] sources.txt:{line_number}: not a valid HTTP(S) URL; skipped")
            continue
        if value not in seen:
            seen.add(value)
            urls.append(value)
        else:
            print(f"[WARN] sources.txt:{line_number}: duplicate URL; skipped")
    return urls


def sync_json_sources(urls: list[str], defaults: dict[str, Any]) -> list[dict[str, Any]]:
    """Synchronize sources.json entries from sources.txt, preserving options for URLs that remain."""
    data: dict[str, Any] = {"defaults": defaults, "sources": []}
    if CONFIG_PATH.exists():
        try:
            loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read {CONFIG_PATH.name}: {exc}") from exc

    existing: dict[str, dict[str, Any]] = {}
    for item in data.get("sources", []):
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            existing[item["url"].strip()] = item

    synced: list[dict[str, Any]] = []
    for index, url in enumerate(urls, 1):
        item = existing.get(url)
        if item is None:
            host = urlparse(url).hostname or f"source-{index}"
            item = {
                "name": host,
                "url": url,
                "mode": "direct",
                "user_agent": str(defaults.get("user_agent", DEFAULT_UA)),
                "headers": {},
                "timeout_seconds": int(defaults.get("timeout_seconds", 30)),
                "retries": int(defaults.get("retries", 2)),
            }
            print(f"[INFO] Added new source to sources.json: {host}")
        synced.append(item)

    # Sources not present in sources.txt are intentionally removed from the JSON list.
    if data.get("sources", []) != synced:
        data["sources"] = synced
        CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[INFO] Synced sources.json with sources.txt ({len(synced)} sources)")

    return synced


def load_sources() -> tuple[list[Source], dict[str, Any]]:
    defaults: dict[str, Any] = {
        "timeout_seconds": 30,
        "retries": 2,
        "user_agent": "Happ/3.0.0",
        "max_body_bytes": MAX_BODY_BYTES,
        "decode_base64": True,
    }

    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("defaults"), dict):
                defaults.update(data["defaults"])
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read {CONFIG_PATH.name}: {exc}") from exc

    urls = read_source_urls()
    json_sources = sync_json_sources(urls, defaults)
    sources: list[Source] = []

    for index, raw in enumerate(json_sources, 1):
        url = str(raw.get("url", "")).strip()
        if not url:
            continue
        mode = str(raw.get("mode", "direct")).strip().lower()
        if mode not in {"direct", "p_kfwl"}:
            print(f"[WARN] {raw.get('name', f'source-{index}')}: unsupported mode {mode!r}; skipped")
            continue
        sources.append(Source(
            name=str(raw.get("name") or f"source-{index}").strip(),
            url=url,
            mode=mode,
            user_agent=raw.get("user_agent"),
            os_name=str(raw.get("os", "android")),
            hwid=raw.get("hwid"),
            headers=raw.get("headers") if isinstance(raw.get("headers"), dict) else {},
            timeout_seconds=int(raw.get("timeout_seconds", defaults["timeout_seconds"])),
            retries=int(raw.get("retries", defaults["retries"])),
            proxy_base=str(raw.get("proxy_base", "https://p.kfwl.lol")).rstrip("/"),
        ))

    return sources, defaults


def make_request_url(source: Source) -> str:
    """Build p.kfwl.lol's documented path-style decoder URL, or use the source as-is."""
    if source.mode == "direct":
        return source.url

    # Path-style form: /ua=<ua>/os=<os>/h=<hwid>/url/<source-url>
    ua = source.user_agent or "happ"
    chunks = [f"ua={quote(ua, safe='')}" , f"os={quote(source.os_name, safe='')}" ]
    if source.hwid:
        chunks.append(f"h={quote(source.hwid, safe='')}")
    # Keep URL separators for the proxy's path-based target URL syntax.
    target = quote(source.url, safe=":/?=&%+@,;~!$'()*-._")
    return f"{source.proxy_base}/{'/'.join(chunks)}/url/{target}"


def _maybe_decode_base64(text: str) -> str | None:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 32 or not re.fullmatch(r"[A-Za-z0-9_+/-]*={0,2}", compact):
        return None
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = raw.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if not decoded or sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded) / len(decoded) < 0.85:
        return None
    return decoded


def candidate_texts(body: str, decode_base64: bool = True) -> list[str]:
    """Return original text and any plausible nested base64-decoded text variants."""
    texts = [html.unescape(body)]
    if not decode_base64:
        return texts

    seen = {texts[0]}
    # A normal subscription may be base64 once; some portals nest it more than once.
    for _ in range(3):
        added = []
        for text in list(texts):
            direct = _maybe_decode_base64(text.strip())
            if direct and direct not in seen:
                seen.add(direct)
                added.append(direct)
            # HTML/API may embed a base64 blob in a JSON string or tag.
            for token in re.findall(r"(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{80,}={0,2}(?![A-Za-z0-9_+/-])", text):
                decoded = _maybe_decode_base64(token)
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    added.append(decoded)
        if not added:
            break
        texts.extend(added)
    return texts


def normalize_uri(uri: str) -> str:
    # Remove common trailing separators/punctuation from HTML/JSON/YAML matches.
    return uri.rstrip("),.;]}:")


def extract_configs(body: str, decode_base64: bool = True) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in candidate_texts(body, decode_base64=decode_base64):
        for match in PROXY_RE.findall(text):
            config = normalize_uri(match.strip())
            if config and config not in seen:
                seen.add(config)
                found.append(config)
    return found


def fetch_source(source: Source, defaults: dict[str, Any]) -> list[str]:
    request_url = make_request_url(source)
    parsed = urlparse(request_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use http or https")

    headers = {"User-Agent": source.user_agent or str(defaults.get("user_agent", DEFAULT_UA)), "Accept": "text/plain, text/html, application/json, */*"}
    headers.update(source.headers or {})
    last_error: Exception | None = None

    for attempt in range(source.retries + 1):
        try:
            with requests.get(request_url, headers=headers, timeout=source.timeout_seconds, allow_redirects=True, stream=True) as response:
                response.raise_for_status()
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > int(defaults.get("max_body_bytes", MAX_BODY_BYTES)):
                        raise ValueError(f"response exceeds {defaults.get('max_body_bytes', MAX_BODY_BYTES)} bytes")
                    chunks.append(chunk)
                encoding = response.encoding or "utf-8"
                body = b"".join(chunks).decode(encoding, errors="replace")
                content_type = response.headers.get("Content-Type", "unknown").split(";")[0]
                configs = extract_configs(body, decode_base64=bool(defaults.get("decode_base64", True)))
                print(f"[INFO] {source.name} ({safe_host(source.url)}): HTTP {response.status_code}, {content_type}, {len(configs)} configs")
                if not configs and ("<html" in body[:2000].lower() or "<!doctype html" in body[:2000].lower()):
                    print(f"[WARN] {source.name}: got HTML but no proxy links. The page may be only a frontend; configure its actual subscription/API endpoint.")
                elif not configs:
                    print(f"[WARN] {source.name}: no supported proxy URIs found in response")
                return configs
        except Exception as exc:
            last_error = exc
            print(f"[WARN] {source.name} ({safe_host(source.url)}): attempt {attempt + 1}/{source.retries + 1} failed: {type(exc).__name__}: {exc}")
            if attempt < source.retries:
                time.sleep(min(2 ** attempt, 5))

    if last_error:
        raise last_error
    return []


def main() -> int:
    print("[START] Web subscription parser")
    sources, defaults = load_sources()
    if not sources:
        print("[WARN] No sources configured. Add URLs to sources.json or sources.txt.")
        OUTPUT_PATH.write_text("", encoding="utf-8")
        return 0

    print(f"[INFO] Sources: {len(sources)}")
    all_configs: list[str] = []
    seen: set[str] = set()
    failures = 0

    for source in sources:
        try:
            configs = fetch_source(source, defaults)
            for config in configs:
                if config not in seen:
                    seen.add(config)
                    all_configs.append(config)
        except Exception:
            failures += 1
            # Keep going; one broken source must not block the others.
            continue

    # Never replace a known-good output with an empty file because all sources failed.
    if not all_configs and OUTPUT_PATH.exists() and OUTPUT_PATH.stat().st_size > 0:
        print("[ERROR] All sources returned zero configs; keeping previous configs.txt unchanged.")
        return 1

    output = "\n".join(all_configs)
    OUTPUT_PATH.write_text((output + "\n") if output else "", encoding="utf-8")
    print(f"[DONE] Unique configs: {len(all_configs)}; source failures: {failures}; output: configs.txt")
    if failures == len(sources):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
