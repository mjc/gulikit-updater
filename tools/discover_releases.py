#!/usr/bin/env python3
"""Collect bounded, non-authoritative observations from reviewed GuliKit sources."""

from __future__ import annotations

import argparse
import contextvars
import hashlib
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urljoin, urlsplit

SCHEMA = 1
MAX_INPUT_BYTES = 256 * 1024
MAX_BASELINE_BYTES = 16 * 1024 * 1024
MAX_JSON_NESTING = 16
MAX_JSON_CONTAINERS = 4_096
MAX_JSON_STRUCTURAL_TOKENS = 100_000
MAX_PAGES = 32
MAX_ARCHIVES = 32
MAX_PAGE_BYTES = 256 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SCRIPTS_PER_PAGE = 2
HTTP_TIMEOUT_SECONDS = 15
SCAN_BUDGET_SECONDS = 180
ALLOWED_ASSET_HOSTS = {"gulikit.com", "www.gulikit.com", "img.website.xin"}
ALLOWED_CACHE_QUERY_KEYS = {"v", "ver", "version"}
_ACTIVE_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "release_discovery_deadline", default=None
)


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _guard_json_resources(data: bytes, label: str) -> None:
    """Bound JSON parser complexity before constructing Python objects."""
    stack: list[int] = []
    in_string = False
    escaped = False
    containers = 0
    structural_tokens = 0
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in b"{}[],:":
            structural_tokens += 1
            if structural_tokens > MAX_JSON_STRUCTURAL_TOKENS:
                raise ValueError(f"{label} has too many JSON structure tokens")
            if byte in (ord("{"), ord("[")):
                containers += 1
                stack.append(ord("}") if byte == ord("{") else ord("]"))
                if containers > MAX_JSON_CONTAINERS:
                    raise ValueError(f"{label} has too many JSON containers")
                if len(stack) > MAX_JSON_NESTING:
                    raise ValueError(f"{label} JSON nesting exceeds the allowed depth")
            elif byte in (ord("}"), ord("]")):
                if not stack or stack.pop() != byte:
                    raise ValueError(f"{label} has mismatched JSON containers")


def _json_bytes(data: bytes, label: str, limit: int = MAX_INPUT_BYTES) -> object:
    if not isinstance(data, bytes) or len(data) > limit:
        raise ValueError(f"{label} must be at most {limit} bytes")
    _guard_json_resources(data, label)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid {label} JSON: {exc}") from exc


def _validate_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value
    ):
        raise ValueError(f"invalid {label} identity")
    return value


def _validate_https_url(value: object, label: str, *, asset: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError(f"invalid {label} URL")
    parsed = urlsplit(value)
    hosts = ALLOWED_ASSET_HOSTS if asset else {"gulikit.com", "www.gulikit.com"}
    if (
        parsed.scheme != "https"
        or parsed.hostname not in hosts
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "#" in value
        or not parsed.path.startswith("/")
    ):
        raise ValueError(f"{label} URL must use an approved HTTPS host")
    if parsed.query:
        if not asset:
            raise ValueError(f"{label} URL must not contain a query")
        parts = parsed.query.split("&")
        if not parts or any("=" not in part for part in parts):
            raise ValueError(f"{label} URL has an invalid cache version query")
        seen: set[str] = set()
        for part in parts:
            key, value_part = part.split("=", 1)
            if (
                key.lower() not in ALLOWED_CACHE_QUERY_KEYS
                or key.lower() in seen
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", value_part)
            ):
                raise ValueError(f"{label} URL has an unapproved query")
            seen.add(key.lower())
    elif not asset and "?" in value:
        raise ValueError(f"{label} URL must not contain a query")
    return value


def _validate_watchlist(
    data: bytes,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    obj = _json_bytes(data, "watchlist")
    if (
        not isinstance(obj, dict)
        or set(obj) - {"schema_version", "pages", "archives"}
        or type(obj.get("schema_version")) is not int
        or obj.get("schema_version") != SCHEMA
    ):
        raise ValueError(
            "watchlist must use schema_version 1 with pages and optional archives"
        )
    pages = obj.get("pages")
    archives = obj.get("archives", [])
    if (
        not isinstance(pages, list)
        or not isinstance(archives, list)
        or (not pages and not archives)
        or len(pages) > MAX_PAGES
        or len(archives) > MAX_ARCHIVES
    ):
        raise ValueError("watchlist page/archive counts are outside allowed bounds")
    result_pages: list[dict[str, object]] = []
    result_archives: list[dict[str, object]] = []
    identities: set[str] = set()
    for item in pages:
        if not isinstance(item, dict) or set(item) != {"id", "url"}:
            raise ValueError("each page requires exactly id and url")
        identity = _validate_id(item["id"], "page")
        if identity in identities:
            raise ValueError(f"duplicate watchlist identity: {identity}")
        identities.add(identity)
        result_pages.append(
            {"id": identity, "url": _validate_https_url(item["url"], "page")}
        )
    for item in archives:
        if not isinstance(item, dict) or set(item) != {"id", "url", "size", "sha256"}:
            raise ValueError("each archive requires exactly id, url, size, and sha256")
        identity = _validate_id(item["id"], "archive")
        if identity in identities:
            raise ValueError(f"duplicate watchlist identity: {identity}")
        identities.add(identity)
        url = _validate_https_url(item["url"], "archive")
        if not urlsplit(url).path.lower().endswith(".zip"):
            raise ValueError("archive URL must be a stable official HTTPS .zip URL")
        size = item["size"]
        digest = item["sha256"]
        if type(size) is not int or not 1 <= size <= MAX_ARCHIVE_BYTES:
            raise ValueError("archive size is outside the allowed bound")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("archive sha256 must be 64 hexadecimal characters")
        result_archives.append(
            {"id": identity, "url": url, "size": size, "sha256": digest.lower()}
        )
    return result_pages, result_archives


def _timestamp(value: str | None) -> str:
    if value is None:
        return (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    if (
        not isinstance(value, str)
        or len(value) > 64
        or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", value)
    ):
        raise ValueError("observed_at must be an ISO UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("observed_at is not a valid UTC timestamp") from exc
    return value


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_https(url: str, limit: int) -> bytes:
    """Fetch one HTTPS response without redirects or transparent decompression."""
    request = Request(
        url,
        headers={
            "User-Agent": "GuliKitReleaseDiscovery/1",
            "Accept-Encoding": "identity",
        },
    )
    opener = build_opener(_NoRedirect)
    active_deadline = _ACTIVE_DEADLINE.get()
    remaining = None if active_deadline is None else active_deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
        raise ValueError("overall discovery time budget exceeded")
    timeout = (
        HTTP_TIMEOUT_SECONDS
        if remaining is None
        else min(HTTP_TIMEOUT_SECONDS, remaining)
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError(f"unexpected HTTP status {response.status}")
            if response.headers.get("Content-Encoding", "identity").lower() not in {
                "",
                "identity",
            }:
                raise ValueError("compressed HTTP response is not accepted")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > limit):
                raise ValueError("HTTP response exceeds byte limit")
            chunks = bytearray()
            while len(chunks) <= limit:
                active_deadline = _ACTIVE_DEADLINE.get()
                if active_deadline is not None and time.monotonic() > active_deadline:
                    raise ValueError("overall discovery time budget exceeded")
                block = response.read1(min(64 * 1024, limit + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if len(chunks) > limit:
                raise ValueError("HTTP response exceeds byte limit")
            if length is not None and len(chunks) != int(length):
                raise ValueError("HTTP response is truncated")
            return bytes(chunks)
    except HTTPError as exc:
        raise ValueError(f"HTTP status {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError(f"HTTPS fetch failed: {exc}") from exc


class _FingerprintParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.events: list[tuple[object, ...]] = []
        self.title_parts: list[str] = []
        self.in_title = False
        self.links: set[str] = set()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        norm_attrs = []
        raw_attrs = [
            (key.lower(), "" if value is None else html.unescape(value).strip())
            for key, value in attrs
        ]
        csrf_input = tag == "input" and any(
            key == "name" and value.lower() == "__requestverificationtoken"
            for key, value in raw_attrs
        )
        for key, val in raw_attrs:
            if key == "nonce":
                continue
            if csrf_input and key == "value":
                continue
            norm_attrs.append((key, re.sub(r"\s+", " ", val)))
            if tag == "a" and key == "href" and val:
                self.links.add(val)
            if tag == "script" and key == "src" and val:
                self.scripts.append(val)
        norm_attrs.sort()
        self.events.append(("start", tag, tuple(norm_attrs)))
        if tag == "title":
            self.in_title = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        self.events.append(("end", tag))
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        normalized = re.sub(r"\s+", " ", data).strip()
        if normalized:
            self.events.append(("text", normalized))
        if self.in_title and normalized:
            self.title_parts.append(normalized)

    def handle_comment(self, data: str) -> None:
        return


def _page_observation(
    page: dict[str, object],
    body: bytes,
    fetcher: Callable[[str, int], bytes],
    deadline: float,
) -> dict[str, object]:
    try:
        if time.monotonic() > deadline:
            raise ValueError("overall discovery time budget exceeded")
        text = body.decode("utf-8-sig", errors="strict")
        parser = _FingerprintParser()
        parser.feed(text)
        parser.close()
        if len(parser.scripts) > MAX_SCRIPTS_PER_PAGE:
            raise ValueError("page references more than two scripts")
        canonical = json.dumps(
            parser.events, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        assets = []
        page_url = str(page["url"])
        page_host = urlsplit(page_url).hostname
        for source in sorted(set(parser.scripts)):
            if time.monotonic() > deadline:
                raise ValueError("overall discovery time budget exceeded")
            asset_url = _validate_https_url(
                urljoin(page_url, source), "script asset", asset=True
            )
            asset_host = urlsplit(asset_url).hostname
            if asset_host not in ALLOWED_ASSET_HOSTS or (
                asset_host in {"gulikit.com", "www.gulikit.com"}
                and asset_host != page_host
            ):
                raise ValueError("script asset host is not allowed for this page")
            asset_data = fetcher(asset_url, MAX_ASSET_BYTES)
            if not isinstance(asset_data, bytes) or len(asset_data) > MAX_ASSET_BYTES:
                raise ValueError("script asset exceeds byte limit")
            assets.append(
                {"url": asset_url, "sha256": hashlib.sha256(asset_data).hexdigest()}
            )
        return {
            "kind": "page",
            "id": page["id"],
            "url": page_url,
            "status": "observed",
            "title": re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip(),
            "page_sha256": hashlib.sha256(canonical).hexdigest(),
            "assets": assets,
            "links": sorted(parser.links),
        }
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"page parse/asset observation failed: {exc}") from exc


def _validate_baseline(value: object) -> dict[str, dict[str, object]]:
    allowed_fields = {
        "schema_version",
        "kind",
        "observed_at",
        "status",
        "authorizes_firmware",
        "observations",
        "candidates",
        "errors",
    }
    if (
        not isinstance(value, dict)
        or set(value) - allowed_fields
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA
        or value.get("kind") != "release_discovery"
        or not isinstance(value.get("status"), str)
        or value.get("status") not in {"complete", "incomplete"}
        or not isinstance(value.get("observations"), list)
        or len(value["observations"]) > MAX_PAGES + MAX_ARCHIVES
    ):
        raise ValueError("baseline must be a schema_version 1 release_discovery report")
    indexed: dict[str, dict[str, object]] = {}
    for observation in value["observations"]:
        if not isinstance(observation, dict):
            raise ValueError("baseline contains a malformed observation")
        kind = observation.get("kind")
        status = observation.get("status")
        if (
            not isinstance(kind, str)
            or kind not in {"page", "archive"}
            or not isinstance(status, str)
            or status not in {"observed", "unobserved"}
        ):
            raise ValueError("baseline contains an invalid observation kind or status")
        identity = _validate_id(observation.get("id"), "baseline observation")
        if identity in indexed:
            raise ValueError("baseline has invalid or duplicate observation identities")
        url = _validate_https_url(observation.get("url"), "baseline observation")
        if kind == "archive" and not urlsplit(url).path.lower().endswith(".zip"):
            raise ValueError("baseline archive URL is not a stable .zip URL")
        if status == "observed":
            if kind == "page":
                if (
                    not isinstance(observation.get("title"), str)
                    or not isinstance(observation.get("page_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", observation["page_sha256"])
                ):
                    raise ValueError(
                        "baseline page observation lacks a valid title or digest"
                    )
                assets = observation.get("assets")
                if not isinstance(assets, list) or len(assets) > MAX_SCRIPTS_PER_PAGE:
                    raise ValueError("baseline page observation lacks an asset list")
                for asset in assets:
                    if not isinstance(asset, dict) or set(asset) != {"url", "sha256"}:
                        raise ValueError(
                            "baseline contains a malformed asset observation"
                        )
                    _validate_https_url(asset["url"], "baseline asset", asset=True)
                    if not isinstance(asset["sha256"], str) or not re.fullmatch(
                        r"[0-9a-f]{64}", asset["sha256"]
                    ):
                        raise ValueError("baseline contains an invalid asset digest")
            else:
                if (
                    type(observation.get("size")) is not int
                    or not 0 <= observation["size"] <= MAX_ARCHIVE_BYTES
                    or not isinstance(observation.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", observation["sha256"])
                    or type(observation.get("matches_watchlist")) is not bool
                ):
                    raise ValueError(
                        "baseline archive observation lacks a valid size or digest"
                    )
        indexed[identity] = observation
    return indexed


def discover(
    watchlist: bytes,
    baseline: bytes | None,
    fetcher: Callable[[str, int], bytes] = fetch_https,
    observed_at: str | None = None,
) -> dict[str, object]:
    """Collect observations and comparison signals; this never authorizes firmware."""
    pages, archives = _validate_watchlist(watchlist)
    timestamp = _timestamp(observed_at)
    previous = (
        _validate_baseline(_json_bytes(baseline, "baseline", MAX_BASELINE_BYTES))
        if baseline is not None
        else {}
    )
    if not callable(fetcher):
        raise ValueError("fetcher must be callable")
    deadline = time.monotonic() + SCAN_BUDGET_SECONDS
    deadline_token = _ACTIVE_DEADLINE.set(deadline)
    observations: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    try:
        for page in pages:
            identity, url = str(page["id"]), str(page["url"])
            try:
                if time.monotonic() > deadline:
                    raise ValueError("overall discovery time budget exceeded")
                body = fetcher(url, MAX_PAGE_BYTES)
                if not isinstance(body, bytes) or len(body) > MAX_PAGE_BYTES:
                    raise ValueError("page response exceeds byte limit")
                observation = _page_observation(page, body, fetcher, deadline)
                if time.monotonic() > deadline:
                    raise ValueError("overall discovery time budget exceeded")
            except Exception as exc:
                observation = {
                    "kind": "page",
                    "id": identity,
                    "url": url,
                    "status": "unobserved",
                }
                errors.append({"id": identity, "url": url, "error": str(exc)[:512]})
            observations.append(observation)
        for archive in archives:
            identity, url = str(archive["id"]), str(archive["url"])
            try:
                if time.monotonic() > deadline:
                    raise ValueError("overall discovery time budget exceeded")
                body = fetcher(url, MAX_ARCHIVE_BYTES)
                if not isinstance(body, bytes) or len(body) > MAX_ARCHIVE_BYTES:
                    raise ValueError("archive response exceeds byte limit")
                if time.monotonic() > deadline:
                    raise ValueError("overall discovery time budget exceeded")
                digest = hashlib.sha256(body).hexdigest()
                matches_watchlist = (
                    len(body) == archive["size"] and digest == archive["sha256"]
                )
                observation = {
                    "kind": "archive",
                    "id": identity,
                    "url": url,
                    "status": "observed",
                    "size": len(body),
                    "sha256": digest,
                    "matches_watchlist": matches_watchlist,
                }
            except Exception as exc:
                observation = {
                    "kind": "archive",
                    "id": identity,
                    "url": url,
                    "status": "unobserved",
                }
                errors.append({"id": identity, "url": url, "error": str(exc)[:512]})
            observations.append(observation)
    finally:
        _ACTIVE_DEADLINE.reset(deadline_token)
    observations.sort(key=lambda item: (str(item["kind"]), str(item["id"])))
    errors.sort(key=lambda item: (item["id"], item["url"], item["error"]))
    candidates: list[dict[str, object]] = []
    for observation in observations:
        if observation.get("status") != "observed":
            continue
        identity = str(observation["id"])
        old = previous.get(identity)
        reasons: set[str] = set()
        if old is None or old.get("status") != "observed":
            reasons.add("new_source")
        elif old.get("status") == "observed":
            if old.get("url") != observation.get("url"):
                reasons.add("source_url_changed")
            if observation["kind"] == "page":
                if old.get("title") != observation.get("title"):
                    reasons.add("title_changed")
                if old.get("page_sha256") != observation.get("page_sha256"):
                    reasons.add("page_changed")
                old_assets = (
                    {
                        x.get("url"): x.get("sha256")
                        for x in old.get("assets", [])
                        if isinstance(x, dict)
                    }
                    if isinstance(old.get("assets", []), list)
                    else {}
                )
                new_assets = {
                    x.get("url"): x.get("sha256")
                    for x in observation.get("assets", [])
                    if isinstance(x, dict)
                }
                if old_assets != new_assets:
                    reasons.add("asset_changed")
            elif old.get("sha256") != observation.get("sha256") or old.get(
                "size"
            ) != observation.get("size"):
                reasons.add("archive_changed")
        if (
            observation.get("kind") == "archive"
            and observation.get("matches_watchlist") is False
        ):
            reasons.add("archive_changed")
        if reasons:
            candidates.append(
                {"id": identity, "url": observation["url"], "reasons": sorted(reasons)}
            )
    candidates.sort(key=lambda item: (str(item["id"]), str(item["url"])))
    report = {
        "schema_version": SCHEMA,
        "kind": "release_discovery",
        "observed_at": timestamp,
        "status": "incomplete" if errors else "complete",
        "authorizes_firmware": False,
        "observations": observations,
        "candidates": candidates,
        "errors": errors,
    }
    return report


def _write_new(path: Path, report: dict[str, object]) -> None:
    path = path.absolute()
    payload = (
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_BASELINE_BYTES:
        raise ValueError(
            f"discovery report exceeds {MAX_BASELINE_BYTES} bytes; split the watchlist"
        )
    _guard_json_resources(payload, "discovery report")
    path.parent.mkdir(parents=False, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _read_bounded_file(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{path} must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(limit + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(data) > limit:
        raise ValueError(f"{path} exceeds the {limit}-byte input limit")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watchlist", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        watchlist = _read_bounded_file(args.watchlist, MAX_INPUT_BYTES)
        baseline = (
            _read_bounded_file(args.baseline, MAX_BASELINE_BYTES)
            if args.baseline
            else None
        )
        report = discover(watchlist, baseline)
        _write_new(args.output, report)
    except ValueError as exc:
        print(f"invalid input: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": report["status"],
                "candidates": len(report["candidates"]),
                "errors": len(report["errors"]),
                "authorizes_firmware": False,
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
