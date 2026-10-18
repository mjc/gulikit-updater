import hashlib
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from urllib.error import HTTPError
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools import discover_releases


PAGE_URL = "https://www.gulikit.com/newsinfo/887152.html"
HEAD_ASSET = (
    "https://img.website.xin/pubsf/18023/18023503/cdn-static-pages/"
    "newsinfo/pc/887152_en-us.nocookie.html.Head.js?version=20261012181500"
)
BODY_ASSET = (
    "https://img.website.xin/pubsf/18023/18023503/cdn-static-pages/"
    "newsinfo/pc/887152_en-us.nocookie.html.Body.js?version=20261012181500"
)
ARCHIVE_URL = "https://www.gulikit.com/download/firmware-6.1.zip"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def watchlist(pages=None, archives=None):
    return json.dumps(
        {
            "schema_version": 1,
            "pages": pages
            if pages is not None
            else [{"id": "main-release", "url": PAGE_URL}],
            "archives": archives if archives is not None else [],
        },
        sort_keys=True,
    ).encode()


def page_html(*, title="KK3 Max firmware", links=(), nonce="nonce-a", token="csrf-a"):
    anchors = "".join(f'<a href="{href}">firmware download</a>' for href in links)
    return (
        "<!doctype html><html><head>"
        f"<title>{title}</title>"
        f'<script nonce="{nonce}" src="{HEAD_ASSET}"></script>'
        f'<script nonce="{nonce}" src="{BODY_ASSET}"></script>'
        "</head><body>"
        f"<!-- volatile comment {token} -->"
        f'<input type="hidden" name="__RequestVerificationToken" value="{token}">'
        f"{anchors}</body></html>"
    ).encode()


def fetch_map(responses, calls=None):
    calls = calls if calls is not None else []

    def fetch(url, limit):
        calls.append((url, limit))
        if url not in responses:
            raise OSError(f"No fixture registered for {url}")
        response = responses[url]
        if isinstance(response, Exception):
            raise response
        return response

    return fetch, calls


def report_bytes(report):
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode()


def reasons_for(report, identity):
    matches = [item for item in report["candidates"] if item["id"] == identity]
    if len(matches) != 1:
        raise AssertionError(f"expected one candidate for {identity}, got {matches!r}")
    return set(matches[0]["reasons"])


class DiscoverReleasesTests(unittest.TestCase):
    def test_new_page_is_reported_as_inert_candidate_with_deterministic_order(self):
        first_url = "https://www.gulikit.com/newsinfo/100001.html"
        second_url = "https://www.gulikit.com/newsinfo/100002.html"
        config = watchlist(
            [
                {"id": "second", "url": second_url},
                {"id": "first", "url": first_url},
            ]
        )
        responses = {
            first_url: page_html(links=("https://www.gulikit.com/filedownload/1",)),
            second_url: page_html(title="Other firmware"),
            HEAD_ASSET: b"head asset",
            BODY_ASSET: b"body asset",
        }
        fetcher, calls = fetch_map(responses)
        result = discover_releases.discover(
            config, None, fetcher, observed_at="2026-10-18T00:00:00Z"
        )

        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["kind"], "release_discovery")
        self.assertEqual(result["status"], "complete")
        self.assertIs(result["authorizes_firmware"], False)
        self.assertEqual(
            [item["id"] for item in result["observations"]], ["first", "second"]
        )
        self.assertEqual(
            [item["id"] for item in result["candidates"]], ["first", "second"]
        )
        self.assertEqual(reasons_for(result, "first"), {"new_source"})
        self.assertEqual(reasons_for(result, "second"), {"new_source"})
        self.assertEqual(result["errors"], [])
        self.assertTrue(calls)
        self.assertTrue(all(limit > 0 for _, limit in calls))

        reversed_config = watchlist(
            [
                {"id": "first", "url": first_url},
                {"id": "second", "url": second_url},
            ]
        )
        repeated, _ = fetch_map(responses)
        rerun = discover_releases.discover(
            reversed_config, None, repeated, observed_at="2026-10-18T00:00:00Z"
        )
        self.assertEqual(report_bytes(result), report_bytes(rerun))

    def test_rotating_csrf_comments_and_script_nonces_are_not_page_changes(self):
        config = watchlist()
        baseline_responses = {
            PAGE_URL: page_html(token="csrf-old", nonce="nonce-old"),
            HEAD_ASSET: b"head asset v1",
            BODY_ASSET: b"body asset v1",
        }
        baseline_fetcher, _ = fetch_map(baseline_responses)
        baseline = discover_releases.discover(
            config, None, baseline_fetcher, observed_at="2026-10-18T00:00:00Z"
        )

        changed_fetcher, calls = fetch_map(
            {
                PAGE_URL: page_html(token="csrf-new", nonce="nonce-new"),
                HEAD_ASSET: b"head asset v1",
                BODY_ASSET: b"body asset v1",
            }
        )
        unchanged = discover_releases.discover(
            config,
            report_bytes(baseline),
            changed_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )
        self.assertEqual(unchanged["status"], "complete")
        self.assertIs(unchanged["authorizes_firmware"], False)
        self.assertEqual(unchanged["candidates"], [])
        self.assertEqual(unchanged["errors"], [])
        self.assertTrue(any(url == PAGE_URL for url, _ in calls))

    def test_title_and_download_index_content_changes_are_distinguished(self):
        config = watchlist()
        baseline_page = page_html(title="KK3 Max firmware", links=())
        baseline_fetcher, _ = fetch_map(
            {
                PAGE_URL: baseline_page,
                HEAD_ASSET: b"head asset",
                BODY_ASSET: b"body asset",
            }
        )
        baseline = discover_releases.discover(
            config, None, baseline_fetcher, observed_at="2026-10-18T00:00:00Z"
        )

        updated_fetcher, _ = fetch_map(
            {
                PAGE_URL: page_html(
                    title="KK3 Max firmware 6.1",
                    links=(
                        "https://www.gulikit.com/filedownload/official-main-6.1.zip",
                    ),
                ),
                HEAD_ASSET: b"head asset",
                BODY_ASSET: b"body asset",
            }
        )
        changed = discover_releases.discover(
            config,
            report_bytes(baseline),
            updated_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )
        reasons = reasons_for(changed, "main-release")
        self.assertIn("title_changed", reasons)
        self.assertIn("page_changed", reasons)
        self.assertEqual(changed["candidates"][0]["url"], PAGE_URL)
        self.assertIs(changed["authorizes_firmware"], False)

        index_fetcher, _ = fetch_map(
            {
                PAGE_URL: page_html(
                    title="KK3 Max firmware",
                    links=(
                        "https://www.gulikit.com/filedownload/official-main-6.1.zip",
                    ),
                ),
                HEAD_ASSET: b"head asset",
                BODY_ASSET: b"body asset",
            }
        )
        index_change = discover_releases.discover(
            config,
            report_bytes(baseline),
            index_fetcher,
            observed_at="2026-10-18T00:02:00Z",
        )
        index_reasons = reasons_for(index_change, "main-release")
        self.assertIn("page_changed", index_reasons)
        self.assertNotIn("title_changed", index_reasons)

    def test_reused_identity_with_changed_page_url_is_reported(self):
        old_url = "https://www.gulikit.com/newsinfo/200001.html"
        new_url = "https://www.gulikit.com/newsinfo/200002.html"
        baseline = discover_releases.discover(
            watchlist([{"id": "same-release", "url": old_url}]),
            None,
            lambda url, _limit: page_html() if url == old_url else b"",
            observed_at="2026-10-18T00:00:00Z",
        )
        changed = discover_releases.discover(
            watchlist([{"id": "same-release", "url": new_url}]),
            report_bytes(baseline),
            lambda url, _limit: page_html() if url == new_url else b"",
            observed_at="2026-10-18T00:01:00Z",
        )
        reasons = reasons_for(changed, "same-release")
        self.assertIn("source_url_changed", reasons)
        self.assertEqual(changed["candidates"][0]["url"], new_url)

    def test_successful_observation_after_unobserved_baseline_is_new_source(self):
        baseline = {
            "schema_version": 1,
            "kind": "release_discovery",
            "status": "incomplete",
            "observations": [
                {
                    "kind": "page",
                    "id": "main-release",
                    "url": PAGE_URL,
                    "status": "unobserved",
                }
            ],
        }
        fetcher, _ = fetch_map(
            {PAGE_URL: page_html(), HEAD_ASSET: b"head", BODY_ASSET: b"body"}
        )

        recovered = discover_releases.discover(
            watchlist(),
            report_bytes(baseline),
            fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )

        self.assertEqual(recovered["status"], "complete")
        self.assertEqual(reasons_for(recovered, "main-release"), {"new_source"})

    def test_asset_only_change_is_reported_without_interpreting_javascript(self):
        config = watchlist()
        html = page_html(title="Stable title", links=("/newsinfo/887152.html",))
        baseline_fetcher, _ = fetch_map(
            {PAGE_URL: html, HEAD_ASSET: b"head v1", BODY_ASSET: b"body v1"}
        )
        baseline = discover_releases.discover(
            config, None, baseline_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        updated_fetcher, _ = fetch_map(
            {PAGE_URL: html, HEAD_ASSET: b"head v1", BODY_ASSET: b"body v2"}
        )
        changed = discover_releases.discover(
            config,
            report_bytes(baseline),
            updated_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )
        reasons = reasons_for(changed, "main-release")
        self.assertIn("asset_changed", reasons)
        self.assertNotIn("title_changed", reasons)
        self.assertNotIn("page_changed", reasons)
        self.assertIs(changed["authorizes_firmware"], False)

    def test_archive_bytes_are_compared_by_stable_id_and_url(self):
        archive_old = b"complete original ZIP bytes v1"
        archive_new = b"complete original ZIP bytes v2"
        config = watchlist(
            pages=[{"id": "landing", "url": PAGE_URL}],
            archives=[
                {
                    "id": "main-6.1",
                    "url": ARCHIVE_URL,
                    "size": len(archive_old),
                    "sha256": digest(archive_old),
                }
            ],
        )
        page_responses = {
            PAGE_URL: page_html(),
            HEAD_ASSET: b"head",
            BODY_ASSET: b"body",
        }
        initial_fetcher, _ = fetch_map({**page_responses, ARCHIVE_URL: archive_old})
        baseline = discover_releases.discover(
            config, None, initial_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        unchanged_fetcher, _ = fetch_map({**page_responses, ARCHIVE_URL: archive_old})
        unchanged = discover_releases.discover(
            config,
            report_bytes(baseline),
            unchanged_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )
        self.assertEqual(unchanged["candidates"], [])

        changed_fetcher, _ = fetch_map({**page_responses, ARCHIVE_URL: archive_new})
        changed = discover_releases.discover(
            config,
            report_bytes(unchanged),
            changed_fetcher,
            observed_at="2026-10-18T00:02:00Z",
        )
        self.assertIn("archive_changed", reasons_for(changed, "main-6.1"))
        self.assertIs(changed["authorizes_firmware"], False)

    def test_fetch_failure_is_incomplete_and_never_claims_unchanged(self):
        config = watchlist()
        good_fetcher, _ = fetch_map(
            {PAGE_URL: page_html(), HEAD_ASSET: b"head", BODY_ASSET: b"body"}
        )
        baseline = discover_releases.discover(
            config, None, good_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        failed_fetcher, _ = fetch_map({PAGE_URL: OSError("HTTP 503")})
        failed = discover_releases.discover(
            config,
            report_bytes(baseline),
            failed_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )
        self.assertEqual(failed["status"], "incomplete")
        self.assertIs(failed["authorizes_firmware"], False)
        self.assertEqual(failed["candidates"], [])
        self.assertEqual(failed["errors"][0]["id"], "main-release")
        self.assertEqual(failed["errors"][0]["url"], PAGE_URL)

    def test_http_429_is_incomplete_and_never_claims_unchanged(self):
        config = watchlist()
        good_fetcher, _ = fetch_map(
            {PAGE_URL: page_html(), HEAD_ASSET: b"head", BODY_ASSET: b"body"}
        )
        baseline = discover_releases.discover(
            config, None, good_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        rate_limited, _ = fetch_map(
            {PAGE_URL: HTTPError(PAGE_URL, 429, "Too Many Requests", {}, None)}
        )

        result = discover_releases.discover(
            config,
            report_bytes(baseline),
            rate_limited,
            observed_at="2026-10-18T00:01:00Z",
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["errors"][0]["id"], "main-release")
        self.assertIn("429", result["errors"][0]["error"])

    def test_expired_scan_budget_prevents_starting_later_page_fetches(self):
        first_url = "https://www.gulikit.com/newsinfo/300001.html"
        second_url = "https://www.gulikit.com/newsinfo/300002.html"
        config = watchlist(
            [
                {"id": "first", "url": first_url},
                {"id": "second", "url": second_url},
            ]
        )
        calls = []

        def fetch(url, _limit):
            calls.append(url)
            return page_html()

        with patch.object(discover_releases, "SCAN_BUDGET_SECONDS", 0):
            result = discover_releases.discover(
                config, None, fetch, observed_at="2026-10-18T00:00:00Z"
            )

        self.assertEqual(calls, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual([item["id"] for item in result["errors"]], ["first", "second"])

    def test_discovery_deadline_context_is_cleared_after_scan(self):
        fetcher, _ = fetch_map({PAGE_URL: OSError("fixture fetch failed")})
        token = discover_releases._ACTIVE_DEADLINE.set(None)
        try:
            result = discover_releases.discover(
                watchlist(), None, fetcher, observed_at="2026-10-18T00:00:00Z"
            )
            self.assertEqual(result["status"], "incomplete")
            self.assertIsNone(discover_releases._ACTIVE_DEADLINE.get())
        finally:
            discover_releases._ACTIVE_DEADLINE.reset(token)

    def test_watchlist_schema_version_rejects_boolean(self):
        invalid = json.dumps(
            {"schema_version": True, "pages": [{"id": "main", "url": PAGE_URL}]}
        ).encode()
        with self.assertRaises(ValueError):
            discover_releases.discover(invalid, None, lambda _url, _limit: b"")

    def test_malformed_observed_digest_in_baseline_is_rejected(self):
        fetcher, _ = fetch_map(
            {PAGE_URL: page_html(), HEAD_ASSET: b"head", BODY_ASSET: b"body"}
        )
        baseline = discover_releases.discover(
            watchlist(), None, fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        baseline["observations"][0]["page_sha256"] = "not-a-sha256"

        with self.assertRaises(ValueError):
            discover_releases.discover(
                watchlist(),
                report_bytes(baseline),
                fetcher,
                observed_at="2026-10-18T00:01:00Z",
            )

    def test_duplicate_unobserved_baseline_identity_is_rejected(self):
        baseline = {
            "schema_version": 1,
            "kind": "release_discovery",
            "status": "incomplete",
            "observations": [
                {
                    "kind": "page",
                    "id": "missed",
                    "url": PAGE_URL,
                    "status": "unobserved",
                },
                {
                    "kind": "archive",
                    "id": "missed",
                    "url": ARCHIVE_URL,
                    "status": "unobserved",
                },
            ],
        }
        with self.assertRaises(ValueError):
            discover_releases.discover(
                watchlist(),
                report_bytes(baseline),
                lambda _url, _limit: b"",
                observed_at="2026-10-18T00:00:00Z",
            )

    def test_truncated_content_length_is_an_unobserved_incomplete_source(self):
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Length": "10"}
        response.read1.side_effect = [b"short", b""]
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(discover_releases, "build_opener", return_value=opener):
            result = discover_releases.discover(
                watchlist(),
                None,
                lambda url, limit: discover_releases.fetch_https(url, limit),
                observed_at="2026-10-18T00:00:00Z",
            )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["observations"][0]["status"], "unobserved")
        self.assertIn("truncated", result["errors"][0]["error"])

    def test_streaming_fetch_rechecks_deadline_between_read1_chunks(self):
        response = MagicMock()
        response.status = 200
        response.headers = {}
        response.read1.side_effect = [b"first chunk"]
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        opener = MagicMock()
        opener.open.return_value = response
        token = discover_releases._ACTIVE_DEADLINE.set(1.0)
        try:
            with (
                patch.object(discover_releases, "build_opener", return_value=opener),
                patch.object(
                    discover_releases.time, "monotonic", side_effect=[0.0, 0.5, 2.0]
                ),
            ):
                with self.assertRaisesRegex(ValueError, "time budget"):
                    discover_releases.fetch_https(PAGE_URL, 1024)
        finally:
            discover_releases._ACTIVE_DEADLINE.reset(token)
        response.read1.assert_called_once()
        response.read.assert_not_called()

    def test_oversized_page_assets_manifests_and_script_counts_are_bounded(self):
        config = watchlist()
        oversized_fetcher, calls = fetch_map({PAGE_URL: b"x" * (256 * 1024 + 1)})
        oversized = discover_releases.discover(
            config, None, oversized_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        self.assertEqual(oversized["status"], "incomplete")
        self.assertEqual(oversized["errors"][0]["id"], "main-release")
        self.assertTrue(calls and calls[0][1] <= 256 * 1024)

        asset_fetcher, asset_calls = fetch_map(
            {
                PAGE_URL: page_html(),
                HEAD_ASSET: b"x" * (2 * 1024 * 1024 + 1),
                BODY_ASSET: b"body",
            }
        )
        oversized_asset = discover_releases.discover(
            config, None, asset_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        self.assertEqual(oversized_asset["status"], "incomplete")
        self.assertEqual(oversized_asset["errors"][0]["id"], "main-release")
        self.assertTrue(
            any(
                url == HEAD_ASSET and limit == 2 * 1024 * 1024
                for url, limit in asset_calls
            )
        )

        three_scripts = (
            "<html><head><title>Release</title>"
            '<script src="https://www.gulikit.com/js/one.js"></script>'
            '<script src="https://www.gulikit.com/js/two.js"></script>'
            '<script src="https://www.gulikit.com/js/three.js"></script>'
            "</head></html>"
        ).encode()
        asset_limit_fetcher, _ = fetch_map(
            {
                PAGE_URL: three_scripts,
                "https://www.gulikit.com/js/one.js": b"one",
                "https://www.gulikit.com/js/two.js": b"two",
                "https://www.gulikit.com/js/three.js": b"three",
            }
        )
        too_many = discover_releases.discover(
            config, None, asset_limit_fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        self.assertEqual(too_many["status"], "incomplete")
        self.assertEqual(too_many["errors"][0]["id"], "main-release")

        oversized_manifest = b" " * (discover_releases.MAX_INPUT_BYTES + 1)
        with self.assertRaises(ValueError):
            discover_releases.discover(
                oversized_manifest, None, lambda _url, _limit: b""
            )
        too_many_pages = watchlist(
            [
                {
                    "id": f"page-{index}",
                    "url": f"https://www.gulikit.com/newsinfo/{index + 1}.html",
                }
                for index in range(discover_releases.MAX_PAGES + 1)
            ]
        )
        with self.assertRaises(ValueError):
            discover_releases.discover(too_many_pages, None, lambda _url, _limit: b"")

    def test_large_complete_report_can_be_reused_as_baseline(self):
        pages = [
            {
                "id": f"large-{index}",
                "url": f"https://www.gulikit.com/newsinfo/large-{index}.html",
            }
            for index in range(2)
        ]
        config = watchlist(pages)
        responses = {item["url"]: page_html(title="x" * (150 * 1024)) for item in pages}
        responses.update({HEAD_ASSET: b"head", BODY_ASSET: b"body"})
        fetcher, _ = fetch_map(responses)
        first = discover_releases.discover(
            config, None, fetcher, observed_at="2026-10-18T00:00:00Z"
        )
        baseline = report_bytes(first)
        self.assertEqual(first["status"], "complete")
        self.assertGreater(len(baseline), discover_releases.MAX_INPUT_BYTES)
        second_fetcher, _ = fetch_map(responses)

        second = discover_releases.discover(
            config,
            baseline,
            second_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )

        self.assertEqual(second["status"], "complete")
        self.assertEqual(second["candidates"], [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "watchlist.json"
            config_path.write_bytes(config)
            baseline_path = root / "baseline.json"
            discover_releases._write_new(baseline_path, first)
            output = root / "next.json"
            run_discovery = discover_releases.discover
            with (
                patch.object(
                    discover_releases,
                    "discover",
                    side_effect=lambda watch, previous: run_discovery(
                        watch, previous, fetcher
                    ),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                status = discover_releases.main(
                    [
                        "--watchlist",
                        str(config_path),
                        "--baseline",
                        str(baseline_path),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.read_text())["candidates"], [])

    def test_baseline_over_its_limit_is_rejected(self):
        oversized_baseline = b" " * (discover_releases.MAX_BASELINE_BYTES + 1)
        with self.assertRaises(ValueError):
            discover_releases.discover(
                watchlist(),
                oversized_baseline,
                lambda _url, _limit: b"",
                observed_at="2026-10-18T00:00:00Z",
            )

    def test_oversized_report_is_refused_before_output_parent_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            watchlist_path = root / "watchlist.json"
            watchlist_path.write_bytes(watchlist())
            output = root / "not-created" / "report.json"
            oversized_report = {
                "payload": "x" * (discover_releases.MAX_BASELINE_BYTES + 1)
            }

            with patch.object(
                discover_releases, "discover", return_value=oversized_report
            ):
                status = discover_releases.main(
                    ["--watchlist", str(watchlist_path), "--output", str(output)]
                )

            self.assertEqual(status, 2)
            self.assertFalse(output.parent.exists())
            self.assertFalse(output.exists())

    def test_json_depth_bomb_is_rejected_by_library_and_cli(self):
        depth_bomb = (
            b'{"schema_version":1,"pages":[],"unused":'
            + b"[" * 17
            + b"0"
            + b"]" * 17
            + b"}"
        )
        with self.assertRaises(ValueError):
            discover_releases.discover(depth_bomb, None, lambda _url, _limit: b"")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            watchlist_path = root / "watchlist.json"
            watchlist_path.write_bytes(depth_bomb)
            output = root / "not-created" / "report.json"
            status = discover_releases.main(
                ["--watchlist", str(watchlist_path), "--output", str(output)]
            )
            self.assertEqual(status, 2)
            self.assertFalse(output.parent.exists())
            self.assertFalse(output.exists())

    def test_container_limit_is_checked_before_json_parser(self):
        over_bound = (
            b'{"schema_version":1,"pages":[],"unused":['
            + b",".join([b"[]"] * 4097)
            + b"]}"
        )
        original_loads = json.loads
        with patch.object(
            discover_releases.json, "loads", wraps=original_loads
        ) as loads:
            with self.assertRaises(ValueError):
                discover_releases.discover(over_bound, None, lambda _url, _limit: b"")
        loads.assert_not_called()

    def test_json_is_utf8_so_other_encodings_cannot_bypass_lexical_bounds(self):
        config = watchlist().decode("utf-8")
        for encoding in ["utf-16", "utf-32"]:
            with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                discover_releases.discover(
                    config.encode(encoding), None, lambda _url, _limit: b""
                )

    def test_unknown_baseline_top_level_field_is_rejected(self):
        baseline = {
            "schema_version": 1,
            "kind": "release_discovery",
            "status": "complete",
            "observations": [],
            "candidates": [],
            "errors": [],
            "authorizes_firmware": False,
            "unexpected": "field",
        }
        with self.assertRaises(ValueError):
            discover_releases.discover(
                watchlist(),
                report_bytes(baseline),
                lambda _url, _limit: b"",
                observed_at="2026-10-18T00:00:00Z",
            )

    def test_valid_escaped_json_structure_in_page_title_is_accepted(self):
        title = 'Firmware {draft} "quoted" \\ path'
        fetcher, _ = fetch_map(
            {
                PAGE_URL: page_html(title=title),
                HEAD_ASSET: b"head",
                BODY_ASSET: b"body",
            }
        )

        first = discover_releases.discover(
            watchlist(),
            None,
            fetcher,
            observed_at="2026-10-18T00:00:00Z",
        )
        repeated_fetcher, _ = fetch_map(
            {
                PAGE_URL: page_html(title=title),
                HEAD_ASSET: b"head",
                BODY_ASSET: b"body",
            }
        )
        result = discover_releases.discover(
            watchlist(),
            report_bytes(first),
            repeated_fetcher,
            observed_at="2026-10-18T00:01:00Z",
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["observations"][0]["title"], title)

    def test_writer_structural_punctuation_limit_prevents_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "not-created" / "report.json"
            report = {"items": [{} for _ in range(50_001)]}

            with self.assertRaises(ValueError):
                discover_releases._write_new(output, report)

            self.assertFalse(output.parent.exists())
            self.assertFalse(output.exists())

    def test_invalid_watchlist_origins_and_duplicate_ids_are_rejected(self):
        for url in [
            "http://www.gulikit.com/newsinfo/1.html",
            "https://evil.example/newsinfo/1.html",
            "https://user@www.gulikit.com/newsinfo/1.html",
            "https://www.gulikit.com:443/newsinfo/1.html",
            "https://www.gulikit.com/newsinfo/1.html?token=x",
            "https://www.gulikit.com/newsinfo/1.html#fragment",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                discover_releases.discover(
                    watchlist([{"id": "bad", "url": url}]),
                    None,
                    lambda _url, _limit: b"",
                )

        duplicate_ids = watchlist(
            [
                {"id": "same", "url": "https://www.gulikit.com/newsinfo/1.html"},
                {"id": "same", "url": "https://www.gulikit.com/newsinfo/2.html"},
            ]
        )
        with self.assertRaises(ValueError):
            discover_releases.discover(duplicate_ids, None, lambda _url, _limit: b"")

    def test_default_fetcher_refuses_http_redirects_without_following_them(self):
        response = MagicMock()
        response.status = 302
        response.headers = {}
        response.__enter__ = MagicMock(return_value=response)
        response.__exit__ = MagicMock(return_value=False)
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(
            discover_releases, "build_opener", return_value=opener
        ) as build:
            with self.assertRaisesRegex(ValueError, "HTTP status 302"):
                discover_releases.fetch_https(PAGE_URL, 1024)
        handler = build.call_args.args[0]
        self.assertIs(handler, discover_releases._NoRedirect)
        self.assertIsNone(
            handler().redirect_request(
                None, None, 302, "Found", {}, "https://evil.example/"
            )
        )
        opener.open.assert_called_once()

    def test_command_reports_invalid_inputs_and_io_with_documented_exit_codes(self):
        script = Path(__file__).resolve().parents[1] / "discover_releases.py"
        with self.subTest(kind="invalid watchlist"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                invalid = root / "watchlist.json"
                invalid.write_bytes(b"{}")
                output = root / "report.json"
                result = subprocess.run(
                    [
                        sys.executable,
                        str(script),
                        "--watchlist",
                        str(invalid),
                        "--output",
                        str(output),
                    ],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())

        with self.subTest(kind="missing watchlist"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                missing = root / "absent.json"
                output = root / "report.json"
                result = subprocess.run(
                    [
                        sys.executable,
                        str(script),
                        "--watchlist",
                        str(missing),
                        "--output",
                        str(output),
                    ],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())

    def test_cli_returns_distinct_complete_and_incomplete_status_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            watchlist_path = root / "watchlist.json"
            watchlist_path.write_bytes(watchlist())
            output = root / "report.json"
            complete_report = {
                "schema_version": 1,
                "kind": "release_discovery",
                "observed_at": "2026-10-18T00:00:00Z",
                "status": "complete",
                "authorizes_firmware": False,
                "observations": [],
                "candidates": [],
                "errors": [],
            }
            stdout = io.StringIO()
            with (
                patch.object(
                    discover_releases, "discover", return_value=complete_report
                ),
                contextlib.redirect_stdout(stdout),
            ):
                status = discover_releases.main(
                    ["--watchlist", str(watchlist_path), "--output", str(output)]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "complete")
            self.assertEqual(json.loads(output.read_text()), complete_report)

            output.unlink()
            incomplete_report = {
                **complete_report,
                "status": "incomplete",
                "errors": [
                    {
                        "id": "main-release",
                        "url": PAGE_URL,
                        "error": "fixture failure",
                    }
                ],
            }
            stdout = io.StringIO()
            with (
                patch.object(
                    discover_releases, "discover", return_value=incomplete_report
                ),
                contextlib.redirect_stdout(stdout),
            ):
                status = discover_releases.main(
                    ["--watchlist", str(watchlist_path), "--output", str(output)]
                )
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "incomplete")
            self.assertEqual(json.loads(output.read_text()), incomplete_report)

            output.write_bytes(b"preserve preexisting report")
            stderr = io.StringIO()
            with (
                patch.object(
                    discover_releases, "discover", return_value=complete_report
                ),
                contextlib.redirect_stderr(stderr),
            ):
                status = discover_releases.main(
                    ["--watchlist", str(watchlist_path), "--output", str(output)]
                )
            self.assertEqual(status, 2)
            self.assertEqual(output.read_bytes(), b"preserve preexisting report")


if __name__ == "__main__":
    unittest.main()
