#!/usr/bin/env python3
"""Append a reviewed firmware ZIP to an explicitly selected signed bare Git archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

ARCHIVE_MARKER = ".firmware-archive.json"
ARCHIVE_SCHEMA = 1
MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_MEMBER_SIZE = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000


def git(
    repo: Path, *args: str, env: dict[str, str] | None = None, check: bool = True
) -> str:
    process_env = clean_env(env)
    result = subprocess.run(
        ["git", f"--git-dir={repo}", *args],
        env=process_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        raise ValueError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def clean_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Drop inherited Git routing/configuration variables, then apply explicit safe overrides."""
    result = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    result["GIT_NO_REPLACE_OBJECTS"] = "1"
    if overrides:
        result.update(
            {
                key: value
                for key, value in overrides.items()
                if not key.startswith("GIT_")
            }
        )
        if "GIT_INDEX_FILE" in overrides:
            result["GIT_INDEX_FILE"] = overrides["GIT_INDEX_FILE"]
        for key, value in overrides.items():
            if re.fullmatch(r"GIT_CONFIG_(?:COUNT|KEY_[0-9]+|VALUE_[0-9]+)", key):
                result[key] = value
    return result


def safe_segment(value: str, label: str, *, lower: bool = False) -> str:
    if lower:
        value = value.lower()
    if not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{0,79}" if lower else r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}",
        value,
    ):
        raise ValueError(f"invalid {label}: {value!r}")
    if value in {".", ".."}:
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def validate_zip(path: Path) -> None:
    if not zipfile.is_zipfile(path):
        raise ValueError("input must be a valid ZIP archive")
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ValueError("ZIP member count exceeds the allowed limit")
            total_size = 0
            for info in infos:
                member_path = PurePosixPath(info.filename)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or "\x00" in info.filename
                    or "\\" in info.filename
                    or re.match(r"^[A-Za-z]:", info.filename)
                ):
                    raise ValueError(f"unsafe ZIP member path: {info.filename!r}")
                if info.flag_bits & 1:
                    raise ValueError(
                        f"encrypted ZIP member is unsupported: {info.filename!r}"
                    )
                if info.file_size > MAX_MEMBER_SIZE:
                    raise ValueError("ZIP member exceeds the allowed uncompressed size")
                total_size += info.file_size
                if total_size > MAX_UNCOMPRESSED_SIZE:
                    raise ValueError("ZIP uncompressed size exceeds the allowed limit")
                if (
                    info.file_size > 0
                    and info.file_size / max(info.compress_size, 1)
                    > MAX_COMPRESSION_RATIO
                ):
                    raise ValueError(
                        "ZIP member compression ratio exceeds the allowed limit"
                    )
            actual_total = 0
            for info in infos:
                actual_member = 0
                if info.is_dir():
                    if info.file_size != 0:
                        raise ValueError("ZIP directory records must not contain data")
                    continue
                with zf.open(info) as member:
                    while block := member.read(1024 * 1024):
                        actual_member += len(block)
                        actual_total += len(block)
                        if (
                            actual_member > MAX_MEMBER_SIZE
                            or actual_total > MAX_UNCOMPRESSED_SIZE
                        ):
                            raise ValueError(
                                "ZIP decompressed data exceeds the allowed limit"
                            )
                if actual_member != info.file_size:
                    raise ValueError(
                        f"ZIP member size does not match its directory entry: {info.filename!r}"
                    )
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError(f"invalid ZIP archive: {exc}") from exc


def validate_timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise ValueError("retrieved-at must be a UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("retrieved-at must be an ISO 8601 UTC timestamp") from exc
    return value


def official_source(value: str) -> str:
    parsed = urlsplit(value)
    if (
        len(value) > 4096
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
        or parsed.scheme != "https"
        or parsed.hostname not in {"gulikit.com", "www.gulikit.com"}
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("source must be an official HTTPS URL on gulikit.com")
    return value


def verify_pinned_signature(
    repo: Path, commit: str, signing_fingerprint: str, env: dict[str, str] | None = None
) -> bool:
    result = subprocess.run(
        [
            "git",
            f"--git-dir={repo}",
            "-c",
            "gpg.format=openpgp",
            "-c",
            "gpg.program=gpg",
            "verify-commit",
            "--raw",
            commit,
        ],
        env=clean_env(env),
        text=True,
        capture_output=True,
    )
    if result.returncode:
        return False
    for line in (result.stdout + result.stderr).splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            signer_fingerprint = fields[2].upper()
            primary_fingerprint = (
                fields[11].upper() if len(fields) > 11 else signer_fingerprint
            )
            if signing_fingerprint.upper() in {
                signer_fingerprint,
                primary_fingerprint,
            }:
                return True
    return False


def archive_root(repo: Path, tip: str, signing_fingerprint: str) -> str:
    roots = git(repo, "rev-list", "--max-parents=0", tip).splitlines()
    if len(roots) != 1:
        raise ValueError("existing ref is not a single-root firmware archive")
    root = roots[0]
    commits = git(repo, "rev-list", "--reverse", tip).splitlines()
    prior_files: set[str] = set()
    parent = None
    for commit in commits:
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).split()[1:]
        if parents != ([] if parent is None else [parent]):
            raise ValueError("archive history must be linear and contain no merges")
        if not verify_pinned_signature(repo, commit, signing_fingerprint):
            raise ValueError(
                "archive history contains an unsigned commit or a signature from another identity"
            )
        diff_args = [
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-status",
            "-r",
            commit,
        ]
        if parent:
            diff_args.insert(1, "-M")
        changes = git(repo, *diff_args).splitlines()
        entries = [line.split("\t") for line in changes]
        if any(len(entry) != 2 or entry[0] != "A" for entry in entries):
            raise ValueError(
                "archive history contains a replacement, deletion, mode change, or rename"
            )
        added = {entry[1] for entry in entries}
        if parent is None:
            if not {ARCHIVE_MARKER}.issubset(added):
                raise ValueError("archive root does not establish the archive marker")
            firmware_added = added - {ARCHIVE_MARKER}
            if len(firmware_added) != 2:
                raise ValueError(
                    "archive root must add exactly one firmware ZIP and provenance record"
                )
        else:
            if len(added) != 2 or any(
                not item.startswith("firmware/") for item in added
            ):
                raise ValueError(
                    "archive append must add exactly one firmware ZIP and provenance record"
                )
            if len({str(PurePosixPath(item).with_suffix("")) for item in added}) != 1:
                raise ValueError(
                    "archive append paths must be a matching ZIP and provenance pair"
                )
            if not any(item.endswith(".zip") for item in added) or not any(
                item.endswith(".json") for item in added
            ):
                raise ValueError(
                    "archive append must contain one ZIP and one provenance JSON"
                )
        firmware_paths = added - ({ARCHIVE_MARKER} if parent is None else set())
        zip_paths = [item for item in firmware_paths if item.endswith(".zip")]
        json_paths = [item for item in firmware_paths if item.endswith(".json")]
        if len(zip_paths) != 1 or len(json_paths) != 1:
            raise ValueError(
                "archive entries must form one ZIP and provenance JSON pair"
            )
        zip_path = PurePosixPath(zip_paths[0])
        if (
            len(zip_path.parts) != 4
            or zip_path.parts[0] != "firmware"
            or zip_paths[0][:-4] != json_paths[0][:-5]
        ):
            raise ValueError(
                "firmware archive paths must be firmware/model/component/version pairs"
            )
        if prior_files & added:
            raise ValueError("archive history reuses an immutable path")
        prior_files.update(added)
        tree = git(repo, "ls-tree", "-r", commit)
        for line in tree.splitlines():
            mode, kind, _oid, name = line.split("\t", 1)[0].split(" ", 2) + [
                line.split("\t", 1)[1]
            ]
            if mode != "100644" or kind != "blob":
                raise ValueError(
                    "archive tree contains a non-regular or non-blob entry"
                )
        parent = commit
    marker = subprocess.run(
        ["git", f"--git-dir={repo}", "show", f"{root}:{ARCHIVE_MARKER}"],
        env=clean_env(),
        text=True,
        capture_output=True,
    )
    if marker.returncode:
        raise ValueError(
            "existing ref is not a marked firmware archive; refusing arbitrary repository history"
        )
    try:
        data = json.loads(marker.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("existing archive marker is invalid") from exc
    if data != {"schema": ARCHIVE_SCHEMA, "type": "gulikit-firmware-archive"}:
        raise ValueError(
            "existing archive marker does not match the supported archive format"
        )
    return root


def import_archive(
    repo_arg: str,
    ref: str,
    signing_key: str,
    model: str,
    component: str,
    version: str,
    zip_arg: str,
    source: str,
    retrieved_at: str,
    expected_sha256: str,
    expected_size: int,
) -> str:
    repo = Path(repo_arg).expanduser().resolve()
    archive = Path(zip_arg).expanduser().resolve()
    if not repo.is_dir() or git(repo, "rev-parse", "--is-bare-repository") != "true":
        raise ValueError("archive repository must be an existing bare Git repository")
    for unsafe_control in (
        repo / "shallow",
        repo / "info" / "grafts",
        repo / "objects" / "info" / "alternates",
    ):
        if unsafe_control.exists() and unsafe_control.stat().st_size:
            raise ValueError(
                "archive repository must not use shallow history, grafts, or alternate object stores"
            )
    if git(repo, "for-each-ref", "--format=%(refname)", "refs/replace"):
        raise ValueError("archive repository must not contain replacement refs")
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})", signing_key):
        raise ValueError("a full GPG signing fingerprint is required")
    source = official_source(source)
    retrieved_at = validate_timestamp(retrieved_at)
    model = safe_segment(model, "model", lower=True)
    component = safe_segment(component, "component", lower=True)
    version = safe_segment(version, "version")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("expected SHA-256 must contain 64 hexadecimal characters")
    if expected_size < 0 or expected_size > MAX_ARCHIVE_SIZE:
        raise ValueError("expected ZIP size is outside the allowed limit")
    ref_check = subprocess.run(
        ["git", f"--git-dir={repo}", "check-ref-format", ref],
        env=clean_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ref_check.returncode != 0 or not ref.startswith("refs/heads/"):
        raise ValueError("archive ref must be a valid refs/heads/* branch")
    symbolic = subprocess.run(
        ["git", f"--git-dir={repo}", "symbolic-ref", "-q", ref],
        env=clean_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if symbolic.returncode == 0:
        raise ValueError("archive ref must not be symbolic")
    if not archive.is_file():
        raise ValueError("input ZIP does not exist or is not a regular file")

    object_format = git(repo, "rev-parse", "--show-object-format")
    zero_oid = "0" * (64 if object_format == "sha256" else 40)
    old = git(repo, "rev-parse", "--verify", ref, check=False) or None
    if old:
        archive_root(repo, old, signing_key)
    old_oid = old or zero_oid

    zip_rel = f"firmware/{model}/{component}/{version}.zip"
    provenance_rel = f"firmware/{model}/{component}/{version}.json"
    if old:
        listing = git(repo, "ls-tree", "-r", "--name-only", old).splitlines()
        if zip_rel in listing or provenance_rel in listing:
            raise ValueError("version path already exists; archive is append-only")

    with tempfile.TemporaryDirectory(prefix="firmware-archive-") as temp:
        snapshot = Path(temp) / "original.zip"
        digest = hashlib.sha256()
        size = 0
        with archive.open("rb") as source_file, snapshot.open("wb") as snapshot_file:
            while block := source_file.read(1024 * 1024):
                size += len(block)
                if size > MAX_ARCHIVE_SIZE:
                    raise ValueError("ZIP archive exceeds the allowed compressed size")
                digest.update(block)
                snapshot_file.write(block)
        sha256 = digest.hexdigest()
        if size != expected_size:
            raise ValueError(
                f"ZIP size mismatch: expected {expected_size}, read {size}"
            )
        if sha256.lower() != expected_sha256.lower():
            raise ValueError("ZIP SHA-256 does not match the reviewed expected value")
        validate_zip(snapshot)

        provenance = {
            "component": component,
            "filename": archive.name,
            "model": model,
            "retrieved_at": retrieved_at,
            "schema": 1,
            "sha256": sha256,
            "size": size,
            "source": source,
            "version": version,
            "zip": zip_rel,
        }
        index = str(Path(temp) / "index")
        env = clean_env()
        env["GIT_INDEX_FILE"] = index
        if old:
            git(repo, "read-tree", old, env=env)
        else:
            git(repo, "read-tree", "--empty", env=env)
        blob = git(repo, "hash-object", "-w", str(snapshot))
        meta = subprocess.run(
            ["git", f"--git-dir={repo}", "hash-object", "-w", "--stdin"],
            input=(json.dumps(provenance, sort_keys=True, indent=2) + "\n"),
            env=clean_env(),
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{blob},{zip_rel}",
            env=env,
        )
        git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{meta},{provenance_rel}",
            env=env,
        )
        if not old:
            marker_text = (
                json.dumps(
                    {"schema": ARCHIVE_SCHEMA, "type": "gulikit-firmware-archive"},
                    sort_keys=True,
                )
                + "\n"
            )
            marker = subprocess.run(
                ["git", f"--git-dir={repo}", "hash-object", "-w", "--stdin"],
                input=marker_text,
                env=clean_env(),
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{marker},{ARCHIVE_MARKER}",
                env=env,
            )
        tree = git(repo, "write-tree", env=env)
        commit_args = ["commit-tree", tree]
        if old:
            commit_args += ["-p", old]
        commit_args += [
            "-S" + signing_key,
            "-m",
            f"Import {model} {component} {version}",
        ]
        commit_env = clean_env(env)
        commit_env["GIT_CONFIG_COUNT"] = "3"
        commit_env["GIT_CONFIG_KEY_0"] = "gpg.format"
        commit_env["GIT_CONFIG_VALUE_0"] = "openpgp"
        commit_env["GIT_CONFIG_KEY_1"] = "gpg.program"
        commit_env["GIT_CONFIG_VALUE_1"] = "gpg"
        commit_env["GIT_CONFIG_KEY_2"] = "user.signingkey"
        commit_env["GIT_CONFIG_VALUE_2"] = signing_key
        new = git(repo, *commit_args, env=commit_env)
        if not verify_pinned_signature(repo, new, signing_key, commit_env):
            raise ValueError(
                "new commit signature verification failed pinned identity check"
            )
        # Compare-and-swap prevents clobbering a concurrent append.
        git(repo, "update-ref", ref, new, old_oid)
    return new


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-repo",
        required=True,
        help="explicit path to an isolated bare archive repository",
    )
    parser.add_argument(
        "--archive-ref",
        required=True,
        help="explicit ref to append, such as refs/heads/vendor-archive",
    )
    parser.add_argument(
        "--signing-key",
        required=True,
        help="GPG signing identity; commits are always OpenPGP signed",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--zip", required=True, help="original complete firmware ZIP")
    parser.add_argument(
        "--source", required=True, help="official GuliKit HTTPS source URL"
    )
    parser.add_argument(
        "--retrieved-at",
        required=True,
        help="retrieval time as an ISO 8601 UTC timestamp ending in Z",
    )
    parser.add_argument(
        "--sha256", required=True, help="reviewed expected SHA-256 of the ZIP"
    )
    parser.add_argument(
        "--size", required=True, type=int, help="reviewed expected ZIP size in bytes"
    )
    args = parser.parse_args(argv)
    try:
        print(
            import_archive(
                args.archive_repo,
                args.archive_ref,
                args.signing_key,
                args.model,
                args.component,
                args.version,
                args.zip,
                args.source,
                args.retrieved_at,
                args.sha256,
                args.size,
            )
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"firmware_archive: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
