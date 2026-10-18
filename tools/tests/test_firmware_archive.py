import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools import firmware_archive


class FirmwareArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gpg_home = self.root / "gnupg"
        self.gpg_home.mkdir(mode=0o700)
        self.addCleanup(self.cleanup_gpg_agent)
        self.gpg_env = {**os.environ, "GNUPGHOME": str(self.gpg_home)}
        subprocess.run(
            [
                "gpg",
                "--homedir",
                str(self.gpg_home),
                "--batch",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Archive Test <archive@example.test>",
                "rsa2048",
                "sign",
                "0",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listing = subprocess.run(
            [
                "gpg",
                "--homedir",
                str(self.gpg_home),
                "--batch",
                "--with-colons",
                "--list-secret-keys",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        self.key = next(
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
        )
        self.source_repo = self.root / "source"
        self.source_repo.mkdir()
        self.run_git(self.source_repo, "init")
        self.run_git(self.source_repo, "config", "user.name", "Source")
        self.run_git(self.source_repo, "config", "user.email", "source@example.test")
        (self.source_repo / "keep.txt").write_text(
            "source checkout remains untouched\n"
        )
        self.run_git(self.source_repo, "add", "keep.txt")
        self.run_git(
            self.source_repo,
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"user.signingkey={self.key}",
            "commit",
            "-S",
            "-m",
            "source",
            env=self.gpg_env,
        )
        self.run_git(self.source_repo, "branch", "-M", "main")
        self.source_head = self.run_git(self.source_repo, "rev-parse", "HEAD")
        self.archive = self.root / "archive.git"
        self.init_archive(self.archive)
        self.zip1 = self.make_zip("one.zip", "firmware.bin", b"firmware one")
        self.zip2 = self.make_zip("two.zip", "firmware.bin", b"firmware two")

    def init_archive(self, path, *options):
        self.run_git(self.root, "init", "--bare", *options, str(path))
        # Fresh CI runners have no global author identity. Keep fixture commits
        # independent of developer configuration and preserve real importer policy.
        self.run_git(path, "config", "user.name", "Archive Test")
        self.run_git(path, "config", "user.email", "archive@example.test")

    def cleanup_gpg_agent(self):
        subprocess.run(
            ["gpgconf", "--homedir", str(self.gpg_home), "--kill", "gpg-agent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def run_git(self, cwd, *args, env=None):
        return subprocess.run(
            ["git", *args], cwd=cwd, env=env, check=True, text=True, capture_output=True
        ).stdout.strip()

    def make_zip(self, name, member, content):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, content)
        return path

    def import_one(
        self,
        path,
        version,
        *,
        key=None,
        sha256=None,
        size=None,
        archive=None,
        ref="refs/heads/archive",
    ):
        data = path.read_bytes()
        with patch.dict(os.environ, {"GNUPGHOME": str(self.gpg_home)}):
            return firmware_archive.import_archive(
                str(archive or self.archive),
                ref,
                key or self.key,
                "KK3-Max",
                "Bluetooth",
                version,
                str(path),
                "https://www.gulikit.com/product/123456",
                "2026-10-18T12:30:00Z",
                sha256 or hashlib.sha256(data).hexdigest(),
                len(data) if size is None else size,
            )

    def append_signed_descendant(self, archive, tip, updates, message):
        index = self.root / f"{archive.name}-{message.replace(' ', '-')}-index"
        env = {**self.gpg_env, "GIT_INDEX_FILE": str(index)}
        self.run_git(archive, "read-tree", tip, env=env)
        for path, contents in updates.items():
            blob = (
                subprocess.run(
                    ["git", f"--git-dir={archive}", "hash-object", "-w", "--stdin"],
                    input=contents,
                    env=self.gpg_env,
                    check=True,
                    capture_output=True,
                )
                .stdout.decode()
                .strip()
            )
            self.run_git(
                archive,
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{blob},{path}",
                env=env,
            )
        tree = self.run_git(archive, "write-tree", env=env)
        commit = subprocess.run(
            [
                "git",
                f"--git-dir={archive}",
                "-c",
                "gpg.format=openpgp",
                "-c",
                f"user.signingkey={self.key}",
                "commit-tree",
                tree,
                "-p",
                tip,
                "-S",
                "-m",
                message,
            ],
            env=self.gpg_env,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.run_git(
            archive,
            "update-ref",
            "refs/heads/archive",
            commit,
            tip,
        )
        return commit

    def test_two_signed_append_only_imports_preserve_hash_provenance_and_source(self):
        self.run_git(
            self.archive,
            "config",
            "filter.archive-test.clean",
            "tr a-z A-Z",
        )
        self.run_git(self.archive, "config", "filter.archive-test.smudge", "cat")
        (self.archive / "info" / "attributes").write_text("*.zip filter=archive-test\n")
        self.assertNotEqual(self.zip1.read_bytes().upper(), self.zip1.read_bytes())
        first = self.import_one(self.zip1, "1.0")
        second = self.import_one(self.zip2, "2.0")
        self.assertEqual(
            self.run_git(
                self.archive, "rev-list", "--parents", "-n", "1", first
            ).split(),
            [first],
        )
        self.assertEqual(self.run_git(self.archive, "merge-base", first, second), first)
        self.assertEqual(
            self.run_git(
                self.archive, "rev-list", "--parents", "-n", "1", second
            ).split(),
            [second, first],
        )
        alternate_objects = str(self.source_repo / ".git" / "objects")
        no_merge_base = subprocess.run(
            [
                "git",
                f"--git-dir={self.archive}",
                "merge-base",
                second,
                self.source_head,
            ],
            env={**os.environ, "GIT_ALTERNATE_OBJECT_DIRECTORIES": alternate_objects},
            capture_output=True,
        )
        self.assertEqual(no_merge_base.returncode, 1)
        for commit in (first, second):
            self.run_git(
                self.archive,
                "-c",
                "gpg.format=openpgp",
                "verify-commit",
                commit,
                env=self.gpg_env,
            )
        blob = self.run_git(
            self.archive,
            "rev-parse",
            "refs/heads/archive:firmware/kk3-max/bluetooth/1.0.zip",
        )
        data = subprocess.run(
            ["git", f"--git-dir={self.archive}", "cat-file", "blob", blob],
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(data, self.zip1.read_bytes())
        metadata = subprocess.run(
            [
                "git",
                f"--git-dir={self.archive}",
                "show",
                "refs/heads/archive:firmware/kk3-max/bluetooth/1.0.json",
            ],
            check=True,
            capture_output=True,
        ).stdout
        provenance = json.loads(metadata)
        self.assertEqual(provenance["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(provenance["size"], len(data))
        self.assertEqual(provenance["filename"], "one.zip")
        self.assertEqual(provenance["source"], "https://www.gulikit.com/product/123456")
        self.assertEqual(provenance["retrieved_at"], "2026-10-18T12:30:00Z")
        self.assertEqual(provenance["model"], "kk3-max")
        self.assertEqual(
            self.run_git(self.source_repo, "rev-parse", "HEAD"), self.source_head
        )
        self.assertEqual(self.run_git(self.source_repo, "status", "--porcelain"), "")

    def test_unsigned_identity_and_failed_signature_leave_ref_unchanged(self):
        with self.assertRaisesRegex(ValueError, "full GPG signing fingerprint"):
            self.import_one(self.zip1, "1", key=" ")
        with self.assertRaises(ValueError):
            self.import_one(self.zip1, "1", key="F" * 40)
        self.assertEqual(
            subprocess.run(
                ["git", f"--git-dir={self.archive}", "show-ref"], capture_output=True
            ).returncode,
            1,
        )

    def test_expected_hash_size_invalid_inputs_duplicates_and_path_traversal(self):
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            self.import_one(self.zip1, "x", size=0)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.import_one(self.zip1, "x", sha256="0" * 64)
        invalid = self.root / "invalid.zip"
        invalid.write_text("not zip")
        with self.assertRaisesRegex(ValueError, "valid ZIP"):
            self.import_one(invalid, "x")
        traversal = self.make_zip("traversal.zip", "../escape", b"bad")
        with self.assertRaisesRegex(ValueError, "unsafe ZIP"):
            self.import_one(traversal, "x")
        self.import_one(self.zip1, "x")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.import_one(self.zip2, "x")
        with self.assertRaisesRegex(ValueError, "invalid model"):
            firmware_archive.safe_segment("../bad", "model", lower=True)
        with self.assertRaisesRegex(ValueError, "official HTTPS"):
            firmware_archive.official_source("https://www.gulikit.com/product/123?x=1")

    def test_retrieved_at_requires_complete_utc_time(self):
        self.assertEqual(
            firmware_archive.validate_timestamp("2026-10-18T12:30:00Z"),
            "2026-10-18T12:30:00Z",
        )
        self.assertEqual(
            firmware_archive.validate_timestamp("2026-10-18T12:30:00.125Z"),
            "2026-10-18T12:30:00.125Z",
        )
        for timestamp in [
            "2026-10-18Z",
            "2026-10-18T12:30Z",
            "2026-10-18T12:30:00+00:00",
            "2026-02-30T12:30:00Z",
            "٢٠٢٦-10-18T12:30:00Z",
        ]:
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                firmware_archive.validate_timestamp(timestamp)

    def test_historical_pairs_are_revalidated_before_append(self):
        zip_path = "firmware/kk3-max/bluetooth/bad.zip"
        provenance_path = "firmware/kk3-max/bluetooth/bad.json"
        for case in (
            "malformed provenance",
            "size mismatch",
            "hash mismatch",
            "invalid ZIP",
        ):
            with self.subTest(case=case):
                archive = self.root / (case.replace(" ", "-") + ".git")
                self.init_archive(archive)
                root = self.import_one(self.zip1, "root", archive=archive)
                provenance_bytes = subprocess.run(
                    [
                        "git",
                        f"--git-dir={archive}",
                        "show",
                        f"{root}:firmware/kk3-max/bluetooth/root.json",
                    ],
                    check=True,
                    capture_output=True,
                ).stdout
                provenance = json.loads(provenance_bytes)
                provenance["version"] = "bad"
                provenance["zip"] = zip_path
                archive_bytes = self.zip1.read_bytes()
                if case == "size mismatch":
                    provenance["size"] += 1
                elif case == "hash mismatch":
                    provenance["sha256"] = "0" * 64
                elif case == "invalid ZIP":
                    archive_bytes = b"not a ZIP archive"
                    provenance["size"] = len(archive_bytes)
                    provenance["sha256"] = hashlib.sha256(archive_bytes).hexdigest()
                bad_provenance = (
                    json.dumps(provenance, sort_keys=True, indent=2) + "\n"
                ).encode()
                if case == "malformed provenance":
                    bad_provenance = b"{"
                # Add a new signed pair. Replacing the root pair would stop at
                # the earlier append-only check and never test content validation.
                updates = {zip_path: archive_bytes, provenance_path: bad_provenance}
                tip = self.append_signed_descendant(archive, root, updates, case)
                with self.assertRaisesRegex(ValueError, "provenance|size|SHA-256|ZIP"):
                    self.import_one(self.zip2, "next", archive=archive)
                self.assertEqual(
                    self.run_git(archive, "rev-parse", "refs/heads/archive"), tip
                )

    def test_zip_payload_crc_corruption_is_rejected(self):
        corrupt = self.root / "corrupt.zip"
        with zipfile.ZipFile(corrupt, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("firmware.bin", b"payload to corrupt")
        raw = corrupt.read_bytes().replace(b"payload to corrupt", b"payloAd to corrupt")
        corrupt.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "ZIP"):
            self.import_one(corrupt, "crc")
        nonempty_directory = self.make_zip("directory.zip", "dir/", b"unexpected")
        with self.assertRaisesRegex(ValueError, "directory records"):
            self.import_one(nonempty_directory, "directory")

    def test_hostile_git_environment_cannot_redirect_repository_or_index(self):
        with patch.dict(
            os.environ,
            {
                "GIT_DIR": str(self.source_repo / ".git"),
                "GIT_WORK_TREE": str(self.source_repo),
                "GIT_INDEX_FILE": str(self.root / "hostile-index"),
                "GIT_OBJECT_DIRECTORY": str(self.source_repo / ".git" / "objects"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "gpg.format",
                "GIT_CONFIG_VALUE_0": "ssh",
            },
            clear=False,
        ):
            self.import_one(self.zip1, "hostile")
        self.assertTrue((self.root / "hostile-index").exists() is False)
        self.assertEqual(
            self.run_git(self.source_repo, "rev-parse", "HEAD"), self.source_head
        )

    def test_replacement_and_unsigned_descendants_are_refused(self):
        first = self.import_one(self.zip1, "root")
        index = self.root / "rewrite-index"
        clean = {**self.gpg_env, "GIT_INDEX_FILE": str(index)}
        tree_lines = subprocess.run(
            ["git", f"--git-dir={self.archive}", "ls-tree", "-r", first],
            env={**os.environ, "GIT_CONFIG_COUNT": "0"},
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
        zip_line = next(
            line
            for line in tree_lines
            if line.endswith("firmware/kk3-max/bluetooth/root.zip")
        )
        zip_path = zip_line.split("\t", 1)[1]
        replacement_blob = (
            subprocess.run(
                ["git", f"--git-dir={self.archive}", "hash-object", "-w", "--stdin"],
                input=b"replacement",
                env=self.gpg_env,
                check=True,
                capture_output=True,
            )
            .stdout.decode()
            .strip()
        )
        subprocess.run(
            ["git", f"--git-dir={self.archive}", "read-tree", first],
            env=clean,
            check=True,
        )
        subprocess.run(
            [
                "git",
                f"--git-dir={self.archive}",
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{replacement_blob},{zip_path}",
            ],
            env=clean,
            check=True,
        )
        replacement_tree = subprocess.run(
            ["git", f"--git-dir={self.archive}", "write-tree"],
            env=clean,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        replacement = subprocess.run(
            [
                "git",
                f"--git-dir={self.archive}",
                "-c",
                "gpg.format=openpgp",
                "-c",
                f"user.signingkey={self.key}",
                "commit-tree",
                replacement_tree,
                "-p",
                first,
                "-S",
                "-m",
                "replace ZIP",
            ],
            env=self.gpg_env,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.run_git(
            self.root,
            "--git-dir",
            str(self.archive),
            "update-ref",
            "refs/heads/archive",
            replacement,
        )
        with self.assertRaisesRegex(ValueError, "replacement|deletion|rename"):
            self.import_one(self.zip2, "next")

        unsigned_archive = self.root / "unsigned.git"
        self.init_archive(unsigned_archive)
        signed_root = self.import_one(self.zip1, "root", archive=unsigned_archive)
        unsigned_tree = self.run_git(
            unsigned_archive, "rev-parse", f"{signed_root}^{{tree}}"
        )
        unsigned = subprocess.run(
            [
                "git",
                f"--git-dir={unsigned_archive}",
                "commit-tree",
                unsigned_tree,
                "-p",
                signed_root,
                "-m",
                "unsigned descendant",
            ],
            env=self.gpg_env,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.run_git(
            self.root,
            "--git-dir",
            str(unsigned_archive),
            "update-ref",
            "refs/heads/archive",
            unsigned,
        )
        with self.assertRaisesRegex(ValueError, "unsigned commit"):
            self.import_one(self.zip2, "next", archive=unsigned_archive)

    def test_merge_history_is_refused(self):
        first = self.import_one(self.zip1, "root")
        second = self.import_one(self.zip2, "second")
        tree = self.run_git(self.archive, "rev-parse", f"{second}^{{tree}}")
        merge = subprocess.run(
            [
                "git",
                f"--git-dir={self.archive}",
                "-c",
                "gpg.format=openpgp",
                "-c",
                f"user.signingkey={self.key}",
                "commit-tree",
                tree,
                "-p",
                first,
                "-p",
                second,
                "-S",
                "-m",
                "merge",
            ],
            env=self.gpg_env,
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.run_git(
            self.root,
            "--git-dir",
            str(self.archive),
            "update-ref",
            "refs/heads/archive",
            merge,
        )
        with self.assertRaisesRegex(ValueError, "linear|merges"):
            self.import_one(self.zip1, "third")

    def test_arbitrary_existing_source_history_is_rejected(self):
        self.run_git(
            self.root,
            "--git-dir",
            str(self.archive),
            "fetch",
            str(self.source_repo),
            self.source_head,
        )
        self.run_git(
            self.root,
            "--git-dir",
            str(self.archive),
            "update-ref",
            "refs/heads/archive",
            "FETCH_HEAD",
        )
        with self.assertRaisesRegex(ValueError, "archive root|marked firmware archive"):
            self.import_one(self.zip1, "1")

    def test_primary_fingerprint_pins_signing_subkey_across_appends(self):
        subprocess.run(
            [
                "gpg",
                "--homedir",
                str(self.gpg_home),
                "--batch",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Subkey Test <subkey@example.test>",
                "rsa2048",
                "cert",
                "0",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        listing = subprocess.run(
            [
                "gpg",
                "--homedir",
                str(self.gpg_home),
                "--batch",
                "--with-colons",
                "--list-secret-keys",
                "subkey@example.test",
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        primary = next(
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
        )
        subprocess.run(
            [
                "gpg",
                "--homedir",
                str(self.gpg_home),
                "--batch",
                "--passphrase",
                "",
                "--quick-add-key",
                primary,
                "rsa2048",
                "sign",
                "0",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.import_one(self.zip1, "subkey-one", key=primary)
        self.import_one(self.zip2, "subkey-two", key=primary)

        wrong_identity_archive = self.root / "wrong-identity.git"
        self.init_archive(wrong_identity_archive)
        original_tip = self.import_one(
            self.zip1, "wrong", archive=wrong_identity_archive, key=self.key
        )
        with self.assertRaisesRegex(ValueError, "another identity"):
            self.import_one(
                self.zip2, "wrong-two", archive=wrong_identity_archive, key=primary
            )
        self.assertEqual(
            self.run_git(wrong_identity_archive, "rev-parse", "refs/heads/archive"),
            original_tip,
        )

    def test_sha256_bare_archive_and_compare_and_swap_race(self):
        sha_archive = self.root / "sha256.git"
        self.init_archive(sha_archive, "--object-format=sha256")
        first = self.import_one(self.zip1, "1", archive=sha_archive)
        self.assertEqual(len(first), 64)
        self.assertEqual(
            self.run_git(
                sha_archive, "rev-list", "--parents", "-n", "1", first
            ).split(),
            [first],
        )

        starting_tip = first
        original_git = firmware_archive.git

        def race_ref(repo, *args, **kwargs):
            if args and args[0] == "update-ref":
                subprocess.run(
                    ["git", f"--git-dir={repo}", "update-ref", args[1], args[2]],
                    check=True,
                )
            return original_git(repo, *args, **kwargs)

        with (
            patch.dict(os.environ, {"GNUPGHOME": str(self.gpg_home)}),
            patch.object(firmware_archive, "git", race_ref),
        ):
            with self.assertRaises(ValueError):
                self.import_one(self.zip2, "2", archive=sha_archive)
        # A concurrent ref advance survives the failed expected-old update.
        self.assertNotEqual(
            self.run_git(sha_archive, "rev-parse", "refs/heads/archive"), starting_tip
        )

    def test_single_branch_clone_omits_archive_ref_while_ordinary_clone_fetches_it(
        self,
    ):
        archive_tip = self.import_one(self.zip1, "catalog")
        catalog_repo = self.root / "catalog.git"
        self.init_archive(catalog_repo, "--initial-branch=main")
        self.run_git(
            self.root,
            "--git-dir",
            str(catalog_repo),
            "fetch",
            str(self.source_repo),
            "main:refs/heads/main",
        )
        self.run_git(
            self.root,
            "--git-dir",
            str(catalog_repo),
            "fetch",
            str(self.archive),
            "refs/heads/archive:refs/heads/archive",
        )
        url = f"file://{catalog_repo}"
        full_clone = self.root / "full-clone"
        narrow_clone = self.root / "narrow-clone"
        subprocess.run(
            ["git", "clone", url, str(full_clone)], check=True, capture_output=True
        )
        subprocess.run(
            [
                "git",
                "clone",
                "--single-branch",
                "--branch",
                "main",
                "--no-tags",
                url,
                str(narrow_clone),
            ],
            check=True,
            capture_output=True,
        )
        self.assertEqual(
            self.run_git(full_clone, "rev-parse", "refs/remotes/origin/archive"),
            archive_tip,
        )
        absent = subprocess.run(
            ["git", "rev-parse", "--verify", "refs/remotes/origin/archive"],
            cwd=narrow_clone,
            capture_output=True,
        )
        self.assertNotEqual(absent.returncode, 0)
        self.assertEqual(
            self.run_git(narrow_clone, "rev-parse", "main"), self.source_head
        )


if __name__ == "__main__":
    unittest.main()
