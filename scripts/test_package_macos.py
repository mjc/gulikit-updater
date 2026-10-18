"""Exercise real bundles/signatures with tiny native executables, without USB."""

import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import package_macos as package


@unittest.skipUnless(platform.system() == "Darwin", "requires macOS signing tools")
class MacPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binaries = self.root / "bin"
        self.binaries.mkdir()
        source = self.root / "help.c"
        source.write_text(
            '#include <stdio.h>\nint main(void) { puts("Usage: gulikit-ui"); }\n'
        )
        self.compiler = os.environ.get("CC", "cc")
        for name in ["gulikit-ui", "gulikit-updater"]:
            package.run(self.compiler, source, "-o", self.binaries / name)
        self.arch = platform.machine()

    def stage(self):
        return package.stage(self.binaries, self.root / "bundle", "0.1.0", self.arch)

    def test_signed_bundle_survives_archive_extraction_and_executes(self):
        app = self.stage()
        package.sign(app, "-")
        archive = self.root / "package.zip"
        package.archive(app, archive)
        extracted = self.root / "consumer folder"
        package.run("/usr/bin/ditto", "-x", "-k", archive, extracted)
        consumer = extracted / package.APP_NAME
        package.run("/usr/bin/codesign", "--verify", "--deep", "--strict", consumer)
        package.smoke(consumer)
        with (consumer / "Contents/Info.plist").open("rb") as file:
            info = plistlib.load(file)
        self.assertTrue(
            (consumer / "Contents/MacOS" / info["CFBundleExecutable"]).is_file()
        )
        self.assertEqual(info["CFBundleShortVersionString"], "0.1.0")

    def test_tampered_nested_cli_fails_signature_verification(self):
        app = self.stage()
        package.sign(app, "-")
        with (app / "Contents/Helpers/gulikit-updater").open("ab") as file:
            file.write(b"modified after signing")
        with self.assertRaises(subprocess.CalledProcessError):
            package.run("/usr/bin/codesign", "--verify", "--deep", "--strict", app)

    def test_wrong_architecture_is_refused(self):
        wrong_arch = "x86_64" if self.arch == "arm64" else "arm64"
        with self.assertRaisesRegex(ValueError, "Wrong architecture"):
            package.stage(self.binaries, self.root / "bundle", "0.1.0", wrong_arch)

    def test_builder_only_library_is_refused(self):
        library = self.root / "builder-only.dylib"
        source = self.root / "library.c"
        source.write_text("int builder_only(void) { return 0; }\n")
        package.run(self.compiler, "-dynamiclib", source, "-o", library)
        source.write_text(
            "int builder_only(void); int main(void) { return builder_only(); }\n"
        )
        package.run(self.compiler, source, library, "-o", self.binaries / "gulikit-ui")
        with self.assertRaisesRegex(ValueError, "Non-system dependency"):
            self.stage()

    def test_development_certificate_cannot_produce_a_release(self):
        for identity in ["-", "Apple Development: Example (TEAM)"]:
            with self.subTest(identity=identity):
                with self.assertRaisesRegex(ValueError, "Developer ID Application"):
                    package.release(
                        self.root, self.root, "release", identity, "profile", None
                    )
        self.assertFalse((self.root / "release.zip").exists())

    def test_rejected_notarization_retains_log_without_publishing_zip(self):
        self.check_rejected_notarization(nonzero_exit=False)

    def test_failed_notarytool_retains_rejected_submission_log(self):
        self.check_rejected_notarization(nonzero_exit=True)

    def check_rejected_notarization(self, nonzero_exit):
        app = self.stage()
        identity = "Developer ID Application: Example (TEAM)"
        real_run = package.run

        def fake_apple_service(*args):
            if args[0] == "/usr/bin/security":
                return f'1) HASH "{identity}"\n'
            if args[0:3] == ("/usr/bin/xcrun", "notarytool", "submit"):
                response = json.dumps({"id": "request-id", "status": "Invalid"})
                if nonzero_exit:
                    raise subprocess.CalledProcessError(65, args, output=response)
                return response
            if args[0:3] == ("/usr/bin/xcrun", "notarytool", "log"):
                return '{"issues": ["signature rejected"]}'
            return real_run(*args)

        with (
            patch.object(package, "run", side_effect=fake_apple_service),
            patch.object(package, "sign"),
            self.assertRaisesRegex(ValueError, "not accepted"),
        ):
            package.release(app, self.root, "release", identity, "profile", None)
        self.assertFalse((self.root / "release.zip").exists())
        self.assertIn(
            "signature rejected", (self.root / "release-notary-log.json").read_text()
        )


if __name__ == "__main__":
    unittest.main()
