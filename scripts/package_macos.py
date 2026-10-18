"""Package native macOS executables; release mode requires notarization."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "GuliKit Updater.app"


def run(*args):
    return subprocess.run(
        [str(arg) for arg in args], check=True, capture_output=True, text=True
    ).stdout


def check_binary(binary, arch):
    if run("/usr/bin/lipo", "-archs", binary).strip() != arch:
        raise ValueError(f"Wrong architecture: {binary}; expected {arch}")
    # A Nix/Homebrew path or unresolved @rpath would work on the builder only.
    dependencies = run("/usr/bin/otool", "-L", binary).splitlines()[1:]
    for line in dependencies:
        dependency = line.strip().split(" (", 1)[0]
        if not dependency.startswith(("/System/Library/", "/usr/lib/")):
            raise ValueError(f"Non-system dependency in {binary}: {dependency}")


def stage(binaries, destination, version, arch):
    app = destination / APP_NAME
    macos = app / "Contents" / "MacOS"
    helpers = app / "Contents" / "Helpers"
    macos.mkdir(parents=True)
    helpers.mkdir()
    for name, directory in [("gulikit-ui", macos), ("gulikit-updater", helpers)]:
        binary = binaries / name
        check_binary(binary, arch)
        shutil.copy2(binary, directory / name)
        (directory / name).chmod(0o755)
    with (app / "Contents" / "Info.plist").open("wb") as file:
        plistlib.dump(
            {
                "CFBundleExecutable": "gulikit-ui",
                "CFBundleIdentifier": "lol.mjc.gulikit-updater",
                "CFBundleName": "GuliKit Updater",
                "CFBundleDisplayName": "GuliKit Updater",
                "CFBundlePackageType": "APPL",
                "CFBundleShortVersionString": version,
                "CFBundleVersion": version,
                "LSMinimumSystemVersion": "12.0",
                "NSHighResolutionCapable": True,
            },
            file,
        )
    return app


def sign(app, identity, keychain=None):
    options = ["--force", "--options", "runtime", "--sign", identity]
    options += ["--timestamp=none"] if identity == "-" else ["--timestamp"]
    if keychain:
        options += ["--keychain", keychain]
    # Sign inside out. --deep is for verification, never for signing.
    run("/usr/bin/codesign", *options, app / "Contents/Helpers/gulikit-updater")
    run("/usr/bin/codesign", *options, app)
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app)


def smoke(app):
    for binary, expected in [
        (app / "Contents/MacOS/gulikit-ui", "Usage: gulikit-ui"),
        (app / "Contents/Helpers/gulikit-updater", "Usage:"),
    ]:
        if expected not in run(binary, "--help"):
            raise ValueError(f"Packaged executable did not print help: {binary}")


def archive(app, path):
    run("/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", app, path)


def release(app, output, name, identity, profile, keychain):
    final = output / f"{name}.zip"
    if final.exists():
        raise FileExistsError(final)
    if not identity.startswith("Developer ID Application:"):
        raise ValueError("A Developer ID Application identity is required")
    security_args = [keychain] if keychain else []
    if f'"{identity}"' not in run(
        "/usr/bin/security", "find-identity", "-v", "-p", "codesigning", *security_args
    ):
        raise ValueError("Developer ID Application identity/private key is unavailable")
    credentials = ["--keychain-profile", profile]
    if keychain:
        credentials += ["--keychain", keychain]
    sign(app, identity, keychain)
    smoke(app)
    submission = app.parent / "notary-submission.zip"
    archive(app, submission)
    # notarytool can return success for a completed but rejected submission.
    submit_error = None
    try:
        response_text = run(
            "/usr/bin/xcrun",
            "notarytool",
            "submit",
            submission,
            *credentials,
            "--wait",
            "--timeout",
            "30m",
            "--output-format",
            "json",
        )
    except subprocess.CalledProcessError as error:
        # Some notarytool versions return a nonzero exit with an Invalid JSON
        # response. Preserve its submission ID/log as well as rejecting it.
        if not error.stdout:
            raise
        response_text = error.stdout
        submit_error = error
    response = json.loads(response_text)
    (output / f"{name}-notary.json").write_text(json.dumps(response, indent=2) + "\n")
    log = run("/usr/bin/xcrun", "notarytool", "log", response["id"], *credentials)
    (output / f"{name}-notary-log.json").write_text(log)
    if submit_error or response.get("status") != "Accepted":
        raise ValueError(f"Notarization was not accepted: {response.get('status')}")
    run("/usr/bin/xcrun", "stapler", "staple", app)
    run("/usr/bin/xcrun", "stapler", "validate", app)
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", app)
    run("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", app)
    # Archive again after stapling; the submission ZIP has no stapled ticket.
    candidate = app.parent / f"{name}.zip"
    archive(app, candidate)
    extracted = app.parent / "extracted"
    run("/usr/bin/ditto", "-x", "-k", candidate, extracted)
    packaged = extracted / APP_NAME
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", packaged)
    run("/usr/bin/xcrun", "stapler", "validate", packaged)
    run("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", packaged)
    smoke(packaged)
    shutil.copy2(candidate, final)
    digest = hashlib.sha256(final.read_bytes()).hexdigest()
    (output / f"{name}.zip.sha256").write_text(f"{digest}  {final.name}\n")
    print(f"Signed, notarized and verified: {final}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["smoke", "release"])
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/distribution")
    parser.add_argument("--arch", choices=["arm64", "x86_64"], required=True)
    parser.add_argument("--identity", default=os.environ.get("MACOS_SIGNING_IDENTITY"))
    parser.add_argument("--notary-profile")
    parser.add_argument("--keychain")
    args = parser.parse_args()
    if args.mode == "release" and (not args.identity or not args.notary_profile):
        parser.error("release requires --identity and --notary-profile")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        parser.error("macOS bundle version must have three numeric components")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output) as temporary:
        app = stage(args.binaries.resolve(), Path(temporary), version, args.arch)
        if args.mode == "smoke":
            sign(app, "-")
            smoke(app)
            print("Local ad-hoc packaging smoke passed; no release artifact produced")
        else:
            name = f"gulikit-updater-{version}-macos-{args.arch}"
            release(
                app,
                args.output.resolve(),
                name,
                args.identity,
                args.notary_profile,
                args.keychain,
            )


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout, file=sys.stderr)
        print(error.stderr, file=sys.stderr)
        raise SystemExit(error.returncode) from error
