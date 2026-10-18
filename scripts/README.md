# Desktop distribution builds

The manual **Distribution builds** GitHub Actions workflow builds the desktop app
and CLI from the selected revision. It produces separate macOS Apple Silicon,
macOS Intel and Windows x64 ZIPs with SHA-256 files. It does not publish a release
or create a tag. Use the ZIP inside the downloaded Actions artifact.
The macOS package requires macOS 12 or later, matching the native adapter's
existing IOKit API use.

macOS releases require a **Developer ID Application** certificate/private key,
hardened runtime, secure timestamps and accepted Apple notarization. The workflow
signs the nested CLI and app, notarizes the app, staples its ticket, then creates
the final ZIP. It extracts that ZIP and repeats signature, ticket, Gatekeeper and
executable checks before uploading. It refuses development/ad-hoc identities and
failed notarization. No sandbox or debug entitlement is added.

Configure these repository secrets before running the workflow:

| Secret                         | Value                                                                         |
| ------------------------------ | ----------------------------------------------------------------------------- |
| `MACOS_CERTIFICATE_P12_BASE64` | Base64 export of the Developer ID Application certificate and its private key |
| `MACOS_CERTIFICATE_PASSWORD`   | Password for that PKCS#12 export                                              |
| `MACOS_SIGNING_IDENTITY`       | Exact `Developer ID Application: Name (TEAMID)` identity                      |
| `APPLE_ID`                     | Apple account authorized for notarization                                     |
| `APPLE_TEAM_ID`                | Team that owns the signing identity                                           |
| `APPLE_APP_PASSWORD`           | App-specific password for notarization                                        |

Credentials go into a temporary runner keychain after compilation. The workflow
deletes the keychain and certificate file even if packaging fails. Signing never
runs on pull requests. Notarization responses/logs are retained as diagnostics.
Use a full Xcode developer directory for `notarytool` and `stapler`; the Nix SDK
alone does not include those tools.

For local builds on nix-darwin, enter this repository's `devenv shell` first (or
run directly when `DEVENV_ROOT` already matches this checkout):

```sh
bash scripts/build_macos.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  python3 scripts/package_macos.py smoke --binaries target/release --arch "$(uname -m)"
```

`smoke` checks native architecture and system-only linkage, builds a temporary
ad-hoc signed app and runs both packaged help commands. It creates no distributable
ZIP and establishes no Developer ID, notarization or Gatekeeper acceptance.
The build script keeps devenv's Rust toolchain and selects Apple's compiler,
linker and SDK so the executable has no Nix/Homebrew runtime dependencies. Set
`DEVELOPER_DIR_OVERRIDE` if full Xcode is installed at a different location.
For a signed local release, use `release` with `--identity`, `--notary-profile`
and optionally `--keychain` after storing notarization credentials with
`xcrun notarytool store-credentials`. The bundled CLI is at
`GuliKit Updater.app/Contents/Helpers/gulikit-updater`.

The local release command also accepts an existing App Store Connect API key,
including one materialized as a temporary file by SecretSpec. Supply
`--notary-key PATH --notary-key-id ID` and, for a team key, `--notary-issuer ID`
instead of `--notary-profile`. The equivalent environment names are
`APPLE_NOTARY_KEY_PATH`, `APPLE_NOTARY_KEY_ID` and `APPLE_NOTARY_ISSUER_ID`.
Have the existing secrets loader inject them only into the packaging process;
never export private-key contents to the terminal or copy them into the repository.
This path uses the API key directly for submission and log retrieval without
storing another notarization password/profile. Developer ID signing still uses
the selected signing identity and optional keychain.

Windows builds use the MSVC x64 target with `RUSTFLAGS=-C target-feature=+crt-static`.
In a Visual Studio developer PowerShell:

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo build --release --workspace --bins --locked --target x86_64-pc-windows-msvc
./scripts/package_windows.ps1 -Binaries target/x86_64-pc-windows-msvc/release
```

The packaging script checks unsigned x64 PE files and DLL imports, rejects Visual
C++ redistributable dependencies, extracts the ZIP, runs both help commands with
a system-only PATH, and opens/closes the demo window. This checks executable launch
without USB access. Native Windows controller access remains tracked in GULI-12.

Unsigned Windows downloads can show **Windows protected your PC** / **Unknown
publisher**. Where permitted, **More info → Run anyway** continues to the app.
Smart App Control and organization policies can block unsigned apps entirely;
packaging cannot guarantee a bypass. See [Microsoft's SmartScreen guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).
Extract the whole ZIP before launching `gulikit-ui.exe`.

CI launch checks do not reproduce a browser download's quarantine or Windows
Mark of the Web. Final acceptance still requires downloading the exact ZIP on a
clean target OS, checking its SHA-256 and opening the extracted app through Finder
or Explorer. Record OS version, artifact/hash and observed prompts in GULI-38.
On macOS, also open the notarized app offline to check the stapled ticket. Do not
remove quarantine or disable platform protections to make that check pass.

Apple's [notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
and [custom workflow guide](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
describe the distribution checks used here.
