# GuliKit updater

Desktop distribution build and signing instructions are in
[scripts/README.md](scripts/README.md).

Updater for the GuliKit KK3 Max (NS39), with two separate executables:

- `gulikit-updater` — command-line updater.
- `gulikit-ui` — Slint desktop app.

Native device access currently supports macOS. Windows and Linux support
package inspection and the UI demo; their device adapters are unfinished.

The GUI selects KK3 Max main and Bluetooth packages from the firmware archive.
The CLI's compiled catalog contains Main 5.9 and Bluetooth 3.23, 3.24 and 5.07.
Bluetooth 3.23 → 3.24 → 3.23 has been verified on hardware;
an eligible Main update through this CLI still needs hardware acceptance.

## Run

From the repository root, enter the development environment once:

```sh
devenv shell
cargo run -p gulikit-ui --bin gulikit-ui
```

On macOS, the desktop app inspects the controller, checks the selected firmware
ZIP and updates either component. It saves a host operation record and requires
a fresh version read after restart before showing the update as verified.
Its firmware browser loads the repository's `firmware` branch, lists archived
KK3 Max main and Bluetooth versions, and downloads complete original ZIPs into
the application's cache. Select a version and original filename, then use
**Download and inspect**. Release notes, source links and measured hashes are
available beside the selection. A cached index and previously verified ZIPs
remain usable offline; **Refresh** checks for newly archived releases.

The selected KK3 Max record pins the archive revision, ZIP, member and payload
hashes, target version and parser. The app rechecks the file before transfer.
Other products and unknown firmware formats remain download-only. A lower
target version requires **Allow downgrade** for that attempt; equal and unknown
installed versions remain blocked. Same-version ZIP variants remain distinct
archive selections, although version readback cannot distinguish their bytes.

On macOS, the app requests administrator authorization at launch for native USB
access. Cancelling the system dialog exits before opening a controller. Demo
mode does not request authorization. Native GUI updates still need hardware
acceptance.

Add `-- --demo` to use an in-memory device through the same UI callbacks and
worker, without USB, files or dialogs:

```sh
cargo run -p gulikit-ui --bin gulikit-ui -- --demo
```

The CLI lists supported releases and checks original firmware ZIPs without
accessing a controller. It accepts only original ZIPs matching the reviewed hashes:

```sh
cargo run --bin gulikit-updater -- packages
cargo run --bin gulikit-updater -- package inspect /path/to/KK3_NS38_NS39_V5.9.zip --model kk3-max --component main
cargo run --bin gulikit-updater -- --help
```

## Update with the CLI on macOS

Use one controller, check its NS39 label and Max controls, and select the correct
component. **Main and Bluetooth use different entry and restart procedures.**
Start with the controller off and connect a USB data cable. Use the rightmost
**A** button in the default Switch layout; check the mapping if it was changed.

| Component | Enter update mode                                                                                | After a completed transfer                                                              |
| --------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| Main      | Hold **APS** (double-square, called APG by the vendor), then press **A** while keeping APS held. | Wait for automatic power-off and the GuliKit drive to disappear, then turn on normally. |
| Bluetooth | Hold **Gear / Set** first, then press **A** while keeping Gear held.                             | Turn on normally once, then off before re-entering Bluetooth update mode for readback.  |

To switch components, leave the current mode with Mode off → normal on, then
turn off and enter the other mode. Inspect again after each transition.

To inspect the Bluetooth version and start an update to 3.24:

```sh
cargo run --bin gulikit-updater -- probe --component bluetooth --confirm-ns39 --json
cargo run --bin gulikit-updater -- update /path/to/NS38_NS39_BT_V3.24.zip --model kk3-max --component bluetooth --confirm-ns39 --record ./bt-attempt.jsonl --json
```

Keep operation records on the host, outside the controller volume. Equal or
unknown installed versions are not written. A downgrade requires
`update --allow-downgrade`; it retains the package, model and session checks.

A completed transfer still needs a fresh version read on the same physical
controller after restart. Re-enter the selected update mode, then create a
separate verification record:

```sh
cargo run --bin gulikit-updater -- verify ./bt-attempt.jsonl --record ./bt-verification.jsonl --confirm-ns39 --confirm-same-controller --json
```

After a partial or unknown outcome, keep USB connected and leave the controller
unchanged. Do not restart, reset, retry, resume, inspect or verify until recovery
has been qualified for that interrupted state. Opening a record cannot resume
an update.

`--json` uses schema version 1. Operation results go to stdout; errors before a
result can be recorded go to stderr. Exit codes: 0 success/already current,
2 usage, 3 rejected package, 4 host I/O, 5 device/preflight refusal,
7 awaiting verification, 8 cleanup/audit attention, 9 uncertain submission.

## Maintain the firmware archive

`gulikit-archive` stores complete original firmware ZIPs in an isolated bare Git
repository. Its `firmware` branch starts with an orphan commit; each import adds
one release in a GPG-signed commit. Configure Git's author and OpenPGP signing
key before importing. The repository contains `/firmware.json` and paths such as
`/kk3-max/bluetooth/v3.24/NS38_NS39_BT_V3.24.zip`.

Archive commands disable repository-controlled Git hooks. Commit signature checks use the operator's local GPG keyring. Choose the archive
remote and revision separately; a valid commit signature is not manufacturer
authentication. No project firmware signing keys or signer registry is required.

Create a metadata JSON file for each original ZIP:

```json
{
  "component": "bluetooth",
  "version": "3.24",
  "filename": "NS38_NS39_BT_V3.24.zip",
  "source_url": "https://www.gulikit.com/newsinfo/915900.html",
  "released_at": "2024-09-06",
  "changelog": "Fixed vibration not stopping in a wired Switch-mode connection to a PC.",
  "changelog_source_url": "https://www.gulikit.com/newsinfo/915900.html",
  "firmware_member": "GuliKit_NS38_NS39_BT_V3.24.exe"
}
```

Use `base` for the controller's main firmware. Keep the manufacturer's original
ZIP filename and record the actual download URL in `retrieved_from` and its UTC
timestamp in `retrieved_at` when known. Missing dates and release notes remain
null. A community mirror's URL records that provenance; a locally measured
hash does not authenticate it as a manufacturer download.

```sh
cargo run -p gulikit-archive -- init /path/to/new-archive.git
cargo run -p gulikit-archive -- import /path/to/new-archive.git /path/to/NS38_NS39_BT_V3.24.zip --metadata /path/to/release.json
cargo run -p gulikit-archive -- list /path/to/new-archive.git
cargo run -p gulikit-archive -- read /path/to/new-archive.git --path /kk3-max/bluetooth/v3.24/NS38_NS39_BT_V3.24.zip --output /path/to/new-output.zip
```

The index always records size and SHA-256 for the complete ZIP and the selected
`firmware_member` file. Existing KK3 Max records also contain the payload digest:
base firmware is a BIN, and Bluetooth firmware is read from the reviewed PE32
layout without executing the Windows updater. An unrecognized image or
mismatched embedded version is refused.

For other products, set `product` to a stable lowercase slug and `member_kind`
to `raw_binary` for a BIN or `opaque_updater_exe` for an updater whose embedded
payload has not been parsed. Raw BIN records include their payload digest;
opaque updater records omit it rather than claiming the EXE is the firmware
payload. Each record selects one product, component and actual member version.
A ZIP shared by several products is preserved intact at each applicable path.
For example, the shared KK3 package contains Max 5.9 and Pro 5.8; TT packages
contain separate base and Bluetooth versions. Adding those records preserves
all earlier KK3 Max metadata and ZIPs.

`published_hashes` retains any publisher-provided checksums with `target`
(`zip`, `firmware_file`, or `payload`), `algorithm`, `value`, and `source_url`.
It is an empty list when no published checksums were found. SHA-256 claims are
compared with the measured content; other algorithms are retained as sourced
claims. These claims remain separate from the locally computed SHA-256 values.

Imports validate ZIP members without extracting or executing them. Existing releases cannot be
replaced, and readback verifies the stored bytes before creating a new output
file. Select the full index path for readback: a version can have multiple
original ZIPs, such as 5.1 and its later FIX package, under the same version
directory. Archive storage is separate from the updater's reviewed-package checks;
adding an archive does not make that version eligible for installation.

## Development

The devenv pins the Rust toolchain and installs treefmt and strict Clippy commit
hooks. Without Nix, use `rust-toolchain.toml` and the same Cargo commands.

Build either binary independently:

```sh
cargo build --release --bin gulikit-updater
cargo build --release -p gulikit-ui --bin gulikit-ui
```

Run checks and UI tests:

```sh
devenv tasks run check:all
cargo test -p gulikit-ui
```

UI tests use Slint's headless backend. The normal suite needs no controller or
desktop session. Vendor-package tests require the original ZIPs in the ignored
`artifacts/vendor/kk3/packages/` directory, or a directory set by
`GULIKIT_VENDOR_DIR`:

```sh
cargo test -p gulikit-core --test vendor_packages -- --ignored
```

[Mockups](mockups/README.md) and [offline research tools](research/README.md)
have separate run instructions. Protocol details, hardware evidence and remaining
work live in the [NS39 guide](https://lific.mjc.lol/GULI/pages/242) and
[delivery plan](https://lific.mjc.lol/GULI/plans/141).
