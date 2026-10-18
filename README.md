# GuliKit updater

Desktop distribution build and signing instructions are in
[scripts/README.md](scripts/README.md).

Updater for the GuliKit KK3 Max (NS39), with two separate executables:

- `gulikit-updater` — command-line updater.
- `gulikit-ui` — Slint desktop app.

Native device access currently supports macOS. Windows and Linux support
package inspection and the UI demo; their device adapters are unfinished.

Reviewed packages: Main 5.9 and Bluetooth 3.23, 3.24 and 5.07. The original ZIP
selects the release. Bluetooth 3.23 → 3.24 → 3.23 has been verified on hardware;
an eligible Main update through this CLI still needs hardware acceptance.

## Run

From the repository root, enter the development environment once:

```sh
devenv shell
cargo run -p gulikit-ui --bin gulikit-ui
```

The desktop app can inspect the controller and firmware packages on macOS.
**Native desktop updates are disabled.** Add `-- --demo` to use an in-memory
device through the same UI callbacks and worker, without USB, files or dialogs:

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

## Compare firmware changes

Open **Changelog** in the desktop app, choose Main or Bluetooth, and enter the
**From version** and **To version**. This works before connecting a controller.
The same comparison is available in the CLI:

```sh
cargo run --bin gulikit-updater -- changelog --component bluetooth --from 3.23 --to 5.07
```

Add `--json` for structured notes and source links. Upgrades show recorded changes
after From through To; downgrades show the changes removed, in reverse order.
The history includes intermediate releases even when their packages are not
available for installation. Historical notes may be incomplete; an empty interval
does not prove there were no firmware changes. Version selection is manual.

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
