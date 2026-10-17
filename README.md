# GuliKit updater

The first implementation slice inspects the reviewed KK3 Max NS39 Main 5.9
and Bluetooth 5.07 packages offline. It does not flash a controller. Native
inspection, transfer and post-restart verification remain tracked work.

## Development

Use the pinned native devenv from this directory:

```sh
devenv shell
cargo run -- packages
cargo run -- package inspect /path/to/KK3_NS38_NS39_V5.9.zip --model kk3-max --component main
cargo run -- package inspect /path/to/GuliKit_NS38_NS39_NS59_BT_V5.07.zip --model kk3-max --component bluetooth --json
devenv tasks run check:all
```

The shell pins Rust 1.98.1 and supplies nextest, Python and uv. On a machine
without Nix, install the toolchain specified in `rust-toolchain.toml` and use
the same Cargo commands. Shell activation does not install application
dependencies or run checks. `Cargo.lock` and `devenv.lock` pin resolved inputs.

The inspector checks the complete original archive digest before parsing it,
then checks the selected member and payload. Bluetooth extraction uses a PE
parser; it never executes the Windows updater. The Main archive also contains
an NS38 binary, which is never selected for NS39. Repacked archives and unknown
releases are rejected. A digest match ties the bytes to the reviewed catalog;
it does not independently establish publisher authenticity.

`--json` produces schema version 1. Successful package information goes to
stdout; runtime errors go to stderr with an empty stdout. Exit codes are 0 for
successful offline inspection, 2 for command-line usage, 3 for rejected firmware,
and 4 for file/output I/O failures. No code in this slice claims installation
success or reads an installed version.

## Tests

```sh
cargo nextest run --workspace --all-features
cargo test --workspace --doc --all-features
```

Original vendor archives stay outside Git. To run the three explicit archive
acceptance tests, put the two original ZIPs in the ignored
`artifacts/vendor/kk3/packages/` cache or set `GULIKIT_VENDOR_DIR`:

```sh
cargo test -p gulikit-core --test vendor_packages -- --ignored
```

These tests check exact payload selection/extraction and altered-archive
rejection. They never connect to USB. CI runs the portable behavioral suite;
the archive tests require separately supplied vendor downloads.

## Source boundaries

`gulikit-core` owns reviewed package metadata, validation, physical-controller
grouping/selection and BOT framing/status parsing. `gulikit-platform` owns
bounded host-file I/O. The CLI parses arguments and renders core results. The
same core can serve Slint, and native adapters can provide each OS's discovery,
SCSI command and update-volume operations without duplicating firmware policy.

Main and Bluetooth access may be available together on one NS39. Selection
counts physical controllers, requires both component accesses on the same
target and refuses more than one device in update mode. A shared Bluetooth
protocol signature is not an NS39 model identifier. Native discovery must
correlate the Main volume and BT command path and recheck uniqueness before
any future write. The current CLI exposes package commands only.

The [CLI execution plan](https://lific.mjc.lol/GULI/plans/141) and
[architecture](https://lific.mjc.lol/GULI/pages/252) hold the delivery scope.
[Research commands](research/README.md) reproduce the preserved official-code
baseline. The existing `mockups/` directory is a separate simulated UI study.
