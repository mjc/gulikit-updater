# GuliKit updater

The updater supports the reviewed KK3 Max NS39 Main 5.9 and Bluetooth 5.07
packages. The shared Rust core implements both component transactions and
restart verification. Native macOS discovery and Main version inspection work;
native firmware writes remain gated while transport and filesystem hardware
qualification is in progress. The current controller reports Main 5.9, which
correctly returns `already_current` with zero firmware writes.

## Development

Use the pinned native devenv from this directory:

```sh
devenv shell
cargo run -- packages
cargo run -- package inspect /path/to/KK3_NS38_NS39_V5.9.zip --model kk3-max --component main
cargo run -- package inspect /path/to/GuliKit_NS38_NS39_NS59_BT_V5.07.zip --model kk3-max --component bluetooth --json
cargo run -- devices --json
cargo run -- probe --component main --confirm-ns39 --json
cargo run -- update /path/to/KK3_NS38_NS39_V5.9.zip --model kk3-max --component main --confirm-ns39 --record ./main-attempt.jsonl --json
cargo run -- verify ./main-attempt.jsonl --record ./main-verification.jsonl --confirm-ns39 --confirm-same-controller --json
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

`--json` produces schema version 1. Package information and completed attempt or
verification records go to stdout. An attempt can report refusal, uncertainty or
cleanup failure and still produce its structured record there. Errors before a
result can be recorded go to stderr with an empty stdout. Exit codes are 0 for
successful inspection, an already-current component, or verified installation;
2 for command-line usage; 3 for rejected firmware; 4 for package/output I/O;
5 for device/preflight refusal; 7 for a transfer awaiting completion or restart
verification; 8 for cleanup or host audit persistence that requires attention;
and 9 for an uncertain outcome after firmware submission.

Put only one controller in update mode. `--confirm-ns39` attests that you checked
the physical NS39 label and Max controls. USB IDs and the shared F1 signature
are observed profile evidence, not automatic proof of the model. The native
adapter checks runtime support for modern IOUSBHost and DeviceSurrender.
`probe --component bluetooth` normally unmounts the controller volume before
requesting modern Capture. Read-only cleanup explicitly destroys the capture,
which resets USB and restarts driver matching; restored storage is checked
separately. A busy volume refuses without forcing an unmount. After any possible
firmware submission, cleanup uses no-reset DeviceSurrender and reports storage
restoration pending, including after final F2 success. No firmware replay or
automatic reset is used after submission. Other OSes currently support package commands.

Each update uses one original, verified package and creates an exclusive host
attempt record outside the controller volume. Operation submission, actual
results, raw version bytes and cleanup results are persisted as JSON lines.
An incomplete record preserves an interrupted attempt; it does not prove a
transfer completed. Equal, newer and unknown installed versions write nothing;
there is no force, reinstall or downgrade option. Main copying and raw Bluetooth
traffic are serialized. A topology change invalidates the active session.

Transfer completion is separate from installation verification. Main installation
finishes with the controller automatically restarting; its own detach is observed
without manually unmounting it. After a completed Bluetooth transfer, power the
controller off and on normally. Re-enter update mode if needed for fresh readback. `verify` requires a fresh version read on a new attachment plus explicit
confirmation of the same physical controller. No USB serial is available, so
this assisted association is recorded separately from the machine-read version.
The required `verify --record` creates a new exclusive host record linking the
original attempt to fresh raw readback, attachment provenance, cleanup and outcome.
It preserves the original attempt; failed persistence requires attention.
Final F2, a host copy, a matching port or a different already-current controller
cannot establish that the original attempt installed successfully. Unknown or
pending outcomes never cause automatic recopy, resend, deletion, erase or recovery.

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
grouping/selection, component version policy, transaction sequencing, outcomes,
restart association and BOT framing/status parsing. `gulikit-platform` owns
bounded host-file I/O, directory-relative exclusive creation, audit persistence,
native discovery, topology watching and exclusive resource ownership. A small
Objective-C bridge uses the shipped Apple USB/registry APIs; it contains no
firmware compatibility or transfer policy. The CLI parses arguments and renders core results. The
same core can serve Slint, and native adapters can provide each OS's discovery,
SCSI command and update-volume operations without duplicating firmware policy.

Main and Bluetooth access may be available together on one NS39. Native discovery
reports a `bluetooth_transport_candidate` when it correlates a suitable command
interface; that alone does not prove the Windows updater would select this storage
identity or that F1 succeeds. A fresh complete F1 response remains required. Selection
counts physical controllers, requires both component accesses on the same
target and refuses more than one device in update mode. A shared Bluetooth
protocol signature is not an NS39 model identifier. Native discovery must
correlate the Main volume and BT command path and recheck uniqueness before
any write. Both native write adapters refuse before firmware submission until
their hardware qualification gates are satisfied. Portable tests and mocked
official-instruction traces do not establish actual-device flash acceptance.

The [CLI execution plan](https://lific.mjc.lol/GULI/plans/141) and
[architecture](https://lific.mjc.lol/GULI/pages/252) hold the delivery scope.
[Research commands](research/README.md) reproduce the preserved official-code
baseline. The existing `mockups/` directory is a separate simulated UI study.
