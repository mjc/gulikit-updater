# GuliKit updater

The updater supports the reviewed KK3 Max NS39 Main 5.9 and Bluetooth 5.07
packages. The shared Rust core implements both component transactions and
restart verification. The macOS Bluetooth adapter permits a transaction only after
fresh F1 identity/version readback on an exclusively held, qualified LUN0 session.
The NS39 has passed real read-only Bluetooth qualification and reports 3.23;
actual transfer and post-restart 5.07 verification are still pending. Main version
inspection works and reports 5.9, correctly returning `already_current` with zero
firmware writes. Main writes remain gated pending bounded filesystem supervision.

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
2 for command-line usage; 3 for rejected firmware; 4 for package, host-record, or output I/O;
5 for device/preflight refusal; 7 for a transfer awaiting completion or restart
verification; 8 for cleanup or host audit persistence that requires attention;
and 9 for an uncertain outcome after firmware submission.

KK3 Max NS39 has separate update modes. Main firmware uses **APS + A** (the
double-square button, called APG in some vendor instructions); Bluetooth firmware
uses **Gear / Set + A**. Start with the controller off and connect a USB data
cable. For Bluetooth, hold Gear first, keep it held, then press A. To switch
components, leave the current mode with Mode off and a normal Mode-on restart,
then power off and enter the other component's update mode. Rediscover after
each transition. The updater does not switch modes automatically.

Put only one controller in update mode. `--confirm-ns39` attests that you checked
the physical NS39 label and Max controls. USB IDs and the shared F1 signature
are observed profile evidence, not automatic proof of the model. The native
adapter checks runtime support for modern IOUSBHost and DeviceSurrender.
`probe --component bluetooth` unmounts any correlated mounted volumes before
requesting modern Capture. Read-only cleanup explicitly destroys the capture,
which resets USB and restarts driver matching; restored storage is checked
separately. A busy volume refuses without forcing an unmount. After any possible
firmware submission, cleanup uses no-reset DeviceSurrender and reports storage
restoration pending, including after final F2 success. No firmware replay or
automatic reset is used after submission. Other OSes currently support package commands.

Each update uses one original, verified package and creates an exclusive host
attempt record outside the controller volume. Operation submission, actual
results, raw version bytes and cleanup results are persisted as JSON lines.
If cancellation or audit failure follows successful Main destination creation but
precedes payload submission, the result records `destination_created_without_payload`
and `main_destination_created`, with zero firmware bytes submitted and exit 8.
The file remains for inspection; another attempt cannot silently overwrite it.
An incomplete record preserves an interrupted attempt; it does not prove a
transfer completed. Equal and unknown installed versions write nothing. A newer installed version
refuses by default; `update --allow-downgrade` explicitly permits installing the
selected older reviewed release. The record retains that version policy. This
option changes version direction only: package hashes, physical model confirmation,
fresh component readback, session ownership and native qualification still apply.
There is no general force or equal-version reinstall option. Main copying and raw Bluetooth
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

Main mode has been observed as USB `34d3:1100` with a GuliKit update volume.
Bluetooth mode has been observed as USB `8087:1024`, with cached SCSI identity
`Gamepad / Updater / 1.00` and no Main update volume. These profiles identify
observed modes, rather than a unique NS39 unit. Main's mass-storage interface
must not be offered as a Bluetooth command path. Native discovery reports a
`bluetooth_transport_candidate` when it correlates a suitable command interface; that alone does not prove the Windows updater would select this storage
identity or that F1 succeeds. A fresh complete F1 response and matching status remain required. The real BT
profile has passed that read-only check with dynamically selected OUT01/IN81;
Main's observed OUT03/IN82 endpoints must not be reused. Selection
counts recognized physical update candidates before component filtering and
refuses more than one device in update mode. Each component can be selected
independently; an absent Main view cannot block Bluetooth preflight and an absent
Bluetooth view cannot block Main inspection. Every access path is bound to its
current USB ancestor and generation. A shared Bluetooth
protocol signature is not an NS39 model identifier. Native discovery must
correlate each component path to its physical attachment and recheck uniqueness
before any write. A mounted descendant is only a Main-volume candidate: fresh
GULI.TXT parsing is required, and writability is a separate write condition. The Bluetooth adapter clears prior F1 qualification before every refresh attempt,
including failures during session preflight. Firmware commands require current
readback, qualified addressing and unchanged exclusive ownership. A failed BOT
session remains failed. Main writes still refuse until filesystem supervision is
qualified. Portable tests and mocked
official-instruction traces do not establish actual-device flash acceptance.

The [CLI execution plan](https://lific.mjc.lol/GULI/plans/141) and
[architecture](https://lific.mjc.lol/GULI/pages/252) hold the delivery scope.
[Research commands](research/README.md) reproduce the preserved official-code
baseline. The existing `mockups/` directory is a separate simulated UI study.
