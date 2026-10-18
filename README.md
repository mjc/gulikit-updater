# GuliKit updater

The updater supports reviewed KK3 Max NS39 Main 5.9 and Bluetooth 3.23 / 3.24 / 5.07
packages. The original ZIP selects the release; the CLI does not silently replace
that selection with the newest version. The shared Rust core owns component
transactions and restart verification. Native macOS adapters provide Bluetooth
transport and supervised Main filesystem updates. Actual-device acceptance is
tracked separately from portable tests and offline instruction emulation.

| Component | Selected release | Firmware bytes | Bluetooth blocks |
| --- | --- | ---: | ---: |
| Main | 5.9 | 51,500 | — |
| Bluetooth | 3.23 | 361,472 | 706 |
| Bluetooth | 3.24 | 361,472 | 706 |
| Bluetooth | 5.07 | 345,088 | 674 |

KK3 Max Bluetooth 3.23 → 3.24 → 3.23 has passed hardware acceptance using
original manufacturer archives. Fresh F1 readbacks confirmed both 3.24 after
the upgrade and 3.23 after the downgrade. This qualifies that Bluetooth pair;
other release pairs and Main downgrade acceptance remain separate checks.

The controller can restart after receiving the last firmware block, before
returning its command-status wrapper. Exact successful DATA OUT for every block,
with all earlier commands confirmed, no final status bytes received, and the
selected device's expected USB removal observed, produces
`transfer_submitted_pending_completion`. The missing final command confirmation
is retained. A passed final F0 status is retained too if the controller detaches
before final F2; that case also awaits completion verification. An expected
detach after a passed final F2 preserves the completed transfer. Only a fresh
independent version read after restart can produce `installed_verified`. An earlier interruption, failed status, partial transfer or
audit failure retains an uncertain outcome. Hardware evidence and remaining work
live in the linked CLI plan and product specification.

## Development

Use the pinned native devenv from this directory:

```sh
devenv shell
cargo run -- packages
cargo run -- package inspect /path/to/KK3_NS38_NS39_V5.9.zip --model kk3-max --component main
cargo run -- package inspect /path/to/NS38_NS39_BT_V3.24.zip --model kk3-max --component bluetooth --json
cargo run -- package inspect /path/to/GuliKit_NS38_NS39_NS59_BT_V5.07.zip --model kk3-max --component bluetooth --json
cargo run -- devices --json
cargo run -- probe --component main --confirm-ns39 --json
cargo run -- update /path/to/KK3_NS38_NS39_V5.9.zip --model kk3-max --component main --confirm-ns39 --record ./main-attempt.jsonl --json
cargo run -- update /path/to/NS38_NS39_BT_V3.24.zip --model kk3-max --component bluetooth --confirm-ns39 --record ./bt-attempt.jsonl --json
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

These mode-entry instructions apply before an update or after a completed
transfer. After a partial or unknown outcome, keep the cable connected and leave
the controller unchanged. Do not restart, reset, retry, resume, inspect or verify
until a recovery procedure has been qualified for that interrupted state.

Put only one controller in update mode. `--confirm-ns39` attests that you checked
the physical NS39 label and Max controls. USB IDs and the shared F1 signature
are observed profile evidence, not automatic proof of the model. The native
adapter checks runtime support for modern IOUSBHost and DeviceSurrender.
Bluetooth capture requires the qualified update profile with no disk media; it
refuses profiles with correlated disks rather than unmounting volumes. Read-only
cleanup destroys the capture, which resets USB and restarts driver matching.
After possible firmware submission, cleanup uses no-reset DeviceSurrender. If
the original device has not observably detached, restoration remains pending.
No firmware replay or automatic reset is used after submission. Other OSes currently support package commands.

BOT transport requests a 20-byte F2 reply and accepts 1–20 received bytes only
with a matching, successful command-status wrapper and exact residue; byte zero
must report success. F1 still requires all 20 bytes and each F0 requires all 512
bytes. The observed NS39 exception accepts exactly one F2 byte `00` with an
otherwise valid passed wrapper reporting zero residue. Its actual count stays
one; the raw wrapper and an explicit quirk flag are saved without changing them.
Other lengths and commands retain the usual residue check.
If the first command-status read stalls with zero bytes received, the
adapter clears the Bulk-IN halt and reads that same status once more. It sends
no new command or firmware block. A repeated stall, partial status, timeout or
invalid wrapper stops the session. The attempt record retains actual counts,
received data, status packets, errors and halt-clearance results. Commands have
a five-second budget, checked before and after each operation. Apple's synchronous
halt-clearance API has no timeout parameter: ownership remains held until it
returns, and an overrun prevents the next read. This budget is not a hard
wall-clock bound on that host call.

Each update uses one original, verified package and creates an exclusive host
attempt record outside the controller volume. Operation submission, actual
results, raw version bytes and cleanup results are persisted as JSON lines.
If cancellation or audit failure follows successful Main destination creation but
precedes payload submission, the result records `destination_created_without_payload`
and `main_destination_created`, with zero firmware bytes submitted and exit 8.
The file remains for inspection; another attempt cannot silently overwrite it.
An incomplete record preserves an interrupted attempt; it does not prove a
transfer completed. Bluetooth block count and installed-version comparison come from the selected
reviewed package. Audit refusal before I/O records zero submission; an error after
submission may have begun retains uncertainty. Equal and unknown installed versions
write nothing. A newer installed version
refuses by default; `update --allow-downgrade` explicitly permits installing the
selected older reviewed release. The record retains that version policy. The
original manufacturer-supplied Bluetooth 3.23 archive is available in the catalog;
physical upgrade and downgrade between 3.23 and 3.24 are verified. Other pairs
and recovery from a partial update need their own evidence. This option changes version direction only: package hashes, physical model confirmation,
fresh component readback, session ownership and native qualification still apply.
There is no general force or equal-version reinstall option. Main copying and raw Bluetooth
traffic are serialized. A topology change invalidates the active session.

Transfer completion is separate from installation verification. Main installation
finishes with the controller automatically restarting; its own detach is observed
without manually unmounting it. After a completed Bluetooth transfer, power the
controller on normally once, then off, then re-enter Bluetooth update mode with
Gear held before pressing the rightmost A. This fresh entry permits version readback. `verify` requires a fresh version read on a new attachment plus explicit
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

Original vendor archives stay outside Git. To run the five explicit archive
acceptance tests, put the four original ZIPs in the ignored
`artifacts/vendor/kk3/packages/` cache or set `GULIKIT_VENDOR_DIR`:

```sh
cargo test -p gulikit-core --test vendor_packages -- --ignored
```

These tests check exact payload selection/extraction for Main 5.9 and Bluetooth
3.23 / 3.24 / 5.07, plus altered-archive rejection. They never connect to USB. CI runs the portable behavioral suite;
the archive tests require separately supplied vendor downloads. Two ignored child
entrypoints are subprocess fixtures invoked by the ordinary supervision tests.
Those tests exercise actual child exit, parent disconnect, process-group isolation,
bounded reporting, protocol phases and lease retention without controller access.

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
session remains failed. Main writes require the supervised I/O worker and a
freshly checked writable volume, selected root, attachment and process lease.
The Main transaction has a 180-second supervision budget, including its bounded
120-second completion wait. If I/O blocks or shutdown cannot be confirmed, the
CLI reports uncertainty while ownership remains held until the worker exits.
This filesystem shutdown policy is never applied to a Bluetooth USB capture. Portable tests and mocked
official-instruction traces do not establish actual-device flash acceptance.

The [CLI execution plan](https://lific.mjc.lol/GULI/plans/141) and
[architecture](https://lific.mjc.lol/GULI/pages/252) hold the delivery scope.
[Research commands](research/README.md) reproduce the preserved official-code
baseline. The existing `mockups/` directory is a separate simulated UI study.
