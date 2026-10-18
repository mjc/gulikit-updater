# Offline protocol research

`native_probe.m` preserves the original read-only macOS IOUSBHost probe.
`emulate_update.py` executes the pinned official x86 update-loop instructions
under Unicorn with fake Windows/UI/device calls. No firmware-write opcode
exists in the native probe. Emulation does not use USB or launch the EXE natively.

The original findings and source evidence are in
[GULI-DOC-1](https://lific.mjc.lol/GULI/pages/227); ongoing discovery/protocol
research is [GULI-23](https://lific.mjc.lol/GULI/issues/GULI-23).

## Reproduce the official-loop baseline

Supply the intact original Bluetooth 5.07 ZIP from the official release:

```sh
devenv shell
uv run --with-requirements research/requirements.txt python research/prepare.py artifacts/vendor/kk3/packages/GuliKit_NS38_NS39_NS59_BT_V5.07.zip
uv run --with-requirements research/requirements.txt python research/emulate_update.py
uv run --with-requirements research/requirements.txt python -O -m unittest discover -s research -p 'test_*.py'
```

Preparation verifies the original ZIP, EXE, embedded DLL and payload hashes
before saving artifacts under ignored `artifacts/research/`. No vendor binary
is committed. `--exe` can select the prepared EXE for emulation; its digest is
checked before instructions execute. The checked-in `emulation-results.json`
records the original three reference outcomes: exact 674-block payload stream,
first F2 error stopping after one block, and final F2 error rejecting completion.

This preserved loop harness is deliberately narrow. Expanded official-code
research found that the real host does not reliably act on DLL transport
failures and does not verify installed firmware after restart. A native updater
must validate transport/status/length and perform its own installed-version
readback. The F1 signature is shared across device families and cannot identify
NS39 on its own. The official updater's variable trailing CDB bytes contain
stack data; zeroed tails remain unproven on the real device.

The userspace instruction fixtures did not cover the lower USB storage driver's
BOT recovery and residue handling. This gap mattered on the actual NS39: the
first 3.24 attempt stopped when its status read stalled; a second attempt cleared
that halt and read a matching passed wrapper, then stopped on our stricter residue
equality check. That second record shows exactly one F2 byte `00` and zero wrapper
residue. The maintained transport now retries that same status once after clearing
Bulk-IN, and accepts only that exact one-byte zero-residue F2 exception while
preserving its actual count and raw evidence. Neither attempt completed a flash.
Instruction emulation alone did not qualify the complete native transport.

## Build the historical read-only probe on macOS

```sh
mkdir -p target
/usr/bin/clang -fobjc-arc -fblocks -Wall -Wextra -Werror -framework Foundation -framework IOKit -framework IOUSBHost research/native_probe.m -o target/native-probe
```

Building does not access a device. Running `--read-info` or `--inquiry` captures
the controller temporarily and requires root; keep actual device operations
within an explicitly requested hardware session. The original probe's NS39/BT
labels describe the research context, not a proven model detector. The observed
`34d3:1100` storage interface belongs to **Main update mode**, entered using
APS + A (double-square/APG), and is not the Bluetooth updater. This preserved
historical probe targets that Main profile; its earlier BT labels are incorrect.
Do not use it to qualify Bluetooth transfers. Main-mode F1 command rejection is
wrong-mode evidence; the older timeout also retains its original transport log.

Bluetooth uses the separate **Gear / Set + A** mode. Exit the previous update
mode via Mode off, then normal Mode-on restart. With the controller off, connect
USB, hold Gear first and then press A. Fresh discovery has observed Bluetooth
`8087:1024` with cached SCSI `Gamepad / Updater / 1.00` and no Main volume.
A shared BOT interface does not make both update modes available together.
These entry steps do not establish safe recovery from an interrupted update.
After a partial or unknown transfer, keep the controller connected and unchanged
until recovery has been qualified for that state.
These observed profiles are not unique model or unit identity. The maintained
`crates/platform/examples/native_probe.rs` uses production discovery; a complete
fresh F1 reply and matching status are required before any Bluetooth update.

## Reproduce the expanded Bluetooth Windows context

After preparation, run the actual discovery worker, update handler and embedded
USB DLL in the bounded Unicorn fixture:

```sh
uv run --with-requirements research/requirements.txt python -O research/run_context_suite.py
uv run --with-requirements research/requirements.txt python -O -m unittest discover -s research -p 'test_*.py'
```

`--exe`, `--dll` and `--output` select reference paths and the generated trace
cache. Defaults use the files produced by `prepare.py` and the ignored research
cache. Both reference images are size/hash checked before PE parsing or mapping;
optimization cannot remove input checks or scenario acceptance checks. No vendor
binary or generated firmware trace belongs in Git.

Seven scenarios execute the real descriptor filter and DLL exports: matching,
ASCII Guli, raw-UTF16-conditioned Guli and non-USB descriptor fixtures; F1 retry
and exhaustion; and the complete synthetic 5.06-to-5.07 update. The latter checks
674 exact 512-byte blocks, complete payload hash, first/final F2 placement,
progress/message pumping, success dialog, handle closure and discovery resumption.
A selected drive is obtained through the real discovery instructions. The fixture
records the storage query's eight initialized bytes and four stack bytes rather
than treating all twelve bytes as initialized.

Windows/CRT imports, loader/runtime objects, responses and scheduling are fixtures.
Two static CRT text-formatting functions are also modeled; DeviceUsb exports and
MFC/UI wrappers execute their actual instructions. The descriptor cases do not
establish the controller's actual Windows descriptor. This proves the stated
userspace control flow, including the misleading mismatch dialog after failed
F1 transport. Windows kernel behavior, USB wire packets, native F1 acceptance,
real firmware transfer and installed-version readback remain separate evidence.
