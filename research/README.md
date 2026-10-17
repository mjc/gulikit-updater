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

## Build the historical read-only probe on macOS

```sh
mkdir -p target
/usr/bin/clang -fobjc-arc -fblocks -Wall -Wextra -Werror -framework Foundation -framework IOKit -framework IOUSBHost research/native_probe.m -o target/native-probe
```

Building does not access a device. Running `--read-info` or `--inquiry` captures
the controller temporarily and requires root; keep actual device operations
within an explicitly requested hardware session. The original probe's NS39/BT
labels describe the research context, not a proven model detector. The observed
34d3:1100 storage interface and Main update volume belong to the same physical
device, and Main/BT access must not be assumed mutually exclusive.
