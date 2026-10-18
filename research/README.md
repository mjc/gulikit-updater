# Offline protocol research

These historical scripts are outside the maintained build, check, packaging and
release workflows. Replaying them requires a separate Python and uv environment.

These tools execute the reviewed Bluetooth 5.07 updater's x86 instructions in
Unicorn with simulated Windows and device calls. They do not access USB or run
the EXE natively. USB-driver behavior and installed firmware require separate
evidence; see the [NS39 guide](https://lific.mjc.lol/GULI/pages/242).

## Instruction emulation

From the repository root, with that research environment available, supply the
intact official Bluetooth 5.07 ZIP:

```sh
uv run --with-requirements research/requirements.txt python research/prepare.py artifacts/vendor/kk3/packages/GuliKit_NS38_NS39_NS59_BT_V5.07.zip
uv run --with-requirements research/requirements.txt python research/emulate_update.py
uv run --with-requirements research/requirements.txt python -O research/run_context_suite.py
uv run --with-requirements research/requirements.txt python -O -m unittest discover -s research -p 'test_*.py'
```

Preparation checks archive, EXE, DLL and payload hashes before extracting into
ignored `artifacts/research/`. The loop fixture checks payload streaming and
first/final status failures; the context suite exercises discovery, retries and
the complete simulated update. `--help` lists input/output overrides.
`emulation-results.json` contains the original loop reference results.

## Ghidra scripts

The scripts in `ghidra/` inventory and decompile the prepared EXE/DLL. The
reference analysis used Ghidra 12.0.4 and Java 21. Set `GHIDRA_HOME` to the
installation containing `support/analyzeHeadless`, then run from the repo root:

```sh
: "${GHIDRA_HOME:?Set GHIDRA_HOME to your Ghidra installation}"
mkdir -p artifacts/research/ghidra/project
"$GHIDRA_HOME/support/analyzeHeadless" "$PWD/artifacts/research/ghidra/project" BluetoothAudit \
  -import "$PWD/artifacts/research/GuliKit_NS38_NS39_NS59_BT_V5.07.exe" \
  -scriptPath "$PWD/research/ghidra" \
  -postScript AuditWholeProgram.java "$PWD/artifacts/research/ghidra/exe" full 10
```

Use a fresh project directory for a new analysis. Repeat for
`artifacts/research/DeviceUsb.official.dll` with a separate output directory.
`full 10` decompiles all discovered functions with a ten-second per-function
timeout. Inspect the logs and coverage output for failures and missed targets.

For an imported program, use `-process FILENAME -noanalysis` instead of
`-import PATH`, with one of these post-scripts:

| Post-script                     | Arguments                          | Purpose                                            |
| ------------------------------- | ---------------------------------- | -------------------------------------------------- |
| `RecoverCallbackContext.java`   | `OUTPUT_DIRECTORY`                 | Recover functions through pointer/callee analysis. |
| `RecoverExplicitCallbacks.java` | `OUTPUT_DIRECTORY HEX_ADDRESS ...` | Recover functions at specified addresses.          |

Recovery changes Ghidra analysis metadata, not the vendor binary. Keep databases,
exports and logs under ignored `artifacts/`. Historical findings are in
[GULI-DOC-1](https://lific.mjc.lol/GULI/pages/227).

`native_probe.m` and `scsi_probe.c` are historical probes, separate from the
offline tools. The Objective-C probe targets Main mode despite its old Bluetooth
labels. Use the maintained CLI for device inspection.
