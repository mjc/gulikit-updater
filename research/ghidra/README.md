# Offline Ghidra analysis

These are the unchanged scripts used to inventory the official Bluetooth 5.07
EXE and embedded USB DLL, then recover callbacks missed by initial autoanalysis.
They read PE images and modify Ghidra analysis metadata; they do not execute the
vendor programs or access hardware. Prepare the original images with
[`../prepare.py`](../prepare.py), following [`../README.md`](../README.md).

The reference run used Ghidra **12.0.4** from the repository's pinned nixpkgs.
Enter its environment from the repository root without adding a dependency:

```sh
devenv -O packages:pkgs ghidra shell
```

Set `GHIDRA_HOME` to that installation's Ghidra home (the directory containing
`support/analyzeHeadless`). Supply a compatible JDK through your environment;
the reference run used Java 21. Set `JAVA_HOME` if needed. No machine-specific
installation path is required by these scripts.

## Inputs and commands

The original ignored `analysis-manifest.json` under
`artifacts/vendor/protocol-research/f1-diagnosis/ghidra/` records these inputs:

| Prepared input                                           |   Bytes | SHA-256                                                            |
| -------------------------------------------------------- | ------: | ------------------------------------------------------------------ |
| `artifacts/research/GuliKit_NS38_NS39_NS59_BT_V5.07.exe` | 2245632 | `3dc8fd352597de4b619efcf139933fbbccc5c1c335aa580455bf5f64f4b9c97a` |
| `artifacts/research/DeviceUsb.official.dll`              |    8704 | `fad660bc7e006c58f37db9d75b72bf30c089ef62fc4e72673cbfd424d247b5e5` |

Run the following sequentially from the repository root, using a fresh output
folder for each reproduction. Keep project databases, exports and logs under
ignored `artifacts/`. The `full 10` arguments are required here to decompile all
**discovered** functions with a ten-second per-function timeout; omitting `full`
limits the EXE decompilation selection. The inventories still cover discovered
functions and instructions in either mode.

```sh
: "${GHIDRA_HOME:?Set GHIDRA_HOME to the Ghidra 12.0.4 home}"
GHIDRA_AUDIT_ROOT="$PWD/artifacts/research/ghidra-reproduction"
GHIDRA_AUDIT_SCRIPTS="$PWD/research/ghidra"
mkdir -p "$GHIDRA_AUDIT_ROOT/project"

"$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_AUDIT_ROOT/project" BluetoothAudit \
  -import "$PWD/artifacts/research/GuliKit_NS38_NS39_NS59_BT_V5.07.exe" \
  -scriptPath "$GHIDRA_AUDIT_SCRIPTS" \
  -log "$GHIDRA_AUDIT_ROOT/exe-headless.log" \
  -postScript AuditWholeProgram.java "$GHIDRA_AUDIT_ROOT/exe" full 10

"$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_AUDIT_ROOT/project" BluetoothAudit \
  -import "$PWD/artifacts/research/DeviceUsb.official.dll" \
  -scriptPath "$GHIDRA_AUDIT_SCRIPTS" \
  -log "$GHIDRA_AUDIT_ROOT/dll-headless.log" \
  -postScript AuditWholeProgram.java "$GHIDRA_AUDIT_ROOT/dll" full 10

"$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_AUDIT_ROOT/project" BluetoothAudit \
  -process GuliKit_NS38_NS39_NS59_BT_V5.07.exe -noanalysis \
  -scriptPath "$GHIDRA_AUDIT_SCRIPTS" \
  -log "$GHIDRA_AUDIT_ROOT/exe-recovery.log" \
  -postScript RecoverCallbackContext.java "$GHIDRA_AUDIT_ROOT/exe-callback-recovery"

"$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_AUDIT_ROOT/project" BluetoothAudit \
  -process DeviceUsb.official.dll -noanalysis \
  -scriptPath "$GHIDRA_AUDIT_SCRIPTS" \
  -log "$GHIDRA_AUDIT_ROOT/dll-recovery.log" \
  -postScript RecoverCallbackContext.java "$GHIDRA_AUDIT_ROOT/dll-callback-recovery"

"$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_AUDIT_ROOT/project" BluetoothAudit \
  -process GuliKit_NS38_NS39_NS59_BT_V5.07.exe -noanalysis \
  -scriptPath "$GHIDRA_AUDIT_SCRIPTS" \
  -log "$GHIDRA_AUDIT_ROOT/exe-explicit.log" \
  -postScript RecoverExplicitCallbacks.java "$GHIDRA_AUDIT_ROOT/exe-explicit-callbacks" \
  00526253 005260ea 004256b5 00525b85 00526261 00508825 00525f79 005262a5 \
  00525dfd 005260ba 00525cf9 00525f95 0052611a 00525e7c 005260c8

"$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_AUDIT_ROOT/project" BluetoothAudit \
  -process DeviceUsb.official.dll -noanalysis \
  -scriptPath "$GHIDRA_AUDIT_SCRIPTS" \
  -log "$GHIDRA_AUDIT_ROOT/dll-explicit.log" \
  -postScript RecoverExplicitCallbacks.java "$GHIDRA_AUDIT_ROOT/dll-explicit-callbacks" \
  10001ab9 100019cb
```

Initial exports remain separate from recovery exports. Recovery operates on the
existing imported programs with `-noanalysis`; it adds analysis metadata and
exports the recovered functions without rerunning initial autoanalysis. The
explicit address lists above are the final targets used in the reference run,
including callbacks not reached by aligned-pointer recovery.

## Recorded coverage and limits

The reference initial export decompiled all 9,585 discovered EXE functions and
34 DLL functions, with zero failed decompilations. Callback-context recovery
added and decompiled 810 EXE functions and two DLL functions. Its pointer/callee
closure is bounded to three rounds and 1,000 new functions. The final explicit
pass decompiled all 15 listed EXE targets and both DLL targets. These are separate
coverage measurements, not a claim that every possible runtime path was found.

Autoanalysis logged EXE exception-data disassembly errors at `004f0054` and
`004c004f`, DLL `TerminatedCString` warnings, and unavailable PDBs. Preserve and
inspect logs and each export's coverage/index files rather than treating a
successful headless exit as a clean analysis. Computed calls, heuristic MFC
entries and data pointers need manual confirmation; unaligned, computed or
runtime-created callback targets may remain undiscovered. Corroborate disputed
decompiler output against instructions. This analysis did not observe Windows
execution, its storage/USB kernel stack, USB wire traffic, or device acceptance.
