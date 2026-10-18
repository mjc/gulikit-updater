# Desktop UI

Slint desktop client for the same application operations used by the CLI.
Run from the repository root:

```sh
devenv shell -- cargo run -p gulikit-ui
```

Confirm the physical NS39 label and Max controls, inspect the selected component,
and choose its original reviewed firmware ZIP. Selecting a package never starts
an update. Native **Update** is disabled; direct update requests are refused before
reading the package or opening a save dialog. Device work and native file dialogs
run on one worker.

Native device access currently supports macOS. Windows and Linux build the UI
and support package inspection, but do not yet have native device adapters.
Native desktop writes remain unavailable until desktop supervision and update
acceptance are complete. The shared backend retains the CLI's supervised Main
path and Bluetooth protocol operations.

A warning above the instructions states that Main and Bluetooth require different
update and restart procedures. Switching components clears the old
attachment and package, shows the new mode instructions, and waits for an explicit
inspection request. Main entry uses APS (double-square, called APG by the vendor)
then A; Bluetooth entry requires Gear held first, then A, with the controller off
and USB connected. Labeled SVG button icons accompany entry and readback steps;
the instructions and accessible names retain the hold-first order. Switching modes
requires Mode off → normal on, then off again.

Transfer completion requires a separate version check after restart. Main powers
off automatically and its GuliKit drive disappears; then turn it on normally.
Bluetooth requires normal power off and on after completion. Re-enter
update mode and confirm the same physical controller before **Check version**.
**Open record…** can load an earlier attempt for fresh verification. It cannot
resume or retry a transfer. An unknown outcome blocks further USB inspection
and verification until recovery is qualified; changing screens or opening an
earlier record cannot clear that hold. A Main destination created without payload
also blocks another attempt. Full operation records stay in the selected host
files; **Log** contains a short, copyable summary. Keep records off the controller.

For an offline simulated device:

```sh
devenv shell -- cargo run -p gulikit-ui -- --demo
```

The demo enables simulated updates through the same controller, worker interface, Slint callbacks, progress
handling and restart verification flow. Its device implementation stores versions
and attempt records in memory; it never opens devices, firmware files or native
dialogs. **Choose file…** offers simulated packages. **Demo…** changes device
conditions: normal, current, newer, identity failure, connection loss, failed
readback or unknown version. Selecting a condition does not start a transfer or
skip to a successful screen. Restarting the app resets the simulated device.

The window resizes and scrolls, with a minimum size of 760 × 600. macOS, Windows
and Linux use the same Slint source. A build on one platform does not establish
acceptance on the others.

For native startup and normal-shutdown measurements, enter
`devenv --profile profiling shell` and build with
`cargo build -p gulikit-ui --release --locked`. The profile retains debug symbols
in the optimized binary and supplies Linux profiling and virtual-display tools.

```sh
GULIKIT_PROFILE_LIFECYCLE_MS=1000 pyroclast cpu --out artifacts/research/lifecycle/cpu -- target/release/gulikit-ui --demo
```

`GULIKIT_PROFILE_LIFECYCLE_MS` requests a normal window close after the given
idle interval; it requires `--demo` and accepts 50–60000 milliseconds. Its JSON
output separates time to show the window, idle time, and shutdown through the
worker join. Time to show the window does not establish time to first paint.
Pyroclast records the whole process, including initialization and teardown.
Use a new output directory for each capture. On macOS, select the installed
Xcode developer directory for the command if `xctrace` is unavailable.

Pyroclast allocation recording currently requires Linux:

```sh
xvfb-run -a env GULIKIT_PROFILE_LIFECYCLE_MS=1000 pyroclast memory --out artifacts/research/lifecycle/heap -- target/release/gulikit-ui --demo
```

Keep Linux virtual-display results separate from native macOS measurements.

```sh
devenv shell -- cargo test -p gulikit-ui
devenv tasks run check:all
```

Automated tests exercise the shared controller with typed device observations,
including explicit write authorization, operation locking, confirmed progress,
cancellation, stale attachments, version refusal, uncertain outcomes and fresh
restart verification. Simulated-device tests run the same operations without
hardware or sleeps. Core transfer tests check actual progress callbacks through
fake protocol ports. Native boundary tests check rejected host inputs without
opening a device or dialog.

Slint tests compile the production UI and use its version-pinned headless backend.
They dispatch pointer and keyboard events, advance a controlled clock, and render
offscreen. They cover both modes, package selection, minimum-size filename
wrapping, failure presentation, log contrast, read-only text and isolated clipboard
contents. No computer use, desktop session or hardware is required.

Tracked integration: GULI-10 and GULI-11. Design: GULI-DOC-2.
