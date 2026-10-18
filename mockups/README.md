# GuliKit updater mockups

Interactive HTML/CSS mockups for a Slint UI. All device states and transfers are
simulated. The mockups have no hardware integration or Slint dependency.

Open `index.html` in a browser, or serve this directory:

```sh
python3 -m http.server 18764 --bind 127.0.0.1
```

Use the top controls to switch screens and layouts. **Choose file** includes a
wrong-model example. **Update** runs a simulated transfer; **Simulate fresh
readback** completes verification. Component buttons return to mode instructions
and require a new simulated inspection. **Log** opens the log; **Help** opens the
connection instructions.

Package data comes from GULI-DOC-1. Mode and restart guidance follows
[GULI-DOC-16](https://lific.mjc.lol/GULI/pages/242). Installed Main 5.8 and Bluetooth
5.06 are illustrative; only the selected component’s observation is shown.
Android is a layout concept with unproven USB support; iOS is deferred.

The study header, screen controls and simulation buttons are for mockup review only.

Main and Bluetooth use separate modes. Main uses **APS (double-square) + A**
(the vendor calls the double-square button APG). Bluetooth uses **Gear / Set + A**:
controller off, USB connected, hold Gear first and keep it held while pressing A.
A is the physical rightmost button in the default Switch layout; modified layouts
need their button mapping checked. To switch components, exit the current mode
with Mode off → normal on, then turn off before entering the other update mode.
A fresh inspection is required; the old mode does not establish readiness.

A warning above the selected mode’s instructions states that Main and Bluetooth
require different update and restart procedures.

The completion sequences also differ. Main powers off automatically and its
GuliKit drive disappears; wait for that, then turn on normally. Bluetooth requires
normal power off and on after completion. Fresh verification may require
re-entering the selected update mode. Neither transfer completion nor selecting
the other component proves an installed version. Native Bluetooth write
qualification is still pending; the mockup only simulates transfers.

Automated callback tests run without a browser, desktop or hardware:

```sh
node --test mockups/app.test.cjs
```

They execute the production script with a small DOM adapter, covering both
component-switch controls, fresh-inspection gating, transfer/restart locks,
mode-entry order, distinct completion sequences and qualification wording.

Button instructions include labeled APS/double-square, Gear/Set and A icons. The
SVGs in `mockups/icons/` are shared by this preview and the compiled Slint UI.
Each icon appears alongside the hold-first instructions and an accessible button
name.
