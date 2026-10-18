# UI mockups

Open `index.html` in a browser, or serve this directory:

```sh
python3 -m http.server 18764 --bind 127.0.0.1 --directory mockups
```

Run that command from the repository root. The top controls select screens and
layouts. **Choose file** includes a wrong-model example; **Update** and
**Simulate fresh readback** exercise the simulated update flow. All versions,
connections and transfers are simulated. Android is a layout concept only.

With Node.js installed, run the callback tests from the repository root:

```sh
node --test mockups/app.test.cjs
```

The preview and Slint app share the button SVGs in `icons/`.
