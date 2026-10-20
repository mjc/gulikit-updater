#!/bin/bash
# Run from the repository's devenv. Keep its Rust toolchain, but link the
# distributable against Apple's SDK instead of a Nix/Homebrew runtime.
set -euo pipefail
export DEVELOPER_DIR="${DEVELOPER_DIR_OVERRIDE:-/Applications/Xcode.app/Contents/Developer}"
export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
export MACOSX_DEPLOYMENT_TARGET=13.0
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/usr/bin/clang
export CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER=/usr/bin/clang
/usr/bin/xcrun --find clang > /dev/null
cargo build --release --workspace --bins --locked
