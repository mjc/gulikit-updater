{ pkgs, ... }:
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [ cargo-nextest python3 uv libusb1 pkg-config ];

  tasks."check:all".exec = ''
    set -euo pipefail
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo nextest run --workspace --all-features
    RUSTDOCFLAGS="-D warnings" cargo test --workspace --doc --all-features
  '';
}
