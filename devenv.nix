{ pkgs, ... }:
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [ cargo-nextest python3 uv ]
    ++ lib.optionals stdenv.hostPlatform.isLinux [ pkg-config fontconfig ];

  tasks."check:all".exec = ''
    set -euo pipefail
    cargo fmt --all -- --check
    cargo build --workspace --bins --all-features --locked
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo nextest run --workspace --all-features
    RUSTDOCFLAGS="-D warnings" cargo test --workspace --doc --all-features
  '';
}
