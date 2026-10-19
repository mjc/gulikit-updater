{
  config,
  lib,
  pkgs,
  ...
}:
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  # cc-rs uses Apple's macosx target spelling, which the Nix wrapper warns about.
  env = lib.optionalAttrs config.stdenv.hostPlatform.isDarwin {
    "CC_${lib.replaceStrings [ "-" ] [ "_" ] config.stdenv.hostPlatform.rust.rustcTarget}" =
      "${config.stdenv.cc.cc}/bin/clang";
    "CFLAGS_${lib.replaceStrings [ "-" ] [ "_" ] config.stdenv.hostPlatform.rust.rustcTarget}" =
      "-Werror=unguarded-availability";
  };

  packages =
    with pkgs;
    [
      cargo-nextest
    ]
    ++ lib.optionals stdenv.hostPlatform.isLinux [
      pkg-config
      fontconfig
    ];

  treefmt = {
    enable = true;
    config = {
      programs = {
        rustfmt = {
          enable = true;
          package = config.languages.rust.toolchainPackage;
        };
        nixfmt.enable = true;
        taplo.enable = true;
        prettier.enable = true;
        clang-format = {
          enable = true;
          package = pkgs.llvmPackages_23.clang-tools;
        };
        google-java-format.enable = true;
      };
      settings.global.excludes = [ "artifacts/**" ];
      settings.formatter.clang-format.includes = [ "*.m" ];
    };
  };

  # Format on request and at commit, without rewriting files on shell entry.
  tasks."devenv:treefmt:run".before = lib.mkForce [ ];

  # A linked worktree must not install hooks that target another checkout.
  tasks."check:hooks-path" = {
    before = [ "devenv:git-hooks:install" ];
    exec = ''
      ${lib.getExe config.git-hooks.gitPackage} config extensions.worktreeConfig true
      ${lib.getExe config.git-hooks.gitPackage} config --worktree core.hooksPath "$DEVENV_STATE/git-hooks"
    '';
    status = ''
      test "$(${lib.getExe config.git-hooks.gitPackage} config --worktree --get core.hooksPath)" = "$DEVENV_STATE/git-hooks"
    '';
  };

  git-hooks.hooks = {
    treefmt.enable = true;
    clippy = {
      enable = true;
      after = [ "treefmt" ];
      always_run = true;
      settings = {
        allFeatures = true;
        denyWarnings = true;
        extraArgs = "--workspace --all-targets --locked";
      };
    };
  };

  tasks."check:packaging".exec = "cargo nextest run -p gulikit-dist --locked";

  tasks."dist:macos:build".exec = "bash scripts/build_macos.sh";
  tasks."dist:macos:smoke" = {
    after = [ "dist:macos:build" ];
    exec = ''
      export DEVELOPER_DIR="''${DEVELOPER_DIR_OVERRIDE:-/Applications/Xcode.app/Contents/Developer}"
      cargo run --locked -p gulikit-dist -- smoke --binaries target/release --arch "$(uname -m)"
    '';
  };
  tasks."dist:macos:release" = {
    after = [ "dist:macos:build" ];
    exec = ''
      export DEVELOPER_DIR="''${DEVELOPER_DIR_OVERRIDE:-/Applications/Xcode.app/Contents/Developer}"
      cargo run --locked -p gulikit-dist -- release --binaries target/release --arch "$(uname -m)"
    '';
  };

  tasks."check:all".exec = ''
    set -euo pipefail
    treefmt --fail-on-change --no-cache
    cargo build --workspace --bins --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo nextest run --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo test --workspace --doc --all-features --locked
  '';
}
