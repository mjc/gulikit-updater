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

  packages =
    with pkgs;
    [
      cargo-nextest
      python3
      uv
    ]
    ++ lib.optionals stdenv.hostPlatform.isLinux [
      pkg-config
      fontconfig
    ];

  profiles.profiling.module = {
    env = {
      CARGO_PROFILE_RELEASE_DEBUG = "1";
      CARGO_PROFILE_RELEASE_STRIP = "none";
    }
    // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
      LD_LIBRARY_PATH = lib.makeLibraryPath (
        with pkgs;
        [
          libxkbcommon
          xorg.libX11
          xorg.libXcursor
          xorg.libXrandr
          xorg.libXi
          xorg.libxcb
        ]
      );
    };
    packages = [
      pkgs.resvg
    ]
    ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux (
      with pkgs;
      [
        heaptrack
        linuxPackages.perf
        xvfb-run
      ]
    );
  };

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
        ruff-format.enable = true;
        prettier.enable = true;
        clang-format.enable = true;
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

  tasks."check:all".exec = ''
    set -euo pipefail
    treefmt --fail-on-change --no-cache
    cargo build --workspace --bins --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo nextest run --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo test --workspace --doc --all-features --locked
  '';
}
