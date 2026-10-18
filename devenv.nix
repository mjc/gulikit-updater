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
      python315
      uv
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
        ruff-format.enable = true;
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

  tasks."check:all".exec = ''
    set -euo pipefail
    treefmt --fail-on-change --no-cache
    python3 -m unittest discover -s scripts -p 'test_*.py' -v
    cargo build --workspace --bins --all-features --locked
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo nextest run --workspace --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo test --workspace --doc --all-features --locked
  '';
}
