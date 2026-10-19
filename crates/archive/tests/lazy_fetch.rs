#![cfg(unix)]

use gulikit_archive::{GitArchive, GitArchiveError};
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

const MISSING_COMMIT: &str = "1111111111111111111111111111111111111111";

#[test]
fn opening_promisor_archive_does_not_run_configured_uploadpack_helper() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("archive.git");
    let helper = temp.path().join("uploadpack-helper");
    let ssh = temp.path().join("ssh-shim");
    let marker = temp.path().join("uploadpack-was-run");

    run_git(
        Command::new("git")
            .args(["init", "--quiet", "--bare", "--initial-branch=firmware"])
            .arg(&repo),
    );
    for (key, value) in [
        ("core.repositoryformatversion", "1".to_owned()),
        ("extensions.partialClone", "origin".to_owned()),
        (
            "remote.origin.url",
            "ssh://example.invalid/archive.git".to_owned(),
        ),
        ("remote.origin.promisor", "true".to_owned()),
        ("remote.origin.uploadpack", shell_quote(&helper)),
        ("core.sshCommand", shell_quote(&ssh)),
    ] {
        run_git(git_command(&repo).args(["config", key, &value]));
    }
    write_executable(
        &helper,
        format!(
            "#!/bin/sh\nprintf invoked > {}\nexit 1\n",
            shell_quote(&marker)
        ),
    );
    write_executable(
        &ssh,
        "#!/bin/sh\nfor argument do remote_command=$argument; done\nexec /bin/sh -c \"$remote_command\"\n",
    );
    fs::write(
        repo.join("refs/heads/firmware"),
        format!("{MISSING_COMMIT}\n"),
    )
    .unwrap();

    // Prove that this Git version and fixture really do trigger the configured helper
    // during an ordinary missing-object lookup when lazy fetching is enabled.
    let baseline = git_output(git_command(&repo).args(["cat-file", "-p", MISSING_COMMIT]));
    assert!(!baseline.status.success(), "the helper intentionally fails");
    assert!(
        marker.is_file(),
        "ordinary Git did not invoke the fetch helper"
    );
    fs::remove_file(&marker).unwrap();

    // The public archive opening path reaches the missing commit, but its Git
    // subprocesses must have lazy fetching disabled regardless of repository config.
    let result = GitArchive::open(&repo);
    assert!(
        matches!(&result, Err(GitArchiveError::Git(message)) if message.contains(MISSING_COMMIT) || message.contains("could not get object info")),
        "unexpected archive error: {result:?}"
    );
    assert!(
        !marker.exists(),
        "opening the archive executed the configured upload-pack helper"
    );
}

fn git_command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg(format!("--git-dir={}", repo.display()));
    command
}

fn git_output(command: &mut Command) -> Output {
    let inherited: Vec<_> = env::vars_os()
        .filter(|(key, _)| !key.to_string_lossy().starts_with("GIT_"))
        .collect();
    command.env_clear().envs(inherited).output().unwrap()
}

fn run_git(command: &mut Command) -> Output {
    let output = git_output(command);
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn write_executable(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).unwrap();
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}
