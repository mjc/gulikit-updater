#![cfg(unix)]

use assert_cmd::Command;
use std::{
    env,
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Output},
};
use tempfile::TempDir;

#[test]
fn relative_path_only_cannot_select_git_from_archive_directory() {
    let fixture = GitProgramFixture::new();
    let output = list_with_path(&fixture, OsStr::new("."));

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("absolute host Git executable"));
    assert!(!fixture.marker.exists());
}

#[test]
fn relative_path_entry_is_skipped_before_absolute_host_git_entry() {
    let fixture = GitProgramFixture::new();
    let path = env::join_paths([Path::new("."), fixture.host_git_dir.as_path()]).unwrap();
    let output = list_with_path(&fixture, &path);

    assert!(
        output.status.success(),
        "archive list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"releases\": []"));
    assert!(!fixture.marker.exists());
}

fn list_with_path(fixture: &GitProgramFixture, path: &OsStr) -> Output {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("list")
        .arg(&fixture.repository)
        .env("PATH", path)
        .output()
        .unwrap()
}

struct GitProgramFixture {
    _directory: TempDir,
    repository: PathBuf,
    marker: PathBuf,
    host_git_dir: PathBuf,
}

impl GitProgramFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("archive.git");
        let host_git = absolute_host_git();
        let host_git_dir = host_git.parent().unwrap().to_owned();
        git(
            &host_git,
            &[
                "init",
                "--quiet",
                "--bare",
                "--initial-branch=firmware",
                repository.to_str().unwrap(),
            ],
        );

        let marker = directory.path().join("fake-git-ran");
        let script = format!(
            "#!/bin/sh\nprintf invoked > '{}'\nexec '{}' \"$@\"\n",
            marker.display(),
            host_git.display()
        );
        let fake_git = repository.join("git");
        fs::write(fake_git, script).unwrap();
        fs::set_permissions(repository.join("git"), fs::Permissions::from_mode(0o700)).unwrap();

        Self {
            _directory: directory,
            repository,
            marker,
            host_git_dir,
        }
    }
}

fn absolute_host_git() -> PathBuf {
    env::split_paths(&env::var_os("PATH").expect("PATH is set"))
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("git"))
        .find_map(|candidate| {
            fs::metadata(&candidate)
                .ok()
                .filter(std::fs::Metadata::is_file)
                .and_then(|_| fs::canonicalize(candidate).ok())
        })
        .expect("host git executable is available through an absolute PATH entry")
}

fn git(program: &Path, args: &[&str]) {
    let output = ProcessCommand::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "host git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
