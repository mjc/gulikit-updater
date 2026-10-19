#![cfg(unix)]

use gulikit_archive::{Component, GitArchive, GitArchiveError, ReleaseMetadata};
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;
use zip::{ZipWriter, write::SimpleFileOptions};

#[test]
#[cfg(unix)]
fn two_imports_are_signed_orphan_then_linear_append_without_source_checkout_changes() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let (source, source_head, source_status) = source_fixture(temp.path(), &fixture);

    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init(&repo).unwrap();
    configure_archive(&repo, &fixture, true);

    let main_zip = temp.path().join("main.zip");
    let bluetooth_zip = temp.path().join("bluetooth.zip");
    fs::write(&main_zip, synthetic_zip("firmware.bin", b"main firmware")).unwrap();
    fs::write(
        &bluetooth_zip,
        synthetic_zip("firmware.bin", b"other firmware"),
    )
    .unwrap();

    let first = archive
        .import(
            &main_zip,
            metadata(Component::Base, "5.9", "KK3_NS38_NS39_V5.9.zip"),
        )
        .unwrap();
    let second = archive
        .import(
            &bluetooth_zip,
            metadata(Component::Base, "5.8", "NS39_V5.8.zip"),
        )
        .unwrap();

    assert_ne!(first, second);
    assert_eq!(commit_parents(&repo, &first).len(), 0);
    assert_eq!(commit_parents(&repo, &second), std::slice::from_ref(&first));
    assert!(git_fails(&[
        "--git-dir",
        &repo.display().to_string(),
        "merge-base",
        &source_head,
        &second
    ]));
    assert_eq!(
        git_at(&source, &["status", "--porcelain"]).stdout,
        source_status
    );
    assert_eq!(archive.index().unwrap().releases().len(), 2);
    assert_eq!(
        archive
            .read("/kk3-max/base/v5.9/KK3_NS38_NS39_V5.9.zip")
            .unwrap(),
        fs::read(main_zip).unwrap()
    );
    assert_eq!(
        archive.read("/kk3-max/base/v5.8/NS39_V5.8.zip").unwrap(),
        fs::read(bluetooth_zip).unwrap()
    );
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "verify-commit",
        &first,
    ]);
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "verify-commit",
        &second,
    ]);
    let refs = git(&[
        "--git-dir",
        &repo.display().to_string(),
        "for-each-ref",
        "--format=%(refname)",
    ]);
    assert_eq!(
        String::from_utf8(refs.stdout).unwrap().trim(),
        "refs/heads/firmware"
    );
    let paths = git(&[
        "--git-dir",
        &repo.display().to_string(),
        "ls-tree",
        "-r",
        "--name-only",
        &second,
    ]);
    let mut paths: Vec<_> = String::from_utf8(paths.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            "firmware.json",
            "kk3-max/base/v5.8/NS39_V5.8.zip",
            "kk3-max/base/v5.9/KK3_NS38_NS39_V5.9.zip",
        ]
    );

    check_export_and_invalid_append(temp.path(), &repo, &archive, &second);
}

fn source_fixture(temp: &Path, fixture: &SignedFixture) -> (PathBuf, String, Vec<u8>) {
    let source = temp.join("source");
    fs::create_dir(&source).unwrap();
    git(&["init", "--quiet", &source.display().to_string()]);
    git_at(&source, &["config", "user.name", "Source Fixture"]);
    git_at(&source, &["config", "user.email", "source@example.invalid"]);
    git_at(&source, &["config", "gpg.format", "openpgp"]);
    git_at(
        &source,
        &[
            "config",
            "gpg.program",
            &fixture.wrapper.display().to_string(),
        ],
    );
    git_at(
        &source,
        &["config", "user.signingkey", &fixture.fingerprint],
    );
    fs::write(source.join("README"), "fixture\n").unwrap();
    git_at(&source, &["add", "README"]);
    git_at(
        &source,
        &["commit", "--quiet", "-S", "-m", "source history"],
    );
    let source_head = String::from_utf8(git_at(&source, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();
    let source_status = git_at(&source, &["status", "--porcelain"]).stdout;

    (source, source_head, source_status)
}

fn check_export_and_invalid_append(temp: &Path, repo: &Path, archive: &GitArchive, second: &str) {
    let exported = temp.join("export.zip");
    let binary = assert_cmd::cargo::cargo_bin!("gulikit-archive");
    assert_cmd::Command::new(binary)
        .arg("read")
        .arg(repo)
        .args(["--path", "/kk3-max/base/v5.8/NS39_V5.8.zip", "--output"])
        .arg(&exported)
        .assert()
        .success();
    let original = fs::read(&exported).unwrap();
    assert_cmd::Command::new(binary)
        .arg("read")
        .arg(repo)
        .args([
            "--path",
            "/kk3-max/base/v5.9/KK3_NS38_NS39_V5.9.zip",
            "--output",
        ])
        .arg(&exported)
        .assert()
        .code(2);
    assert_eq!(fs::read(&exported).unwrap(), original);

    // A valid signature alone does not authorize a history entry without an append.
    let same_tree = String::from_utf8(
        git(&[
            "--git-dir",
            &repo.display().to_string(),
            "rev-parse",
            &format!("{second}^{{tree}}"),
        ])
        .stdout,
    )
    .unwrap();
    let invalid_commit = String::from_utf8(
        git(&[
            "--git-dir",
            &repo.display().to_string(),
            "commit-tree",
            same_tree.trim(),
            "-p",
            second,
            "-S",
            "-m",
            "invalid empty append",
        ])
        .stdout,
    )
    .unwrap();
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "update-ref",
        BRANCH,
        invalid_commit.trim(),
        second,
    ]);
    assert!(matches!(
        archive.index(),
        Err(GitArchiveError::InvalidHistory(_))
    ));
}

#[test]
#[cfg(unix)]
fn duplicate_identity_and_invalid_zip_leave_the_archive_ref_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init(&repo).unwrap();
    configure_archive(&repo, &fixture, true);
    let package = temp.path().join("main.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"one")).unwrap();
    let commit = archive
        .import(
            &package,
            metadata(Component::Base, "5.9", "KK3_NS38_NS39_V5.9.zip"),
        )
        .unwrap();
    let mut missing_member = metadata(Component::Base, "5.8", "historical.zip");
    missing_member.firmware_member = "missing.bin".to_owned();
    assert!(matches!(
        archive.import(&package, missing_member),
        Err(GitArchiveError::Zip(_))
    ));
    assert!(matches!(
        archive.import(
            &package,
            metadata(Component::Base, "5.9", "KK3_NS38_NS39_V5.9.zip")
        ),
        Err(GitArchiveError::Manifest(_))
    ));
    assert_eq!(
        String::from_utf8(
            git(&[
                "--git-dir",
                &repo.display().to_string(),
                "rev-parse",
                BRANCH
            ])
            .stdout
        )
        .unwrap()
        .trim(),
        commit
    );
    fs::write(&package, b"not a ZIP").unwrap();
    assert!(matches!(
        archive.import(&package, metadata(Component::Base, "5.8", "NS39_V5.8.zip")),
        Err(GitArchiveError::Zip(_))
    ));
    assert_eq!(archive.index().unwrap().releases().len(), 1);
}

#[test]
#[cfg(unix)]
fn failed_gpg_signing_does_not_publish_a_ref() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::without_key(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init(&repo).unwrap();
    configure_archive(&repo, &fixture, false);
    let package = temp.path().join("main.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"main firmware")).unwrap();

    assert!(
        archive
            .import(
                &package,
                metadata(Component::Base, "5.9", "KK3_NS38_NS39_V5.9.zip")
            )
            .is_err()
    );
    assert!(archive.index().unwrap().releases().is_empty());
    assert!(git_fails(&[
        "--git-dir",
        &repo.display().to_string(),
        "show-ref",
        "--verify",
        BRANCH
    ]));
}

#[test]
fn open_refuses_a_working_source_repository_and_init_refuses_existing_paths() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    git(&["init", "--quiet", &source.display().to_string()]);
    assert!(matches!(
        GitArchive::open(&source),
        Err(GitArchiveError::NotBare)
    ));
    assert!(matches!(
        GitArchive::init(&source),
        Err(GitArchiveError::AlreadyExists)
    ));
}

const BRANCH: &str = "refs/heads/firmware";

fn metadata(component: Component, version: &str, filename: &str) -> ReleaseMetadata {
    ReleaseMetadata {
        component,
        version: version.to_owned(),
        filename: filename.to_owned(),
        source_url: if component == Component::Base {
            "https://www.gulikit.com/newsinfo/887152.html".to_owned()
        } else {
            "https://www.gulikit.com/newsinfo/915900.html".to_owned()
        },
        released_at: None,
        retrieved_at: None,
        retrieved_from: None,
        changelog: None,
        changelog_source_url: None,
        firmware_member: "firmware.bin".to_owned(),
        published_hashes: Vec::new(),
    }
}

fn synthetic_zip(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(name, SimpleFileOptions::default())
        .unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap().into_inner()
}

fn commit_parents(repo: &Path, commit: &str) -> Vec<String> {
    let output = git(&[
        "--git-dir",
        &repo.display().to_string(),
        "rev-list",
        "--parents",
        "-n1",
        commit,
    ]);
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

fn configure_archive(repo: &Path, fixture: &SignedFixture, signing: bool) {
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "config",
        "user.name",
        "Archive Test Operator",
    ]);
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "config",
        "user.email",
        "archive-test@example.invalid",
    ]);
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "config",
        "gpg.program",
        &fixture.wrapper.display().to_string(),
    ]);
    if signing {
        git(&[
            "--git-dir",
            &repo.display().to_string(),
            "config",
            "user.signingkey",
            &fixture.fingerprint,
        ]);
    } else {
        git(&[
            "--git-dir",
            &repo.display().to_string(),
            "config",
            "user.signingkey",
            "0123456789012345678901234567890123456789",
        ]);
    }
}

struct SignedFixture {
    _directory: TempDir,
    home: PathBuf,
    wrapper: PathBuf,
    fingerprint: String,
}

impl SignedFixture {
    fn new(parent: &Path) -> Self {
        Self::create(parent, true)
    }

    fn without_key(parent: &Path) -> Self {
        Self::create(parent, false)
    }

    fn create(_parent: &Path, make_key: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;

        // Darwin's agent socket path must fit sockaddr_un, including its suffix.
        // The default per-user temporary directory is too long for nested homes.
        let mut builder = tempfile::Builder::new();
        builder.prefix("archive-gpg-");
        #[cfg(target_os = "macos")]
        let directory = builder.tempdir_in("/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let directory = builder.tempdir().unwrap();
        let home = directory.path().join("gnupg");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let fingerprint = if make_key {
            gpg(
                &home,
                &[
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    "Archive Test <archive-test@example.invalid>",
                    "rsa2048",
                    "sign",
                    "0",
                ],
            );
            let listing = gpg(&home, &["--batch", "--with-colons", "--list-secret-keys"]);
            String::from_utf8(listing.stdout)
                .unwrap()
                .lines()
                .find_map(|line| {
                    line.strip_prefix("fpr:")
                        .and_then(|line| line.split(':').nth(8))
                })
                .unwrap()
                .to_owned()
        } else {
            "0123456789012345678901234567890123456789".to_owned()
        };
        let wrapper = directory.path().join("gpg-wrapper");
        let home_shell = home.display().to_string().replace('\'', "'\\''");
        fs::write(
            &wrapper,
            format!("#!/bin/sh\nGNUPGHOME='{home_shell}'\nexport GNUPGHOME\nexec gpg \"$@\"\n"),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _directory: directory,
            home,
            wrapper,
            fingerprint,
        }
    }
}

impl Drop for SignedFixture {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.home)
            .arg("--kill")
            .arg("gpg-agent")
            .status();
    }
}

fn gpg(home: &Path, args: &[&str]) -> Output {
    Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .args(args)
        .output()
        .unwrap()
        .tap_success()
}

trait AssertSuccess {
    fn tap_success(self) -> Self;
}

impl AssertSuccess for Output {
    fn tap_success(self) -> Self {
        assert!(
            self.status.success(),
            "gpg failed: {}",
            String::from_utf8_lossy(&self.stderr)
        );
        self
    }
}

fn git(args: &[&str]) -> Output {
    run_git(Command::new("git").args(args))
}

fn git_at(directory: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("git");
    command.current_dir(directory).args(args);
    run_git(&mut command)
}

fn git_fails(args: &[&str]) -> bool {
    !git_output(Command::new("git").args(args)).status.success()
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

fn git_output(command: &mut Command) -> Output {
    let git_vars: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| !key.to_string_lossy().starts_with("GIT_"))
        .collect();
    command.env_clear();
    command.envs(git_vars);
    command.output().unwrap()
}
