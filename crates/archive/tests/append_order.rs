#![cfg(unix)]

use gulikit_archive::{Component, GitArchive, GitArchiveError, ReleaseMetadata};
use std::{
    fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::{TempDir, tempdir};
use zip::{ZipWriter, write::SimpleFileOptions};

const BRANCH: &str = "refs/heads/firmware";

#[test]
fn signed_history_rejects_reordering_and_front_insertion() {
    let temp = tempdir().unwrap();
    let signing = SigningFixture::new();
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &signing.home).unwrap();
    configure_archive(&repo, &signing);

    let commits: Vec<_> = (0..4)
        .map(|index| {
            let version = ["5.9", "5.8", "5.7", "5.6"][index];
            let filename = format!("release-{version}.zip");
            let package = temp.path().join(&filename);
            fs::write(&package, synthetic_zip(b"firmware bytes")).unwrap();
            archive
                .import(&package, metadata(version, &filename))
                .unwrap()
        })
        .collect();

    assert_eq!(archive.index().unwrap().releases().len(), 4);

    let reordered_tree = rewrite_index(&repo, &commits[2], |releases| {
        releases.swap(0, 1);
    });
    let reordered_commit = signed_commit(&repo, &reordered_tree, &commits[1], &signing.home);
    move_ref(&repo, &reordered_commit, &commits[3]);
    assert_invalid_history(&archive, &repo, temp.path(), &signing.home);

    move_ref(&repo, &commits[3], &reordered_commit);
    let front_insert_tree = rewrite_index(&repo, &commits[3], |releases| {
        let newest = releases.pop().unwrap();
        releases.insert(0, newest);
    });
    let front_insert_commit = signed_commit(&repo, &front_insert_tree, &commits[2], &signing.home);
    move_ref(&repo, &front_insert_commit, &commits[3]);
    assert_invalid_history(&archive, &repo, temp.path(), &signing.home);
}

fn assert_invalid_history(archive: &GitArchive, repo: &Path, temp: &Path, gpg_home: &Path) {
    assert!(matches!(
        GitArchive::open_with_gpg_home(repo, gpg_home),
        Err(GitArchiveError::InvalidHistory(_))
    ));
    assert!(matches!(
        archive.index(),
        Err(GitArchiveError::InvalidHistory(_))
    ));

    let package = temp.join("rejected.zip");
    fs::write(&package, synthetic_zip(b"new firmware")).unwrap();
    assert!(matches!(
        archive.import(&package, metadata("5.5", "rejected.zip")),
        Err(GitArchiveError::InvalidHistory(_))
    ));
}

fn rewrite_index(
    repo: &Path,
    commit: &str,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) -> String {
    let manifest = git(repo, &["show", &format!("{commit}:firmware.json")]);
    let mut value: serde_json::Value = serde_json::from_slice(&manifest.stdout).unwrap();
    let releases = value["releases"].as_array_mut().unwrap();
    mutate(releases);
    let bytes = serde_json::to_vec_pretty(&value).unwrap();

    let index_file = TempDir::new().unwrap();
    let index_path = index_file.path().join("index");
    git_env(repo, &["read-tree", commit], &index_path);
    let blob = git_input_env(
        repo,
        &["hash-object", "-w", "--no-filters", "--stdin"],
        &index_path,
        &bytes,
    );
    let blob = String::from_utf8(blob.stdout).unwrap().trim().to_owned();
    git_env(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            &blob,
            "firmware.json",
        ],
        &index_path,
    );
    String::from_utf8(git_env(repo, &["write-tree"], &index_path).stdout)
        .unwrap()
        .trim()
        .to_owned()
}

fn signed_commit(repo: &Path, tree: &str, parent: &str, gpg_home: &Path) -> String {
    let mut command = Command::new("git");
    command
        .arg(format!("--git-dir={}", repo.display()))
        .args([
            "-c",
            "gpg.format=openpgp",
            "commit-tree",
            tree,
            "-p",
            parent,
            "-S",
        ])
        .env("GNUPGHOME", gpg_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"Adversarial append-order fixture\n")
        .unwrap();
    String::from_utf8(assert_success(child.wait_with_output().unwrap()).stdout)
        .unwrap()
        .trim()
        .to_owned()
}

fn move_ref(repo: &Path, new: &str, old: &str) {
    git(repo, &["update-ref", BRANCH, new, old]);
}

fn configure_archive(repo: &Path, fixture: &SigningFixture) {
    for (key, value) in [
        ("user.name", "Append Order Test"),
        ("user.email", "append-order@example.invalid"),
        ("user.signingkey", &fixture.fingerprint),
    ] {
        git(repo, &["config", key, value]);
    }
}

fn metadata(version: &str, filename: &str) -> ReleaseMetadata {
    ReleaseMetadata {
        product: "kk3-max".to_owned(),
        member_kind: gulikit_archive::manifest::FirmwareMemberKind::Kk3,
        component: Component::Base,
        version: version.to_owned(),
        filename: filename.to_owned(),
        source_url: "https://example.com/releases".to_owned(),
        released_at: None,
        retrieved_at: None,
        retrieved_from: None,
        changelog: None,
        changelog_source_url: None,
        firmware_member: "firmware.bin".to_owned(),
        published_hashes: Vec::new(),
    }
}

fn synthetic_zip(contents: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("firmware.bin", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap().into_inner()
}

fn git(repo: &Path, args: &[&str]) -> Output {
    assert_success(
        Command::new("git")
            .arg(format!("--git-dir={}", repo.display()))
            .args(args)
            .output()
            .unwrap(),
    )
}

fn git_env(repo: &Path, args: &[&str], index: &Path) -> Output {
    assert_success(
        Command::new("git")
            .arg(format!("--git-dir={}", repo.display()))
            .env("GIT_INDEX_FILE", index)
            .args(args)
            .output()
            .unwrap(),
    )
}

fn git_input_env(repo: &Path, args: &[&str], index: &Path, input: &[u8]) -> Output {
    let mut child = Command::new("git")
        .arg(format!("--git-dir={}", repo.display()))
        .env("GIT_INDEX_FILE", index)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    assert_success(child.wait_with_output().unwrap())
}

fn assert_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct SigningFixture {
    _directory: TempDir,
    home: PathBuf,
    fingerprint: String,
}

impl SigningFixture {
    fn new() -> Self {
        let mut builder = tempfile::Builder::new();
        let directory = builder.prefix("append-order-gpg-");
        #[cfg(target_os = "macos")]
        let directory = directory.tempdir_in("/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let directory = directory.tempdir().unwrap();

        let home = directory.path().join("gnupg");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let generated = gpg(
            &home,
            &[
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Append Order Test <append-order@example.invalid>",
                "rsa2048",
                "sign",
                "0",
            ],
        );
        assert_success(generated);
        let listing = assert_success(gpg(
            &home,
            &["--batch", "--with-colons", "--list-secret-keys"],
        ));
        let fingerprint = String::from_utf8(listing.stdout)
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("fpr:")
                    .and_then(|line| line.split(':').nth(8))
            })
            .unwrap()
            .to_owned();

        Self {
            _directory: directory,
            home,
            fingerprint,
        }
    }
}

impl Drop for SigningFixture {
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
}
