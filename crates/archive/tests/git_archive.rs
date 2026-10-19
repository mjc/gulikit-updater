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
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
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

    check_export_and_invalid_append(temp.path(), &repo, &archive, &second, &fixture.home);
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

fn check_export_and_invalid_append(
    temp: &Path,
    repo: &Path,
    archive: &GitArchive,
    second: &str,
    gpg_home: &Path,
) {
    let exported = temp.join("export.zip");
    let binary = assert_cmd::cargo::cargo_bin!("gulikit-archive");
    assert_cmd::Command::new(binary)
        .arg("read")
        .arg(repo)
        .env("GNUPGHOME", gpg_home)
        .args(["--path", "/kk3-max/base/v5.8/NS39_V5.8.zip", "--output"])
        .arg(&exported)
        .assert()
        .success();
    let original = fs::read(&exported).unwrap();
    assert_cmd::Command::new(binary)
        .arg("read")
        .arg(repo)
        .env("GNUPGHOME", gpg_home)
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
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);
    let package = temp.path().join("main.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"one")).unwrap();
    let commit = archive
        .import(
            &package,
            metadata(Component::Base, "5.9", "KK3_NS38_NS39_V5.9.zip"),
        )
        .unwrap();
    fs::write(&package, synthetic_duplicate_member_zip(b"one")).unwrap();
    assert!(matches!(
        archive.import(&package, metadata(Component::Base, "5.8", "duplicate-names.zip")),
        Err(GitArchiveError::Zip(message)) if message.contains("duplicate file names")
    ));
    assert_eq!(archive.index().unwrap().releases().len(), 1);
    fs::write(&package, synthetic_zip("firmware.bin", b"one")).unwrap();
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
fn signed_same_length_blob_replacement_is_rejected_before_listing_or_extending() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);
    let package = temp.path().join("original.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"one")).unwrap();
    let original = archive
        .import(&package, metadata(Component::Base, "5.9", "original.zip"))
        .unwrap();
    let replacement = temp.path().join("replacement.zip");
    fs::write(&replacement, synthetic_zip("firmware.bin", b"two")).unwrap();
    assert_eq!(
        fs::metadata(&package).unwrap().len(),
        fs::metadata(&replacement).unwrap().len()
    );
    let blob = git_text(
        &repo,
        &[
            "hash-object",
            "-w",
            "--no-filters",
            &replacement.display().to_string(),
        ],
    );
    git_repo(&repo, &["read-tree", &original]);
    git_repo(
        &repo,
        &[
            "update-index",
            "--cacheinfo",
            "100644",
            &blob,
            "kk3-max/base/v5.9/original.zip",
        ],
    );
    let tree = git_text(&repo, &["write-tree"]);
    let rewritten = git_text(
        &repo,
        &["commit-tree", &tree, "-S", "-m", "same-length invalid root"],
    );
    git_repo(&repo, &["update-ref", BRANCH, &rewritten, &original]);
    assert!(matches!(
        GitArchive::open_with_gpg_home(&repo, &fixture.home),
        Err(GitArchiveError::InvalidBlob)
    ));
    assert!(matches!(archive.index(), Err(GitArchiveError::InvalidBlob)));
    assert!(matches!(
        archive.import(&package, metadata(Component::Base, "5.8", "new.zip")),
        Err(GitArchiveError::InvalidBlob)
    ));
    assert_eq!(git_text(&repo, &["rev-parse", BRANCH]), rewritten);
}

#[test]
fn recursive_tree_expansion_is_rejected_despite_a_small_root_tree() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);
    let package = temp.path().join("original.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"one")).unwrap();
    let original = archive
        .import(&package, metadata(Component::Base, "5.9", "original.zip"))
        .unwrap();
    let blob = git_text(&repo, &["rev-parse", &format!("{original}:firmware.json")]);
    let mut expanded_tree = Vec::new();
    for n in 0..2400 {
        expanded_tree.extend_from_slice(format!("100644 {n:04}{}\0", "x".repeat(230)).as_bytes());
        expanded_tree.extend_from_slice(&hex::decode(&blob).unwrap());
    }
    let subtree_file = temp.path().join("subtree");
    fs::write(&subtree_file, expanded_tree).unwrap();
    let subtree = git_text(
        &repo,
        &[
            "hash-object",
            "-w",
            "-t",
            "tree",
            &subtree_file.display().to_string(),
        ],
    );
    let tree = git_repo(
        &repo,
        &["cat-file", "tree", &format!("{original}^{{tree}}")],
    )
    .stdout;
    let mut root = tree;
    root.extend_from_slice(b"40000 overflow\0");
    root.extend_from_slice(&hex::decode(&subtree).unwrap());
    assert!(root.len() < 1024);
    let root_file = temp.path().join("root");
    fs::write(&root_file, root).unwrap();
    let tree = git_text(
        &repo,
        &[
            "hash-object",
            "-w",
            "-t",
            "tree",
            &root_file.display().to_string(),
        ],
    );
    let rewritten = git_text(
        &repo,
        &["commit-tree", &tree, "-S", "-m", "oversized recursive tree"],
    );
    git_repo(&repo, &["update-ref", BRANCH, &rewritten, &original]);
    assert!(matches!(
        GitArchive::open_with_gpg_home(&repo, &fixture.home),
        Err(GitArchiveError::InvalidTree)
    ));
}

fn git_repo(repo: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("git");
    command.current_dir(repo).arg("--git-dir=.").args(args);
    run_git(&mut command)
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    String::from_utf8(git_repo(repo, args).stdout)
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
#[cfg(unix)]
fn failed_gpg_signing_does_not_publish_a_ref() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::without_key(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
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
    assert_eq!(archive.index().unwrap().releases(), []);
    assert!(git_fails(&[
        "--git-dir",
        &repo.display().to_string(),
        "show-ref",
        "--verify",
        BRANCH
    ]));
}

#[test]
#[cfg(unix)]
fn repository_local_gpg_helpers_cannot_sign_or_forge_verification() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);

    let marker = temp.path().join("malicious-gpg-helper-ran");
    let marker_shell = marker.display().to_string().replace('\'', "'\\''");
    let malicious_helper = temp.path().join("fake-gpg");
    fs::write(
        &malicious_helper,
        format!(
            "#!/bin/sh\nprintf invoked >> '{marker_shell}'\nprintf '[GNUPG:] GOODSIG 0123456789012345678901234567890123456789 Forged\\n[GNUPG:] VALIDSIG 0123456789012345678901234567890123456789 2026-10-18 1792329600 0 4 0 1 10 00 0123456789012345678901234567890123456789\\n'\nexit 0\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&malicious_helper, fs::Permissions::from_mode(0o700)).unwrap();
    for key in [
        "gpg.program",
        "gpg.openpgp.program",
        "gpg.x509.program",
        "gpg.ssh.program",
    ] {
        git(&[
            "--git-dir",
            &repo.display().to_string(),
            "config",
            key,
            &malicious_helper.display().to_string(),
        ]);
    }

    let package = temp.path().join("original.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"firmware")).unwrap();
    let signed = archive
        .import(&package, metadata(Component::Base, "5.9", "original.zip"))
        .unwrap();
    assert_eq!(archive.index().unwrap().releases().len(), 1);
    assert!(!marker.exists());

    let tree = git_text(&repo, &["rev-parse", &format!("{signed}^{{tree}}")]);
    let unsigned = git_text(
        &repo,
        &["commit-tree", &tree, "-p", &signed, "-m", "unsigned child"],
    );
    git_repo(&repo, &["update-ref", BRANCH, &unsigned, &signed]);
    assert!(matches!(
        GitArchive::open_with_gpg_home(&repo, &fixture.home),
        Err(GitArchiveError::InvalidHistory(
            "commit has no signature for its object format"
        ))
    ));
    assert!(!marker.exists());

    check_rejected_signature_headers(
        temp.path(),
        &repo,
        &archive,
        &tree,
        &signed,
        &unsigned,
        &marker,
    );
}

fn check_rejected_signature_headers(
    temp: &Path,
    repo: &Path,
    archive: &GitArchive,
    tree: &str,
    signed: &str,
    unsigned: &str,
    marker: &Path,
) {
    let malformed_commit = format!(
        "tree {tree}\nparent {signed}\nauthor Archive Test <archive-test@example.invalid> 1792329600 +0000\ncommitter Archive Test <archive-test@example.invalid> 1792329600 +0000\ngpgsig -----BEGIN SSH SIGNATURE-----\n -----END SSH SIGNATURE-----\n\nwrong signature backend\n"
    );
    let malformed_file = temp.join("wrong-signature-backend.commit");
    fs::write(&malformed_file, malformed_commit).unwrap();
    let malformed = git_text(
        repo,
        &[
            "hash-object",
            "-t",
            "commit",
            "-w",
            &malformed_file.display().to_string(),
        ],
    );
    git_repo(repo, &["update-ref", BRANCH, &malformed, unsigned]);
    assert!(matches!(
        archive.index(),
        Err(GitArchiveError::InvalidHistory(
            "commit contains a non-OpenPGP signature"
        ))
    ));
    assert!(!marker.exists());

    let wrong_hash_header = format!(
        "tree {tree}\nparent {signed}\nauthor Archive Test <archive-test@example.invalid> 1792329600 +0000\ncommitter Archive Test <archive-test@example.invalid> 1792329600 +0000\ngpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n -----END PGP SIGNATURE-----\n\nwrong hash signature header\n"
    );
    let wrong_hash_file = temp.join("wrong-hash-signature.commit");
    fs::write(&wrong_hash_file, wrong_hash_header).unwrap();
    let wrong_hash = git_text(
        repo,
        &[
            "hash-object",
            "-t",
            "commit",
            "-w",
            &wrong_hash_file.display().to_string(),
        ],
    );
    git_repo(repo, &["update-ref", BRANCH, &wrong_hash, &malformed]);
    assert!(matches!(
        archive.index(),
        Err(GitArchiveError::InvalidHistory(
            "commit has no signature for its object format"
        ))
    ));
    assert!(!marker.exists());

    let duplicate_signature = format!(
        "tree {tree}\nparent {signed}\nauthor Archive Test <archive-test@example.invalid> 1792329600 +0000\ncommitter Archive Test <archive-test@example.invalid> 1792329600 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n -----END PGP SIGNATURE-----\ngpgsig -----BEGIN PGP SIGNATURE-----\n -----END PGP SIGNATURE-----\n\nduplicate signature headers\n"
    );
    let duplicate_file = temp.join("duplicate-signature.commit");
    fs::write(&duplicate_file, duplicate_signature).unwrap();
    let duplicate = git_text(
        repo,
        &[
            "hash-object",
            "-t",
            "commit",
            "-w",
            &duplicate_file.display().to_string(),
        ],
    );
    git_repo(repo, &["update-ref", BRANCH, &duplicate, &wrong_hash]);
    assert!(matches!(
        archive.index(),
        Err(GitArchiveError::InvalidHistory(
            "commit has duplicate SHA-1 signature headers"
        ))
    ));
    assert!(!marker.exists());
}

#[test]
#[cfg(unix)]
fn repository_reference_transaction_hooks_are_never_run() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);

    let hook_dir = temp.path().join("repository-hooks");
    fs::create_dir(&hook_dir).unwrap();
    let marker = temp.path().join("reference-hook-ran");
    let marker_shell = marker.display().to_string().replace('\'', "'\\''");
    let hook = hook_dir.join("reference-transaction");
    fs::write(
        &hook,
        format!("#!/bin/sh\nprintf invoked > '{marker_shell}'\nexit 1\n"),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "config",
        "core.hooksPath",
        &hook_dir.display().to_string(),
    ]);

    let package = temp.path().join("main.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"firmware")).unwrap();
    archive
        .import(&package, metadata(Component::Base, "5.9", "original.zip"))
        .unwrap();

    assert!(!marker.exists());
    assert_eq!(archive.index().unwrap().releases().len(), 1);
}

#[test]
fn duplicate_tree_headers_are_rejected_before_signature_validation() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);
    let package = temp.path().join("main.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"firmware")).unwrap();
    let parent = archive
        .import(&package, metadata(Component::Base, "5.9", "original.zip"))
        .unwrap();
    let tree = git_text(&repo, &["rev-parse", &format!("{parent}^{{tree}}")]);
    let commit = format!(
        "tree {tree}\nparent {parent}\nauthor Archive Test <archive-test@example.invalid> 1792329600 +0000\ncommitter Archive Test <archive-test@example.invalid> 1792329600 +0000\ntree {tree}\n\nmalformed duplicate-tree commit\n"
    );
    let commit_file = temp.path().join("duplicate-tree-commit");
    fs::write(&commit_file, commit).unwrap();
    let malformed = git_text(
        &repo,
        &[
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            &commit_file.display().to_string(),
        ],
    );
    git_repo(&repo, &["update-ref", BRANCH, &malformed, &parent]);

    assert!(matches!(
        archive.index(),
        Err(GitArchiveError::InvalidHistory(
            "commit has duplicate tree headers"
        ))
    ));
}

#[test]
fn signed_commits_with_commit_oids_in_tree_headers_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    let archive = GitArchive::init_with_gpg_home(&repo, &fixture.home).unwrap();
    configure_archive(&repo, &fixture, true);

    let package = temp.path().join("firmware.zip");
    fs::write(&package, synthetic_zip("firmware.bin", b"root firmware")).unwrap();
    let root = archive
        .import(&package, metadata(Component::Base, "5.9", "root.zip"))
        .unwrap();

    // A signed malformed root whose tree header points to a commit object still
    // exposes that commit's tree through `git ls-tree <commit>`. The archive
    // validator must reject the object type before interpreting that tree.
    let malformed_root = signed_commit_with_tree_oid(
        temp.path(),
        &repo,
        &fixture,
        &root,
        None,
        "malformed signed root",
    );
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "verify-commit",
        &malformed_root,
    ]);
    set_archive_ref(&repo, &malformed_root);
    assert_archive_rejects_invalid_tree(
        &archive,
        &repo,
        &fixture,
        &package,
        "5.8",
        "rejected-root.zip",
    );
    set_archive_ref(&repo, &root);
    assert_eq!(archive.index().unwrap().releases().len(), 1);
    assert_eq!(
        archive.read("/kk3-max/base/v5.9/root.zip").unwrap(),
        fs::read(&package).unwrap()
    );

    fs::write(&package, synthetic_zip("firmware.bin", b"second firmware")).unwrap();
    let second = archive
        .import(&package, metadata(Component::Base, "5.8", "second.zip"))
        .unwrap();
    fs::write(&package, synthetic_zip("firmware.bin", b"third firmware")).unwrap();
    let donor = archive
        .import(&package, metadata(Component::Base, "5.7", "third.zip"))
        .unwrap();

    // The donor commit's tree has one appended release. Referencing its commit
    // OID from a signed child must not make that commit-ish tree acceptable.
    let malformed_append = signed_commit_with_tree_oid(
        temp.path(),
        &repo,
        &fixture,
        &donor,
        Some(&second),
        "malformed signed append",
    );
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "verify-commit",
        &malformed_append,
    ]);
    set_archive_ref(&repo, &malformed_append);
    assert_archive_rejects_invalid_tree(
        &archive,
        &repo,
        &fixture,
        &package,
        "5.6",
        "rejected-append.zip",
    );
    set_archive_ref(&repo, &second);
    assert_eq!(archive.index().unwrap().releases().len(), 2);
    assert_eq!(
        archive.read("/kk3-max/base/v5.8/second.zip").unwrap(),
        synthetic_zip("firmware.bin", b"second firmware")
    );
}

fn assert_archive_rejects_invalid_tree(
    archive: &GitArchive,
    repo: &Path,
    fixture: &SignedFixture,
    package: &Path,
    version: &str,
    filename: &str,
) {
    assert!(matches!(
        GitArchive::open_with_gpg_home(repo, &fixture.home),
        Err(GitArchiveError::InvalidTree)
    ));
    assert!(matches!(archive.index(), Err(GitArchiveError::InvalidTree)));
    assert!(matches!(
        archive.import(package, metadata(Component::Base, version, filename)),
        Err(GitArchiveError::InvalidTree)
    ));
}

fn signed_commit_with_tree_oid(
    temp: &Path,
    repo: &Path,
    fixture: &SignedFixture,
    tree_oid: &str,
    parent: Option<&str>,
    message: &str,
) -> String {
    let parent_header = parent.map_or_else(String::new, |parent| format!("parent {parent}\n"));
    let unsigned = format!(
        "tree {tree_oid}\n{parent_header}author Archive Test <archive-test@example.invalid> 1792329600 +0000\ncommitter Archive Test <archive-test@example.invalid> 1792329600 +0000\n\n{message}\n"
    );
    let mut signer = Command::new("gpg");
    signer
        .arg("--homedir")
        .arg(&fixture.home)
        .args([
            "--batch",
            "--armor",
            "--detach-sign",
            "--local-user",
            &fixture.fingerprint,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = signer.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(unsigned.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap().tap_success();
    let signature = String::from_utf8(output.stdout).unwrap();
    let signature_header = signature
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                format!("gpgsig {line}\n")
            } else {
                format!(" {line}\n")
            }
        })
        .collect::<String>();
    let commit_bytes = unsigned.replacen(
        &format!("\n\n{message}\n"),
        &format!("\n{signature_header}\n{message}\n"),
        1,
    );
    let commit_file = temp.join(format!("{message}.commit"));
    fs::write(&commit_file, commit_bytes).unwrap();
    let output = git(&[
        "--git-dir",
        &repo.display().to_string(),
        "hash-object",
        "--literally",
        "-t",
        "commit",
        "-w",
        &commit_file.display().to_string(),
    ]);
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn set_archive_ref(repo: &Path, oid: &str) {
    fs::write(repo.join("refs/heads/firmware"), format!("{oid}\n")).unwrap();
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

#[test]
fn sha256_archive_imports_and_reads_a_signed_release() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = SignedFixture::new(temp.path());
    let repo = temp.path().join("archive.git");
    git(&[
        "init",
        "--quiet",
        "--bare",
        "--object-format=sha256",
        "--initial-branch=firmware",
        &repo.display().to_string(),
    ]);
    configure_archive(&repo, &fixture, true);
    let archive = GitArchive::open_with_gpg_home(&repo, &fixture.home).unwrap();
    let bytes = synthetic_zip("firmware.bin", b"sha256 archive firmware");
    let package = temp.path().join("firmware.zip");
    fs::write(&package, &bytes).unwrap();
    let commit = archive
        .import(&package, metadata(Component::Base, "5.9", "firmware.zip"))
        .unwrap();
    assert_eq!(commit.len(), 64);
    assert_eq!(archive.index().unwrap().releases().len(), 1);
    assert_eq!(
        archive.read("/kk3-max/base/v5.9/firmware.zip").unwrap(),
        bytes
    );
}

const BRANCH: &str = "refs/heads/firmware";

fn metadata(component: Component, version: &str, filename: &str) -> ReleaseMetadata {
    ReleaseMetadata {
        product: "kk3-max".to_owned(),
        member_kind: gulikit_archive::manifest::FirmwareMemberKind::Kk3,
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

fn synthetic_duplicate_member_zip(content: &[u8]) -> Vec<u8> {
    let first_name = "firmware.bin";
    let second_name = "not-used.bin";
    assert_eq!(first_name.len(), second_name.len());
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let contents: [&[u8]; 2] = [content, b"different duplicate content"];
    for (index, data) in contents.into_iter().enumerate() {
        let member_name = if index == 0 { first_name } else { second_name };
        writer
            .start_file(member_name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(data).unwrap();
    }
    let mut bytes = writer.finish().unwrap().into_inner();
    let positions: Vec<_> = bytes
        .windows(second_name.len())
        .enumerate()
        .filter_map(|(index, window)| (window == second_name.as_bytes()).then_some(index))
        .collect();
    for position in &positions {
        bytes[*position..*position + first_name.len()].copy_from_slice(first_name.as_bytes());
    }
    assert_eq!(
        positions.len(),
        2,
        "expected local and central name records"
    );
    bytes
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
    git(&[
        "--git-dir",
        &repo.display().to_string(),
        "config",
        "gpg.openpgp.program",
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
