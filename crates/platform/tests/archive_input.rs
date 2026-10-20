use gulikit_core::package::{
    ArchiveParserKind, ArchiveSelection, ArchiveSelectionData, Component, PackageError,
};
use gulikit_platform::{InspectError, inspect_archive_package};

fn selection() -> ArchiveSelection {
    let release = &gulikit_core::package::catalog()[0];
    ArchiveSelection::try_from(ArchiveSelectionData {
        archive_revision: "a".repeat(40),
        path: format!("/kk3-max/base/v{}/{}", release.version, release.archive),
        component: Component::Main,
        version: release.version.into(),
        archive: release.archive.into(),
        archive_size: release.archive_size as u64,
        archive_sha256: release.archive_sha256.into(),
        firmware_member: release.member.into(),
        member_size: release.member_size() as u64,
        member_sha256: release.member_sha256().into(),
        payload_size: release.payload_size() as u64,
        payload_sha256: release.payload_sha256().into(),
        source_url: release.source_url.into(),
        parser: ArchiveParserKind::MainBinV1,
    })
    .unwrap()
}

#[test]
fn selected_archive_reread_rejects_changed_bytes_and_excess_size() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("selected.zip");
    let selection = selection();
    let size = usize::try_from(selection.data().archive_size).unwrap();
    std::fs::write(&path, vec![0; size]).unwrap();
    assert!(matches!(
        inspect_archive_package(&path, &selection),
        Err(InspectError::Rejected(PackageError::Digest {
            kind: "archive"
        }))
    ));
    std::fs::write(&path, vec![0; size + 10]).unwrap();
    let error = inspect_archive_package(&path, &selection).unwrap_err();
    assert!(
        matches!(error, InspectError::Rejected(PackageError::Size { kind: "archive", actual, .. }) if actual == size + 1)
    );
}

#[cfg(unix)]
#[test]
fn selected_archive_reread_refuses_symlinks_directories_and_nonblocking_fifos() {
    use nix::{sys::stat::Mode, unistd::mkfifo};
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.zip");
    std::fs::write(&target, b"not firmware").unwrap();
    let link = directory.path().join("link.zip");
    symlink(&target, &link).unwrap();
    assert!(matches!(
        inspect_archive_package(&link, &selection()),
        Err(InspectError::Io(_))
    ));
    assert!(matches!(
        inspect_archive_package(directory.path(), &selection()),
        Err(InspectError::NotFile)
    ));
    let fifo = directory.path().join("fifo.zip");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    assert!(matches!(
        inspect_archive_package(&fifo, &selection()),
        Err(InspectError::NotFile)
    ));
}
