//! Original manufacturer ZIP storage, separate from updater write authorization.
#![forbid(unsafe_code)]

mod content;
pub mod git;
pub mod manifest;
mod remote;

pub use git::{GitArchive, GitArchiveError};
pub use manifest::{Component, FirmwareIndex, FirmwareMemberKind, ReleaseMetadata, ReleaseRecord};
pub use remote::{
    ArchiveClient, ArchiveFetcher, ArchiveSnapshot, RemoteError, read_verified_archive,
};
