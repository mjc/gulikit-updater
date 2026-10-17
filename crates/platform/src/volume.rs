//! Directory-relative, exclusive firmware files; no cached path is used for writes.

use nix::{
    fcntl::{OFlag, open, openat},
    sys::stat::Mode,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub struct Volume {
    root: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    destination: Option<File>,
}
impl Volume {
    /// Bind an opened directory to the OS device number of its selected filesystem.
    pub fn open_on_device(path: &Path, device: u64) -> Result<Self, String> {
        let volume = Self::open(path)?;
        if volume.device != device {
            return Err("Opened root does not belong to the selected USB volume".into());
        }
        Ok(volume)
    }
    pub fn open(path: &Path) -> Result<Self, String> {
        let root = File::from(
            open(
                path,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let metadata = root.metadata().map_err(|e| e.to_string())?;
        let volume = Self {
            root,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            destination: None,
        };
        volume.check_root()?;
        Ok(volume)
    }
    pub fn check_root(&self) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err("Selected volume root changed; rediscovery is required".into());
        }
        Ok(())
    }
    pub fn read_version(&self) -> Result<Vec<u8>, String> {
        self.check_root()?;
        let file = File::from(
            openat(
                &self.root,
                "GULI.TXT",
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("GULI.TXT must be a regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 4096 {
            return Err("GULI.TXT exceeds 4096 bytes".into());
        }
        Ok(bytes)
    }
    pub fn create(&mut self) -> Result<(), String> {
        self.check_root()?;
        if self.destination.is_some() {
            return Err("A destination is already open".into());
        }
        self.destination = Some(File::from(
            openat(
                &self.root,
                "NS39_KK3_MAX_V5.9.bin",
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|e| e.to_string())?,
        ));
        Ok(())
    }
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, gulikit_core::update::SubmissionError> {
        self.check_root()
            .map_err(gulikit_core::update::SubmissionError::before)?;
        self.destination
            .as_mut()
            .ok_or_else(|| gulikit_core::update::SubmissionError::before("No open firmware file"))?
            .write(bytes)
            .map_err(|error| error.to_string().into())
    }
    pub fn flush(&mut self) -> Result<(), String> {
        self.destination
            .as_ref()
            .ok_or("No open firmware file")?
            .sync_all()
            .map_err(|e| e.to_string())
    }
    pub fn close(&mut self) -> Result<(), String> {
        if let Some(file) = self.destination.take() {
            nix::unistd::close(file).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_before_open_is_not_the_selected_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("GULI.TXT"), b"www.gulikit.com\nversion 5.8").unwrap();
        let replacement_device = std::fs::metadata(dir.path()).unwrap().dev();
        assert!(
            Volume::open_on_device(dir.path(), replacement_device.checked_add(1).unwrap()).is_err()
        );
        assert!(!dir.path().join("NS39_KK3_MAX_V5.9.bin").exists());
    }
    #[test]
    fn rejects_symlinked_version_and_existing_destination_without_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("GULI.TXT")).unwrap();
        let mut volume = Volume::open(dir.path()).unwrap();
        assert!(volume.read_version().is_err());
        std::fs::write(
            dir.path().join("NS39_KK3_MAX_V5.9.bin"),
            b"previous attempt",
        )
        .unwrap();
        assert!(volume.create().is_err());
        assert_eq!(
            std::fs::read(dir.path().join("NS39_KK3_MAX_V5.9.bin")).unwrap(),
            b"previous attempt"
        );
    }
    #[test]
    fn refuses_replaced_root_and_bounded_nonregular_version() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let volume = Volume::open(&root).unwrap();
        std::fs::write(root.join("GULI.TXT"), vec![b' '; 4097]).unwrap();
        assert!(volume.read_version().is_err());
        std::fs::rename(&root, parent.path().join("old")).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(volume.check_root().is_err());
    }
    #[test]
    fn exact_bytes_are_durable_before_checked_close() {
        let root = tempfile::tempdir().unwrap();
        let mut volume = Volume::open(root.path()).unwrap();
        volume.create().unwrap();
        volume.write(b"unchanged bytes").unwrap();
        volume.flush().unwrap();
        volume.close().unwrap();
        assert_eq!(
            std::fs::read(root.path().join("NS39_KK3_MAX_V5.9.bin")).unwrap(),
            b"unchanged bytes"
        );
    }
}
