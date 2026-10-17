//! One advisory owner across user and administrator invocations. Never unlink the lock.

use nix::{
    errno::Errno,
    fcntl::{OFlag, open},
    sys::stat::{Mode, fchmod},
};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub struct ProcessLock {
    file: File,
    path: PathBuf,
}
impl Drop for ProcessLock {
    fn drop(&mut self) {
        // A concurrently spawned helper may briefly inherit this open file
        // description before exec closes it. Ownership ends with this guard,
        // without waiting for every inherited descriptor to close.
        let _ = self.file.unlock();
    }
}
impl ProcessLock {
    pub fn acquire() -> Result<Self, String> {
        Self::at(Path::new("/tmp/gulikit-updater.lock"))
    }
    fn at(path: &Path) -> Result<Self, String> {
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let descriptor = match open(
            path,
            flags | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::from_bits_truncate(0o644),
        ) {
            Ok(fd) => {
                fchmod(&fd, Mode::from_bits_truncate(0o644)).map_err(|e| e.to_string())?;
                fd
            }
            Err(Errno::EEXIST) => open(path, flags, Mode::empty()).map_err(|e| e.to_string())?,
            Err(error) => return Err(error.to_string()),
        };
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
            return Err("Updater lock must be an empty regular file with one link".into());
        }
        file.try_lock()
            .map_err(|e| format!("Another updater owns the process lock: {e}"))?;
        let lock = Self {
            file,
            path: path.to_owned(),
        };
        lock.check()?;
        Ok(lock)
    }
    pub fn check(&self) -> Result<(), String> {
        let held = self.file.metadata().map_err(|e| e.to_string())?;
        let named = std::fs::symlink_metadata(&self.path).map_err(|e| e.to_string())?;
        if !named.is_file()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || named.nlink() != 1
            || named.len() != 0
        {
            return Err("Updater process lock changed; this session is invalid".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_second_owner_and_detects_a_replaced_lock_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("updater.lock");
        let first = ProcessLock::at(&path).unwrap();
        assert!(ProcessLock::at(&path).is_err());
        first.check().unwrap();
        drop(first);
        let second = ProcessLock::at(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::File::create(&path).unwrap();
        assert!(second.check().is_err());
    }
    #[test]
    fn guard_drop_releases_ownership_even_if_a_helper_inherits_the_description() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("updater.lock");
        let owner = ProcessLock::at(&path).unwrap();
        let inherited = owner.file.try_clone().unwrap();
        drop(owner);
        let next = ProcessLock::at(&path).unwrap();
        drop(inherited);
        next.check().unwrap();
        assert!(ProcessLock::at(&path).is_err());
    }
    #[test]
    fn refuses_symlinks_and_nonempty_files_without_writing_them() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("existing");
        std::fs::write(&target, b"preserve").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(ProcessLock::at(&target).is_err());
        assert!(ProcessLock::at(&link).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"preserve");
    }
}
