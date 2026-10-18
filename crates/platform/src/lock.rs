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
    unlock_on_drop: bool,
}
impl Drop for ProcessLock {
    fn drop(&mut self) {
        // A concurrently spawned helper may briefly inherit this open file
        // description before exec closes it. Ownership ends with this guard,
        // without waiting for every inherited descriptor to close.
        if self.unlock_on_drop {
            let _ = self.file.unlock();
        }
    }
}
impl ProcessLock {
    ///
    /// # Errors
    ///
    /// Returns an error if the updater lock cannot be opened safely, is already owned, or fails its file identity checks.
    pub fn acquire() -> Result<Self, String> {
        Self::at(Path::new("/tmp/gulikit-updater.lock"))
    }
    pub(crate) fn at(path: &Path) -> Result<Self, String> {
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
            unlock_on_drop: true,
        };
        lock.check()?;
        Ok(lock)
    }
    /// Descriptor passed to a Main I/O worker. The guardian retains ownership.
    ///
    /// # Errors
    ///
    /// Returns an error if lock identity changed or duplicating the held descriptor fails.
    pub fn worker_descriptor(&self) -> Result<File, String> {
        self.check()?;
        self.file.try_clone().map_err(|error| error.to_string())
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the guardian does not supply exactly one complete lease descriptor, reception fails, or the inherited lock is invalid.
    pub fn adopt_worker_stderr() -> Result<Self, String> {
        Self::adopt_worker_descriptor_at(PathBuf::from("/tmp/gulikit-updater.lock"))
    }
    pub(crate) fn adopt_worker_descriptor_at(path: PathBuf) -> Result<Self, String> {
        use rustix::net::{
            RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg,
        };
        use std::{
            io::IoSliceMut,
            mem::MaybeUninit,
            os::{fd::AsFd, unix::net::UnixStream},
            time::Duration,
        };
        let socket = UnixStream::from(
            std::io::stderr()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| error.to_string())?,
        );
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let mut byte = [0];
        let received = recvmsg(
            &socket,
            &mut [IoSliceMut::new(&mut byte)],
            &mut ancillary,
            RecvFlags::empty(),
        )
        .map_err(|error| error.to_string())?;
        let mut descriptors = Vec::new();
        for message in ancillary.drain() {
            match message {
                RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
                _ => return Err("Unexpected Main lease ancillary message".into()),
            }
        }
        if received.bytes != 1
            || byte != *b"L"
            || received.flags.contains(ReturnFlags::CTRUNC)
            || descriptors.len() != 1
        {
            return Err(
                "Main worker requires exactly one complete guardian lease descriptor".into(),
            );
        }
        // rustix owns received descriptors, including all rejection/cleanup paths.
        let received = File::from(descriptors.pop().expect("one descriptor checked"));
        let file = received.try_clone().map_err(|error| error.to_string())?; // CLOEXEC duplicate
        Self::inherited(file, path)
    }
    #[must_use]
    pub fn is_worker_lease(&self) -> bool {
        !self.unlock_on_drop
    }
    fn inherited(file: File, path: PathBuf) -> Result<Self, String> {
        let lock = Self {
            file,
            path,
            unlock_on_drop: false,
        };
        lock.check()?;
        // Reentrant only for the inherited open file description. Another owner refuses.
        lock.file.try_lock().map_err(|error| error.to_string())?;
        Ok(lock)
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the named lock no longer identifies the held, singly linked regular file.
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
    fn worker_drop_closes_its_descriptor_without_unlocking_the_guardians_lease() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("updater.lock");
        let guardian = ProcessLock::at(&path).unwrap();
        let worker =
            ProcessLock::inherited(guardian.file.try_clone().unwrap(), path.clone()).unwrap();
        drop(worker);
        assert!(ProcessLock::at(&path).is_err());
        drop(guardian);
        ProcessLock::at(&path).unwrap();
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
