//! Signed, append-only storage for complete firmware ZIP archives.
//!
//! The archive is a bare Git repository with one orphan branch. It stores
//! original ZIP bytes and a measured JSON index; it does not authorize writes.

use crate::manifest::{
    Error as ManifestError, FirmwareIndex, MAX_ARCHIVE_BYTES, MAX_INDEX_BYTES, MAX_RELEASES,
    ReleaseMetadata, ReleaseRecord,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
};
use thiserror::Error;

const BRANCH: &str = "refs/heads/firmware";
const MAX_COMMIT_BYTES: u64 = 1024 * 1024;
const MAX_TREE_BYTES: u64 = 512 * 1024;
const MAX_ZIP_MEMBERS: usize = 4096;
const MAX_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Errors from repository validation, signed imports, and archive reads.
#[derive(Debug, Error)]
pub enum GitArchiveError {
    #[error("archive repository path already exists")]
    AlreadyExists,
    #[error("archive repository path is not a directory")]
    InvalidRepositoryPath,
    #[error("repository is not a bare Git archive")]
    NotBare,
    #[error("archive repository has an unexpected ref or HEAD")]
    InvalidRefs,
    #[error("archive history is invalid: {0}")]
    InvalidHistory(&'static str),
    #[error("archive tree does not match its index")]
    InvalidTree,
    #[error("archive blob does not match its measured record")]
    InvalidBlob,
    #[error("Git command failed: {0}")]
    Git(String),
    #[error("could not resolve an absolute host GPG executable from PATH")]
    GpgProgramUnavailable,
    #[error("GPG home is not an existing directory")]
    InvalidGpgHome,
    #[error("archive ZIP is invalid or exceeds safety limits: {0}")]
    Zip(String),
    #[error("package path is not a regular file")]
    NotRegularFile,
    #[error("package file exceeds the archive size limit")]
    PackageTooLarge,
    #[error("requested release is not in the archive")]
    ReleaseNotFound,
    #[error("archive ref changed during import")]
    RefChanged,
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A handle to an isolated bare repository whose only branch is `firmware`.
#[derive(Clone, Debug)]
pub struct GitArchive {
    path: PathBuf,
    object_id_len: usize,
    gpg: GpgContext,
    hooks: HookDirectory,
}

#[derive(Clone, Debug)]
struct HookDirectory {
    _owner: Arc<tempfile::TempDir>,
    path: PathBuf,
}

impl HookDirectory {
    fn new() -> Result<Self, GitArchiveError> {
        let owner = Arc::new(tempfile::TempDir::new()?);
        let path = fs::canonicalize(owner.path())?;
        Ok(Self {
            _owner: owner,
            path,
        })
    }
}

#[derive(Clone, Debug)]
struct GpgContext {
    program: Option<PathBuf>,
    home: Option<PathBuf>,
}

impl GpgContext {
    fn from_host(home: Option<&Path>) -> Result<Self, GitArchiveError> {
        let home = home.map(canonical_gpg_home).transpose()?;
        Ok(Self {
            program: resolve_host_gpg_program(),
            home,
        })
    }

    fn program(&self) -> Result<&Path, GitArchiveError> {
        self.program
            .as_deref()
            .ok_or(GitArchiveError::GpgProgramUnavailable)
    }
}

impl GitArchive {
    /// Create a new bare archive repository at a path that does not exist.
    ///
    /// # Errors
    /// Rejects an existing path or a failed bare-repository initialization.
    pub fn init(path: &Path) -> Result<Self, GitArchiveError> {
        Self::init_with_context(path, GpgContext::from_host(None)?)
    }

    /// Create a bare archive using the caller-selected GPG home directory.
    ///
    /// The GPG executable is still resolved from the caller's host PATH, never
    /// from repository configuration.
    ///
    /// # Errors
    /// Rejects an existing path, invalid GPG home, or failed initialization.
    pub fn init_with_gpg_home(path: &Path, home: &Path) -> Result<Self, GitArchiveError> {
        Self::init_with_context(path, GpgContext::from_host(Some(home))?)
    }

    fn init_with_context(path: &Path, gpg: GpgContext) -> Result<Self, GitArchiveError> {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(GitArchiveError::AlreadyExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::create_dir(path)?;
        let hooks = HookDirectory::new()?;
        let mut command = clean_git();
        command.current_dir(path);
        add_hooks_path(&mut command, &hooks.path);
        let output = command
            .arg("init")
            .arg("--quiet")
            .arg("--bare")
            .arg("--initial-branch=firmware")
            .arg(".")
            .output()?;
        check_output(output)?;
        Self::open_with_context(path, gpg)
    }

    /// Open and validate an existing bare archive repository.
    ///
    /// # Errors
    /// Rejects non-bare repositories, unexpected refs, invalid history, or invalid trees.
    pub fn open(path: &Path) -> Result<Self, GitArchiveError> {
        Self::open_with_context(path, GpgContext::from_host(None)?)
    }

    /// Open an archive using the caller-selected GPG home directory.
    ///
    /// The GPG executable is resolved from the caller's host PATH, never from
    /// repository configuration.
    ///
    /// # Errors
    /// Rejects an invalid GPG home, non-bare repositories, unexpected refs, or invalid history.
    pub fn open_with_gpg_home(path: &Path, home: &Path) -> Result<Self, GitArchiveError> {
        Self::open_with_context(path, GpgContext::from_host(Some(home))?)
    }

    fn open_with_context(path: &Path, gpg: GpgContext) -> Result<Self, GitArchiveError> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(GitArchiveError::InvalidRepositoryPath);
        }
        let path = fs::canonicalize(path)?;
        let hooks = HookDirectory::new()?;
        if !path.join("HEAD").is_file()
            || !path.join("objects").is_dir()
            || !path.join("refs").is_dir()
        {
            return Err(GitArchiveError::NotBare);
        }
        let archive = Self {
            path,
            object_id_len: 0,
            gpg,
            hooks,
        };
        if archive.git(&["rev-parse", "--is-bare-repository"], None)? != b"true\n" {
            return Err(GitArchiveError::NotBare);
        }
        if archive.git(&["symbolic-ref", "HEAD"], None)? != format!("{BRANCH}\n").as_bytes() {
            return Err(GitArchiveError::InvalidRefs);
        }
        let refs = archive.git(&["for-each-ref", "--format=%(refname)", "--count=2"], None)?;
        let refs = String::from_utf8_lossy(&refs);
        let refs: Vec<_> = refs.lines().collect();
        if refs.len() > 1 || refs.first().is_some_and(|reference| *reference != BRANCH) {
            return Err(GitArchiveError::InvalidRefs);
        }
        let object_format = archive.git(&["rev-parse", "--show-object-format"], None)?;
        let object_id_len = match object_format.as_slice() {
            b"sha1\n" => 40,
            b"sha256\n" => 64,
            _ => {
                return Err(GitArchiveError::InvalidHistory(
                    "unsupported Git object format",
                ));
            }
        };
        let archive = Self {
            object_id_len,
            ..archive
        };
        archive.validated_head()?;
        Ok(archive)
    }

    /// Return the latest validated index, or an empty index for an initialized repository.
    ///
    /// # Errors
    /// Returns an error if the ref, commit chain, signatures, tree, or manifest is invalid.
    pub fn index(&self) -> Result<FirmwareIndex, GitArchiveError> {
        Ok(self
            .validated_head()?
            .map_or_else(FirmwareIndex::empty, |snapshot| snapshot.index))
    }

    /// Add one complete, valid ZIP as a signed commit, without changing any checkout.
    ///
    /// # Errors
    /// Rejects unsafe or invalid ZIP input, duplicate releases, signing failures, and ref races.
    pub fn import(
        &self,
        package: &Path,
        metadata: ReleaseMetadata,
    ) -> Result<String, GitArchiveError> {
        let old_ref = self.current_ref()?;
        let parent = self.validate_history(old_ref.as_deref())?;
        let bytes = read_package(package)?;
        validate_zip(&bytes)?;
        let (firmware_file, payload) = crate::content::firmware_bytes(&metadata, &bytes)?;
        let record =
            ReleaseRecord::measure_optional(metadata, &bytes, &firmware_file, payload.as_deref())?;
        let mut index = parent
            .as_ref()
            .map_or_else(FirmwareIndex::empty, |snapshot| snapshot.index.clone());
        index.add(record.clone())?;
        let index_bytes = index.to_json()?;

        let tree = self.write_tree(parent.as_ref(), &record, &bytes, &index_bytes)?;
        let commit = self.create_signed_commit(&tree, old_ref.as_deref(), &record)?;
        self.verify_commit(&commit)?;
        let expected_ref = old_ref.clone();
        let old_oid = old_ref.unwrap_or_else(|| "0".repeat(self.object_id_len));
        match self.git(&["update-ref", BRANCH, &commit, &old_oid], None) {
            Ok(_) => Ok(commit),
            Err(error @ GitArchiveError::Git(_)) => {
                if self.current_ref()? == expected_ref {
                    Err(error)
                } else {
                    Err(GitArchiveError::RefChanged)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Read one complete ZIP after checking its recorded size and SHA-256.
    ///
    /// # Errors
    /// Rejects an invalid archive history or ZIP, missing release, and size/hash mismatches.
    pub fn read(&self, path: &str) -> Result<Vec<u8>, GitArchiveError> {
        let snapshot = self
            .validated_head()?
            .ok_or(GitArchiveError::ReleaseNotFound)?;
        let record = snapshot
            .index
            .find(path)
            .ok_or(GitArchiveError::ReleaseNotFound)?;
        let path = record
            .path()
            .strip_prefix('/')
            .ok_or(GitArchiveError::InvalidTree)?;
        let oid = snapshot
            .tree
            .get(path)
            .ok_or(GitArchiveError::InvalidTree)?;
        self.verified_zip(oid, record)
    }

    fn verified_zip(&self, oid: &str, record: &ReleaseRecord) -> Result<Vec<u8>, GitArchiveError> {
        let bytes = self.read_blob(oid, MAX_ARCHIVE_BYTES)?;
        validate_zip(&bytes)?;
        let (firmware_file, payload) = crate::content::firmware_bytes(record.metadata(), &bytes)?;
        record
            .verify_optional(&bytes, &firmware_file, payload.as_deref())
            .map_err(|_| GitArchiveError::InvalidBlob)?;
        Ok(bytes)
    }

    fn validated_head(&self) -> Result<Option<Snapshot>, GitArchiveError> {
        let head = self.current_ref()?;
        self.validate_history(head.as_deref())
    }

    fn current_ref(&self) -> Result<Option<String>, GitArchiveError> {
        let refs = self.git(&["for-each-ref", "--format=%(objectname)", BRANCH], None)?;
        let refs = String::from_utf8_lossy(&refs);
        let values: Vec<_> = refs.lines().collect();
        match values.as_slice() {
            [] => Ok(None),
            [oid]
                if oid.len() == self.object_id_len
                    && oid.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                Ok(Some((*oid).to_owned()))
            }
            _ => Err(GitArchiveError::InvalidRefs),
        }
    }

    fn validate_history(&self, head: Option<&str>) -> Result<Option<Snapshot>, GitArchiveError> {
        let Some(mut oid) = head.map(str::to_owned) else {
            return Ok(None);
        };
        let mut commits = Vec::new();
        loop {
            if commits.len() >= MAX_RELEASES {
                return Err(GitArchiveError::InvalidHistory("too many commits"));
            }
            let (tree, parents) = self.commit_header(&oid)?;
            self.verify_commit(&oid)?;
            if parents.len() > 1 {
                return Err(GitArchiveError::InvalidHistory("merge commit found"));
            }
            commits.push(tree);
            match parents.first() {
                Some(parent) => oid.clone_from(parent),
                None => break,
            }
        }
        commits.reverse();

        let mut previous: Option<Snapshot> = None;
        for tree_oid in commits {
            let tree = self.read_tree(&tree_oid)?;
            let index_oid = tree
                .get("firmware.json")
                .ok_or(GitArchiveError::InvalidTree)?;
            let index_bytes = self.read_blob(index_oid, MAX_INDEX_BYTES)?;
            let index = FirmwareIndex::parse(&index_bytes)?;
            validate_tree_paths(&tree, &index)?;

            let introduced = if let Some(parent) = &previous {
                if index.releases().len() != parent.index.releases().len() + 1
                    || !index.releases().starts_with(parent.index.releases())
                    || parent.index.releases().iter().any(|old| {
                        old.path()
                            .strip_prefix('/')
                            .and_then(|path| parent.tree.get(path))
                            != old.path().strip_prefix('/').and_then(|path| tree.get(path))
                    })
                {
                    return Err(GitArchiveError::InvalidHistory("commit is not append-only"));
                }
                index
                    .releases()
                    .iter()
                    .find(|release| parent.index.find(release.path()).is_none())
                    .ok_or(GitArchiveError::InvalidHistory("new release is missing"))?
            } else {
                if index.releases().len() != 1 {
                    return Err(GitArchiveError::InvalidHistory("root must add one release"));
                }
                &index.releases()[0]
            };
            let path = introduced
                .path()
                .strip_prefix('/')
                .ok_or(GitArchiveError::InvalidTree)?;
            let blob = tree.get(path).ok_or(GitArchiveError::InvalidTree)?;
            self.verified_zip(blob, introduced)?;
            previous = Some(Snapshot {
                tree_oid,
                index,
                tree,
            });
        }
        Ok(previous)
    }

    fn commit_header(&self, oid: &str) -> Result<(String, Vec<String>), GitArchiveError> {
        let size = self.object_size(oid)?;
        if size > MAX_COMMIT_BYTES {
            return Err(GitArchiveError::InvalidHistory(
                "commit object is too large",
            ));
        }
        let bytes = self.git(&["cat-file", "-p", oid], None)?;
        let header = bytes
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty());
        let mut tree = None;
        let mut sha1_signature = None;
        let mut sha256_signature = None;
        let mut parents = Vec::new();
        for line in header {
            if let Some(value) = line.strip_prefix(b"tree ") {
                if tree.is_some() {
                    return Err(GitArchiveError::InvalidHistory(
                        "commit has duplicate tree headers",
                    ));
                }
                tree = Some(String::from_utf8_lossy(value).into_owned());
            } else if let Some(value) = line.strip_prefix(b"gpgsig ") {
                if sha1_signature.replace(value).is_some() {
                    return Err(GitArchiveError::InvalidHistory(
                        "commit has duplicate SHA-1 signature headers",
                    ));
                }
            } else if let Some(value) = line.strip_prefix(b"gpgsig-sha256 ") {
                if sha256_signature.replace(value).is_some() {
                    return Err(GitArchiveError::InvalidHistory(
                        "commit has duplicate SHA-256 signature headers",
                    ));
                }
            } else if let Some(value) = line.strip_prefix(b"parent ") {
                parents.push(String::from_utf8_lossy(value).into_owned());
            } else if line == b"gpgsig" || line == b"gpgsig-sha256" {
                return Err(GitArchiveError::InvalidHistory(
                    "commit has malformed signature header",
                ));
            }
        }
        if sha1_signature
            .into_iter()
            .chain(sha256_signature)
            .any(|value| !value.starts_with(b"-----BEGIN PGP SIGNATURE-----"))
        {
            return Err(GitArchiveError::InvalidHistory(
                "commit contains a non-OpenPGP signature",
            ));
        }
        let selected_signature = match self.object_id_len {
            40 => sha1_signature,
            64 => sha256_signature,
            _ => None,
        };
        if selected_signature.is_none() {
            return Err(GitArchiveError::InvalidHistory(
                "commit has no signature for its object format",
            ));
        }
        let tree = tree.ok_or(GitArchiveError::InvalidHistory("commit has no tree"))?;
        if tree.len() != self.object_id_len
            || parents
                .iter()
                .any(|parent| parent.len() != self.object_id_len)
        {
            return Err(GitArchiveError::InvalidHistory("invalid object identifier"));
        }
        Ok((tree, parents))
    }

    fn read_tree(&self, oid: &str) -> Result<BTreeMap<String, String>, GitArchiveError> {
        if self.git(&["cat-file", "-t", oid], None)? != b"tree\n" {
            return Err(GitArchiveError::InvalidTree);
        }
        if self.object_size(oid)? > MAX_TREE_BYTES {
            return Err(GitArchiveError::InvalidTree);
        }
        let bytes = self.tree_output(oid)?;
        let mut tree = BTreeMap::new();
        for entry in bytes
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            if tree.len() > MAX_RELEASES {
                return Err(GitArchiveError::InvalidTree);
            }
            let separator = entry
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or(GitArchiveError::InvalidTree)?;
            let (header, path) = entry.split_at(separator);
            let path = path
                .strip_prefix(b"\t")
                .ok_or(GitArchiveError::InvalidTree)?;
            let mut fields = header.split(|byte| *byte == b' ');
            let mode = fields.next().ok_or(GitArchiveError::InvalidTree)?;
            let kind = fields.next().ok_or(GitArchiveError::InvalidTree)?;
            let blob = fields.next().ok_or(GitArchiveError::InvalidTree)?;
            if mode != b"100644" || kind != b"blob" || blob.len() != self.object_id_len {
                return Err(GitArchiveError::InvalidTree);
            }
            let path = std::str::from_utf8(path)
                .map_err(|_| GitArchiveError::InvalidTree)?
                .to_owned();
            let blob = std::str::from_utf8(blob)
                .map_err(|_| GitArchiveError::InvalidTree)?
                .to_owned();
            if tree.insert(path, blob).is_some() {
                return Err(GitArchiveError::InvalidTree);
            }
        }
        Ok(tree)
    }

    fn tree_output(&self, oid: &str) -> Result<Vec<u8>, GitArchiveError> {
        let mut command = clean_git();
        command.current_dir(&self.path);
        add_hooks_path(&mut command, &self.hooks.path);
        let mut child = command
            .arg("--git-dir=.")
            .args(["ls-tree", "-rz", "--full-tree", oid])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing tree output"))
            .and_then(|stdout| stdout.take(MAX_TREE_BYTES + 1).read_to_end(&mut bytes));
        if let Err(error) = read {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        if bytes.len() as u64 > MAX_TREE_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GitArchiveError::InvalidTree);
        }
        if !child.wait()?.success() {
            return Err(GitArchiveError::InvalidTree);
        }
        Ok(bytes)
    }

    fn read_blob(&self, oid: &str, limit: usize) -> Result<Vec<u8>, GitArchiveError> {
        let size = self.object_size(oid)?;
        if size > u64::try_from(limit).unwrap_or(u64::MAX) {
            return Err(GitArchiveError::InvalidBlob);
        }
        self.git(&["cat-file", "blob", oid], None)
    }

    fn verify_commit(&self, oid: &str) -> Result<(), GitArchiveError> {
        self.commit_header(oid)?;
        self.git_with_gpg(&["verify-commit", oid], None)?;
        Ok(())
    }

    fn object_size(&self, oid: &str) -> Result<u64, GitArchiveError> {
        let output = self.git(&["cat-file", "-s", oid], None)?;
        let output = std::str::from_utf8(&output).map_err(|_| GitArchiveError::InvalidBlob)?;
        output
            .trim()
            .parse()
            .map_err(|_| GitArchiveError::InvalidBlob)
    }

    fn write_tree(
        &self,
        parent: Option<&Snapshot>,
        record: &ReleaseRecord,
        package: &[u8],
        index: &[u8],
    ) -> Result<String, GitArchiveError> {
        let temp = tempfile::TempDir::new()?;
        let index_file = temp.path().join("index");
        let index_env = Some(index_file.as_path());
        if let Some(parent) = parent {
            self.git(&["read-tree", parent.tree_oid()], index_env)?;
        } else {
            self.git(&["read-tree", "--empty"], index_env)?;
        }
        let package_oid = self.hash_blob(package)?;
        let index_oid = self.hash_blob(index)?;
        let package_path = record
            .path()
            .strip_prefix('/')
            .ok_or(GitArchiveError::InvalidTree)?;
        self.git(
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                &package_oid,
                package_path,
            ],
            index_env,
        )?;
        self.git(
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                &index_oid,
                "firmware.json",
            ],
            index_env,
        )?;
        let tree = self.git(&["write-tree"], index_env)?;
        Ok(String::from_utf8_lossy(&tree).trim().to_owned())
    }

    fn hash_blob(&self, bytes: &[u8]) -> Result<String, GitArchiveError> {
        let oid = self.git_input(&["hash-object", "-w", "--no-filters", "--stdin"], bytes)?;
        Ok(String::from_utf8_lossy(&oid).trim().to_owned())
    }

    fn create_signed_commit(
        &self,
        tree: &str,
        parent: Option<&str>,
        record: &ReleaseRecord,
    ) -> Result<String, GitArchiveError> {
        let message = format!(
            "Add {} {} firmware {}\n",
            record.metadata().product,
            record.component(),
            record.version()
        );
        let mut args = vec!["commit-tree".to_owned(), tree.to_owned()];
        if let Some(parent) = parent {
            args.push("-p".to_owned());
            args.push(parent.to_owned());
        }
        args.push("-S".to_owned());
        let args: Vec<_> = args.iter().map(String::as_str).collect();
        let oid = self.git_with_gpg(&args, Some(message.as_bytes()))?;
        Ok(String::from_utf8_lossy(&oid).trim().to_owned())
    }

    fn git(&self, args: &[&str], index: Option<&Path>) -> Result<Vec<u8>, GitArchiveError> {
        self.run_git(args, index, None)
    }

    fn git_input(&self, args: &[&str], input: &[u8]) -> Result<Vec<u8>, GitArchiveError> {
        self.run_git(args, None, Some(input))
    }

    fn git_with_gpg(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<Vec<u8>, GitArchiveError> {
        let program = self.gpg.program()?;
        let program = program.to_string_lossy();
        let mut command = clean_git();
        command.current_dir(&self.path);
        add_hooks_path(&mut command, &self.hooks.path);
        command
            .arg("-c")
            .arg(format!("gpg.program={program}"))
            .arg("-c")
            .arg(format!("gpg.openpgp.program={program}"))
            .arg("-c")
            .arg(format!("gpg.x509.program={program}"))
            .arg("-c")
            .arg(format!("gpg.ssh.program={program}"))
            .arg("-c")
            .arg("gpg.format=openpgp")
            .arg("--git-dir=.")
            .args(args);
        if let Some(home) = &self.gpg.home {
            command.env("GNUPGHOME", home);
        }
        run_command(command, input)
    }

    fn run_git(
        &self,
        args: &[&str],
        index: Option<&Path>,
        input: Option<&[u8]>,
    ) -> Result<Vec<u8>, GitArchiveError> {
        let mut command = clean_git();
        command.current_dir(&self.path);
        add_hooks_path(&mut command, &self.hooks.path);
        command.arg("--git-dir=.").args(args);
        if let Some(index) = index {
            command.env("GIT_INDEX_FILE", index);
        }
        run_command(command, input)
    }
}

#[derive(Debug)]
struct Snapshot {
    tree_oid: String,
    index: FirmwareIndex,
    tree: BTreeMap<String, String>,
}

impl Snapshot {
    fn tree_oid(&self) -> &str {
        &self.tree_oid
    }
}

fn validate_tree_paths(
    tree: &BTreeMap<String, String>,
    index: &FirmwareIndex,
) -> Result<(), GitArchiveError> {
    let mut expected = BTreeSet::from(["firmware.json".to_owned()]);
    for release in index.releases() {
        let path = release
            .path()
            .strip_prefix('/')
            .ok_or(GitArchiveError::InvalidTree)?;
        expected.insert(path.to_owned());
    }
    if tree.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(GitArchiveError::InvalidTree);
    }
    Ok(())
}

fn read_package(path: &Path) -> Result<Vec<u8>, GitArchiveError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(GitArchiveError::NotRegularFile);
    }
    if metadata.len() == 0 || metadata.len() > u64::try_from(MAX_ARCHIVE_BYTES).unwrap_or(u64::MAX)
    {
        return Err(GitArchiveError::PackageTooLarge);
    }
    let file = open_package_file(path)?;
    if !file.metadata()?.is_file() {
        return Err(GitArchiveError::NotRegularFile);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(MAX_ARCHIVE_BYTES));
    file.take(u64::try_from(MAX_ARCHIVE_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(GitArchiveError::PackageTooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_package_file(path: &Path) -> io::Result<fs::File> {
    use nix::{
        fcntl::{OFlag, open},
        sys::stat::Mode,
    };

    let descriptor = open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    Ok(fs::File::from(descriptor))
}

#[cfg(not(unix))]
fn open_package_file(path: &Path) -> io::Result<fs::File> {
    fs::File::open(path)
}

fn validate_zip(bytes: &[u8]) -> Result<(), GitArchiveError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| GitArchiveError::Zip(error.to_string()))?;
    archive
        .validate_header_consistency()
        .map_err(|error| GitArchiveError::Zip(error.to_string()))?;
    if archive.is_empty() || archive.len() > MAX_ZIP_MEMBERS {
        return Err(GitArchiveError::Zip("invalid member count".to_owned()));
    }
    let total = (0..archive.len()).try_fold(0_u64, |total, index| {
        let member = archive
            .by_index(index)
            .map_err(|error| GitArchiveError::Zip(error.to_string()))?;
        total
            .checked_add(member.size())
            .filter(|size| *size <= MAX_UNCOMPRESSED_BYTES)
            .ok_or_else(|| GitArchiveError::Zip("uncompressed data exceeds limit".to_owned()))
    })?;
    let _ = total;
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|error| GitArchiveError::Zip(error.to_string()))?;
        let expected = member.size();
        let mut read = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = member
                .read(&mut buffer)
                .map_err(|error| GitArchiveError::Zip(error.to_string()))?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
                .filter(|size| *size <= MAX_UNCOMPRESSED_BYTES)
                .ok_or_else(|| {
                    GitArchiveError::Zip("uncompressed data exceeds limit".to_owned())
                })?;
        }
        if read != expected {
            return Err(GitArchiveError::Zip("member size mismatch".to_owned()));
        }
    }
    Ok(())
}

fn clean_git() -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for (key, value) in env::vars_os() {
        if !key.to_string_lossy().starts_with("GIT_") {
            command.env(key, value);
        }
    }
    command.env("GIT_NO_LAZY_FETCH", "1");
    command
}

fn add_hooks_path(command: &mut Command, path: &Path) {
    let mut value = OsString::from("core.hooksPath=");
    value.push(path);
    command.arg("-c").arg(value);
}

fn canonical_gpg_home(home: &Path) -> Result<PathBuf, GitArchiveError> {
    let home = fs::canonicalize(home).map_err(|_| GitArchiveError::InvalidGpgHome)?;
    if !home.is_dir() {
        return Err(GitArchiveError::InvalidGpgHome);
    }
    Ok(home)
}

fn resolve_host_gpg_program() -> Option<PathBuf> {
    #[cfg(windows)]
    const EXECUTABLE_NAMES: [&str; 2] = ["gpg.exe", "gpg"];
    #[cfg(not(windows))]
    const EXECUTABLE_NAMES: [&str; 1] = ["gpg"];

    let search_path = env::var_os("PATH")?;
    for directory in env::split_paths(&search_path) {
        if !directory.is_absolute() {
            continue;
        }
        for name in EXECUTABLE_NAMES {
            let candidate = directory.join(name);
            let Ok(metadata) = fs::metadata(&candidate) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            if let Ok(program) = fs::canonicalize(candidate)
                && program.to_str().is_some()
            {
                return Some(program);
            }
        }
    }
    None
}

fn run_command(mut command: Command, input: Option<&[u8]>) -> Result<Vec<u8>, GitArchiveError> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(input) = input
        && let Err(error) = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing stdin"))?
            .write_all(input)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let output = child.wait_with_output()?;
    check_output(output)
}

fn check_output(output: Output) -> Result<Vec<u8>, GitArchiveError> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(GitArchiveError::Git(stderr.chars().take(2048).collect()))
    }
}
