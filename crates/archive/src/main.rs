use clap::{Parser, Subcommand};
use gulikit_archive::{GitArchive, ReleaseMetadata};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Maintain original KK3 Max ZIPs in a separate firmware branch"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new isolated bare repository. Existing paths are refused.
    Init { repository: PathBuf },
    /// Append one original ZIP and its release details in a signed Git commit.
    Import {
        repository: PathBuf,
        package: PathBuf,
        /// JSON containing component, version, filename, source, and release notes.
        #[arg(long)]
        metadata: PathBuf,
    },
    /// Print the archive's firmware.json without accessing a controller.
    List { repository: PathBuf },
    /// Verify and copy one original ZIP to a new output file.
    Read {
        repository: PathBuf,
        #[arg(long)]
        path: String,
        #[arg(long)]
        output: PathBuf,
    },
}

fn read_metadata(path: &Path) -> Result<ReleaseMetadata, Box<dyn std::error::Error>> {
    const MAX_METADATA_BYTES: u64 = 32 * 1024;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags((nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_NOFOLLOW).bits());
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err("release metadata must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > MAX_METADATA_BYTES {
        return Err("release metadata exceeds 32 KiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Init { repository } => {
            GitArchive::init(&repository)?;
            println!(
                "Created isolated firmware repository: {}",
                repository.display()
            );
        }
        Command::Import {
            repository,
            package,
            metadata,
        } => {
            let metadata = read_metadata(&metadata)?;
            let commit = GitArchive::open(&repository)?.import(&package, metadata)?;
            println!("{commit}");
        }
        Command::List { repository } => {
            let index = GitArchive::open(&repository)?.index()?;
            let mut out = std::io::stdout().lock();
            out.write_all(&index.to_json()?)?;
            writeln!(out)?;
        }
        Command::Read {
            repository,
            path,
            output,
        } => {
            let bytes = GitArchive::open(&repository)?.read(&path)?;
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut file = tempfile::NamedTempFile::new_in(parent)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist_noclobber(&output)?;
            println!("{}", output.display());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
