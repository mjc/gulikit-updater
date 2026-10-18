//! Native macOS distribution packaging. Credentials stay in the packaging process.
#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use clap::Parser;
    match macos::package(&macos::Options::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("macOS packaging requires macOS and the full Xcode developer tools");
    std::process::ExitCode::FAILURE
}
