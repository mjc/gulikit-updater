//! Application operations shared by the command-line and desktop frontends.
#![forbid(unsafe_code)]

pub mod updater;

#[cfg(target_os = "macos")]
pub mod supervision;
