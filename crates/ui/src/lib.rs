//! Desktop controller and interchangeable native and simulated devices.
#![forbid(unsafe_code)]

pub mod backend;
pub mod demo;
pub mod live;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Connect,
    Ready,
    Writing,
    Restart,
    Verified,
    Failed,
}
