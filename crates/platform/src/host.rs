//! Host support describes implemented adapters, not device presence or authorization.

/// Platforms with separate native authorization and transport requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Host {
    MacOs,
    Windows,
    Linux,
    Ios,
    Android,
    Other,
}

impl Host {
    /// Identify the compilation target without discovering any devices.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "ios") {
            Self::Ios
        } else if cfg!(target_os = "android") {
            Self::Android
        } else {
            Self::Other
        }
    }

    /// Whether a native updater adapter exists for this host.
    ///
    /// This does not establish permissions, a connected controller, or support
    /// for building the desktop frontend on mobile platforms.
    #[must_use]
    pub const fn supports_native_updates(self) -> bool {
        matches!(self, Self::MacOs)
    }
}

#[cfg(test)]
mod tests {
    use super::Host;

    #[test]
    fn desktop_and_mobile_support_require_an_implemented_adapter() {
        assert!(Host::MacOs.supports_native_updates());
        for host in [
            Host::Windows,
            Host::Linux,
            Host::Ios,
            Host::Android,
            Host::Other,
        ] {
            assert!(!host.supports_native_updates(), "{host:?}");
        }
    }
}
