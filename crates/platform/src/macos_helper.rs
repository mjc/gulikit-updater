//! Explicit registration and the authenticated Ping control path for the macOS helper.
//!
//! This module does not register the helper implicitly. Call [`register`] only from an
//! explicit user action, and inspect the returned status because macOS may require approval
//! in System Settings. Ping is limited to a bounded, versioned health request.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char};
use std::time::Duration;
use thiserror::Error;

/// The Mach service name used by the helper and its GUI client.
pub const MACH_SERVICE: &str = "lol.mjc.gulikit-updater.helper";
/// The `Contents/Library/LaunchDaemons` plist name for `SMAppService`.
pub const PLIST_NAME: &str = "lol.mjc.gulikit-updater.helper.plist";
/// The signed GUI application identifier expected by the helper.
pub const APP_IDENTIFIER: &str = "lol.mjc.gulikit-updater";
/// The signed helper executable identifier expected by the GUI client.
pub const HELPER_IDENTIFIER: &str = "lol.mjc.gulikit-updater.helper";
/// The one private command-line argument used by launchd to enter the headless helper mode.
pub const HELPER_ARGUMENT: &str = "__privileged-helper";

const MAX_PING_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const ERROR_BUFFER_SIZE: usize = 1024;
const NO_STATUS: u32 = u32::MAX;

const NATIVE_OK: i32 = 0;
const NATIVE_UNSUPPORTED_OS: i32 = 1;
const NATIVE_INVALID_IDENTITY: i32 = 2;
const NATIVE_SERVICE_ERROR: i32 = 3;
const NATIVE_CONNECTION_ERROR: i32 = 4;
const NATIVE_TIMEOUT: i32 = 5;
const NATIVE_PROTOCOL_ERROR: i32 = 6;
const NATIVE_PERMISSION_ERROR: i32 = 7;
const NATIVE_WRONG_THREAD: i32 = 8;

unsafe extern "C" {
    fn gulikit_helper_status(status: *mut u32, error: *mut c_char, capacity: usize) -> i32;
    fn gulikit_helper_register(status: *mut u32, error: *mut c_char, capacity: usize) -> i32;
    fn gulikit_helper_unregister(status: *mut u32, error: *mut c_char, capacity: usize) -> i32;
    fn gulikit_helper_ping(timeout_ms: u32, error: *mut c_char, capacity: usize) -> i32;
    fn gulikit_helper_serve_ping(idle_timeout_ms: u32, error: *mut c_char, capacity: usize) -> i32;
}

#[cfg(test)]
unsafe extern "C" {
    fn gulikit_helper_test_ping_request(case_id: u32) -> i32;
    fn gulikit_helper_test_ping_reply(case_id: u32) -> i32;
    fn gulikit_helper_test_idle_transition(case_id: u32) -> i32;
    fn gulikit_helper_test_ping_round_trip(timeout_ms: u32) -> i32;
}

/// The state reported by `SMAppService` for the bundled launch daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceStatus {
    /// The service has not been registered.
    NotRegistered,
    /// The service is registered and enabled.
    Enabled,
    /// The service is registered but needs user approval in System Settings.
    RequiresApproval,
    /// The service plist or bundled executable could not be found.
    NotFound,
}

impl TryFrom<u32> for ServiceStatus {
    type Error = HelperError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotRegistered),
            1 => Ok(Self::Enabled),
            2 => Ok(Self::RequiresApproval),
            3 => Ok(Self::NotFound),
            other => Err(HelperError::Protocol(format!(
                "unknown SMAppService status value {other}"
            ))),
        }
    }
}

/// Errors returned by service management or the helper Ping channel.
#[derive(Debug, Error)]
pub enum HelperError {
    /// The operation requires macOS 13 or later.
    #[error("the privileged helper requires macOS 13 or later")]
    UnsupportedOs,
    /// The running executable is not signed by Apple with the expected product identity.
    #[error("the running code signature is not an accepted release identity: {0}")]
    InvalidIdentity(String),
    /// Registration or status failed. `status` contains the actual status when macOS supplied it.
    #[error("SMAppService operation failed (status {status:?}): {message}")]
    Service {
        status: Option<ServiceStatus>,
        message: String,
    },
    /// XPC could not establish an authenticated connection.
    #[error("could not connect to the privileged helper: {0}")]
    Connection(String),
    /// The helper did not answer within the requested bound.
    #[error("the helper Ping request timed out")]
    Timeout,
    /// The helper returned an invalid or unsupported bounded protocol message.
    #[error("the helper Ping protocol failed: {0}")]
    Protocol(String),
    /// A duration was zero, exceeded its documented bound, or could not fit the native API.
    #[error("the helper timeout is outside its supported range")]
    InvalidTimeout,
    /// The server requires the launchd helper to run as root.
    #[error("the helper service must run as root")]
    PermissionDenied,
    /// The headless listener must run on the process main thread.
    #[error("the helper listener must run on the process main thread")]
    WrongThread,
}

/// Read the current helper registration state without changing it.
///
/// # Errors
/// Returns an error if `SMAppService` is unavailable or cannot report its state.
pub fn status() -> Result<ServiceStatus, HelperError> {
    let (code, raw_status, message) = invoke_status(gulikit_helper_status);
    status_result(code, raw_status, message)
}

/// Explicitly register the bundled launch daemon and report macOS's resulting status.
///
/// This function is explicit and does not bypass System Settings approval. A successful return
/// of [`ServiceStatus::RequiresApproval`] means the user still needs to approve it.
///
/// # Errors
/// Returns an error if the executable lacks the expected Apple-backed release identity or
/// macOS cannot register the bundled service. Registration errors preserve the actual status
/// when macOS provides one.
pub fn register() -> Result<ServiceStatus, HelperError> {
    let (code, raw_status, message) = invoke_status(gulikit_helper_register);
    status_result(code, raw_status, message)
}

/// Explicitly unregister the bundled launch daemon and report its resulting status.
///
/// # Errors
/// Returns an error if the executable lacks the expected Apple-backed release identity or
/// macOS cannot unregister the bundled service. Errors preserve the actual status when available.
pub fn unregister() -> Result<ServiceStatus, HelperError> {
    let (code, raw_status, message) = invoke_status(gulikit_helper_unregister);
    status_result(code, raw_status, message)
}

/// Send the helper a bounded, mutually authenticated Ping request.
///
/// The GUI identity is derived from its validated running code signature. The client requires
/// the helper's fixed signed identifier and the same Apple-issued Team ID. The Ping request is
/// side-effect-free; the client accepts its reply only after verifying the connected peer is root.
/// XPC may launch an already-enabled on-demand service, but this operation never registers it.
///
/// # Errors
/// Returns an error if the service is not enabled, the identities do not match, the peer is not
/// root, the request times out, or the reply violates the Ping protocol.
pub fn ping(timeout: Duration) -> Result<(), HelperError> {
    validate_duration(timeout, Duration::from_millis(1), MAX_PING_TIMEOUT)?;
    let service_status = status()?;
    if service_status != ServiceStatus::Enabled {
        return Err(HelperError::Service {
            status: Some(service_status),
            message: "the helper is not enabled".to_owned(),
        });
    }

    let timeout_ms = duration_millis(timeout)?;
    let (code, _, message) = invoke_timed(gulikit_helper_ping, timeout_ms);
    native_result(code, None, message)
}

/// Run the headless Ping-only listener until it has been idle with no connected clients.
///
/// This entry point is for the launchd helper process, not the GUI. It requires effective UID 0,
/// the process main thread, a validated helper signing identity, and authenticated GUI Ping
/// requests. It uses `dispatch_main`, so call it before starting other work on that thread.
///
/// # Errors
/// Returns an error if the process is not root, is not on its main thread, its identity is not
/// accepted, or the listener cannot start. Once listening, successful operation exits the helper
/// process after the idle timeout; it does not return `Ok(())` to the caller.
pub fn serve(idle_timeout: Duration) -> Result<(), HelperError> {
    validate_duration(idle_timeout, Duration::from_secs(1), MAX_IDLE_TIMEOUT)?;
    let idle_timeout_ms = duration_millis(idle_timeout)?;
    let (code, _, message) = invoke_timed(gulikit_helper_serve_ping, idle_timeout_ms);
    native_result(code, None, message)
}

fn validate_duration(
    duration: Duration,
    minimum: Duration,
    maximum: Duration,
) -> Result<(), HelperError> {
    if duration < minimum || duration > maximum {
        return Err(HelperError::InvalidTimeout);
    }
    Ok(())
}

fn duration_millis(duration: Duration) -> Result<u32, HelperError> {
    u32::try_from(duration.as_millis()).map_err(|_| HelperError::InvalidTimeout)
}

fn invoke_status(
    operation: unsafe extern "C" fn(*mut u32, *mut c_char, usize) -> i32,
) -> (i32, u32, String) {
    let mut status = NO_STATUS;
    let mut error = [0 as c_char; ERROR_BUFFER_SIZE];
    // SAFETY: Both output pointers refer to initialized writable storage valid for the call. The
    // C shim writes a NUL-terminated message within `capacity` and never retains either pointer.
    let code = unsafe { operation(&raw mut status, error.as_mut_ptr(), error.len()) };
    (code, status, native_message(&error))
}

fn invoke_timed(
    operation: unsafe extern "C" fn(u32, *mut c_char, usize) -> i32,
    timeout_ms: u32,
) -> (i32, u32, String) {
    let mut error = [0 as c_char; ERROR_BUFFER_SIZE];
    // SAFETY: The buffer is initialized and writable for the call. The C shim copies only a
    // bounded NUL-terminated error message and does not retain the pointer.
    let code = unsafe { operation(timeout_ms, error.as_mut_ptr(), error.len()) };
    (code, NO_STATUS, native_message(&error))
}

fn native_message(buffer: &[c_char]) -> String {
    let bytes = buffer
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .collect::<Vec<_>>();
    CStr::from_bytes_until_nul(&bytes).map_or_else(
        |_| "native helper returned an unterminated error message".to_owned(),
        |message| message.to_string_lossy().into_owned(),
    )
}

fn status_result(
    code: i32,
    raw_status: u32,
    message: String,
) -> Result<ServiceStatus, HelperError> {
    let status = (raw_status != NO_STATUS)
        .then(|| ServiceStatus::try_from(raw_status))
        .transpose()?;
    if code == NATIVE_OK {
        return status.ok_or_else(|| {
            HelperError::Protocol("native status call returned no status".to_owned())
        });
    }
    Err(native_error(code, status, message))
}

fn native_result(
    code: i32,
    status: Option<ServiceStatus>,
    message: String,
) -> Result<(), HelperError> {
    if code == NATIVE_OK {
        Ok(())
    } else {
        Err(native_error(code, status, message))
    }
}

fn native_error(code: i32, status: Option<ServiceStatus>, message: String) -> HelperError {
    match code {
        NATIVE_UNSUPPORTED_OS => HelperError::UnsupportedOs,
        NATIVE_INVALID_IDENTITY => HelperError::InvalidIdentity(message),
        NATIVE_SERVICE_ERROR => HelperError::Service { status, message },
        NATIVE_CONNECTION_ERROR => HelperError::Connection(message),
        NATIVE_TIMEOUT => HelperError::Timeout,
        NATIVE_PROTOCOL_ERROR => HelperError::Protocol(message),
        NATIVE_PERMISSION_ERROR => HelperError::PermissionDenied,
        NATIVE_WRONG_THREAD => HelperError::WrongThread,
        other => HelperError::Protocol(format!("unknown native helper error {other}: {message}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_smappservice_statuses() {
        assert!(matches!(
            ServiceStatus::try_from(0),
            Ok(ServiceStatus::NotRegistered)
        ));
        assert!(matches!(
            ServiceStatus::try_from(1),
            Ok(ServiceStatus::Enabled)
        ));
        assert!(matches!(
            ServiceStatus::try_from(2),
            Ok(ServiceStatus::RequiresApproval)
        ));
        assert!(matches!(
            ServiceStatus::try_from(3),
            Ok(ServiceStatus::NotFound)
        ));
        assert!(matches!(
            ServiceStatus::try_from(4),
            Err(HelperError::Protocol(_))
        ));
    }

    #[test]
    fn preserves_status_when_registration_fails() {
        let error = native_error(
            NATIVE_SERVICE_ERROR,
            Some(ServiceStatus::RequiresApproval),
            "approval pending".to_owned(),
        );
        assert!(matches!(
            error,
            HelperError::Service {
                status: Some(ServiceStatus::RequiresApproval),
                ..
            }
        ));
    }

    #[test]
    fn bounds_ping_and_idle_timeouts() {
        assert!(
            validate_duration(Duration::ZERO, Duration::from_millis(1), MAX_PING_TIMEOUT).is_err()
        );
        assert!(
            validate_duration(MAX_PING_TIMEOUT, Duration::from_millis(1), MAX_PING_TIMEOUT).is_ok()
        );
        assert!(
            validate_duration(
                MAX_PING_TIMEOUT + Duration::from_millis(1),
                Duration::from_millis(1),
                MAX_PING_TIMEOUT
            )
            .is_err()
        );
        assert!(
            validate_duration(MAX_IDLE_TIMEOUT, Duration::from_secs(1), MAX_IDLE_TIMEOUT).is_ok()
        );
        assert!(duration_millis(Duration::from_secs(u64::from(u32::MAX))).is_err());
    }

    #[test]
    fn validates_actual_native_ping_request_dictionaries() {
        for (case, expected) in [
            (0, 1), // exact kind, protocol version, request ID and key set
            (1, 0), // wrong kind
            (2, 0), // wrong protocol type
            (3, 0), // unsupported protocol version
            (4, 0), // wrong request ID type
            (5, 0), // additional key
            (6, 0), // missing key
        ] {
            // SAFETY: The native test helper only constructs and validates an in-process XPC
            // dictionary. It does not connect to, register, or launch a service.
            let actual = unsafe { gulikit_helper_test_ping_request(case) };
            assert_eq!(actual, expected, "request validator case {case}");
        }
    }

    #[test]
    fn validates_actual_native_ping_reply_dictionaries() {
        for (case, expected) in [
            (0, 1), // matching pong
            (1, 0), // wrong reply kind
            (2, 0), // unsupported protocol version
            (3, 0), // wrong protocol type
            (4, 0), // mismatched request ID
            (5, 0), // additional key
            (6, 0), // missing key
        ] {
            // SAFETY: The native test helper only constructs and validates an in-process XPC
            // dictionary. It does not connect to, register, or launch a service.
            let actual = unsafe { gulikit_helper_test_ping_reply(case) };
            assert_eq!(actual, expected, "reply validator case {case}");
        }
    }

    #[test]
    fn idle_exit_requires_unchanged_generation_and_no_active_peers() {
        for (case, expected) in [
            (0, 1), // still idle at the delayed exit check
            (1, 0), // a peer opened during the grace period
            (2, 0), // a peer opened and closed; the old generation is stale
            (3, 1), // a fresh idle timer after that peer closed
        ] {
            // SAFETY: The native fixture exercises only the in-process idle state transition.
            // It does not start a listener, connect to XPC, or change service registration.
            let actual = unsafe { gulikit_helper_test_idle_transition(case) };
            assert_eq!(actual, expected, "idle lifecycle case {case}");
        }
    }

    #[test]
    fn anonymous_xpc_endpoint_correlates_ping_reply() {
        // SAFETY: The native test uses only an in-process anonymous XPC endpoint with a bounded
        // wait. It does not use the named launchd service or change registration state.
        let result = unsafe { gulikit_helper_test_ping_round_trip(1_500) };
        assert_eq!(result, NATIVE_OK, "anonymous XPC request/reply round trip");
    }
}
