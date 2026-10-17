//! Strict libusb boundary. Kernel ownership policy is qualified separately.
#![allow(unsafe_code)]

/// Report the linked backend, rather than assuming the crate's bundled version.
pub fn backend_version() -> String {
    let version = rusb::version();
    format!(
        "{}.{}.{}",
        version.major(),
        version.minor(),
        version.micro()
    )
}

fn normalize(status: i32, actual: i32, bytes: &[u8]) -> Result<usize, String> {
    let prefix = usize::try_from(actual).unwrap_or(0).min(bytes.len());
    if status != 0 || actual < 0 || actual as usize > bytes.len() {
        return Err(format!(
            "libusb status={status} actual={actual} requested={} raw={:02x?}",
            bytes.len(),
            &bytes[..prefix]
        ));
    }
    Ok(actual as usize)
}

/// Preserve both the native return code and initialized actual count. The safe
/// rusb convenience API turns a timeout with partial data into success.
pub fn bulk(
    handle: &rusb::DeviceHandle<rusb::Context>,
    endpoint: u8,
    bytes: &mut [u8],
) -> Result<usize, String> {
    let length =
        i32::try_from(bytes.len()).map_err(|_| "USB request exceeds native length range")?;
    let mut actual = 0;
    // SAFETY: handle remains live, mutable buffer is valid for length bytes,
    // and this synchronous call completes before either can be dropped.
    let status = unsafe {
        rusb::ffi::libusb_bulk_transfer(
            handle.as_raw(),
            endpoint,
            bytes.as_mut_ptr(),
            length,
            &mut actual,
            5000,
        )
    };
    normalize(status, actual, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_error_is_preserved_even_with_partial_or_complete_data() {
        let bytes: Vec<u8> = (0..20).collect();
        assert_eq!(normalize(0, 20, &bytes).unwrap(), 20);
        for (status, actual) in [(-7, 7), (-7, 20), (-10, 7), (-9, 3)] {
            let error = normalize(status, actual, &bytes).unwrap_err();
            assert!(error.contains(&format!("status={status}")));
            assert!(error.contains(&format!("actual={actual}")));
            assert!(error.contains("raw="));
        }
        for actual in [-1, 21] {
            assert!(normalize(0, actual, &bytes).is_err());
        }
        assert_eq!(normalize(0, 7, &bytes).unwrap(), 7);
    }
}
