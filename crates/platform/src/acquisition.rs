//! Acquisition failures retain restoration work separately from the primary refusal.

pub const SURRENDER_PENDING_NOTICE: &str = "Host claim surrendered without reset after possible F0; storage driver restoration remains pending. Surrender alone does not establish that restarting or recovery is safe.";

#[derive(Debug, thiserror::Error)]
#[error("{error}; cleanup={cleanup_errors:?}")]
pub struct AcquisitionError {
    pub error: String,
    pub cleanup_errors: Vec<String>,
}
impl From<String> for AcquisitionError {
    fn from(error: String) -> Self {
        Self {
            error,
            cleanup_errors: Vec::new(),
        }
    }
}
impl From<&str> for AcquisitionError {
    fn from(error: &str) -> Self {
        error.to_owned().into()
    }
}
impl AcquisitionError {
    pub fn after_cleanup(error: String, cleanup: Result<(), String>) -> Self {
        Self {
            error,
            cleanup_errors: cleanup.err().into_iter().collect(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_acquisition_retains_restoration_failure_as_structured_attention() {
        let failure = AcquisitionError::after_cleanup(
            "interface open failed".into(),
            Err("remount failed".into()),
        );
        assert_eq!(failure.error, "interface open failed");
        assert_eq!(failure.cleanup_errors, ["remount failed"]);
        let clean = AcquisitionError::after_cleanup("open failed".into(), Ok(()));
        assert_eq!(clean.error, "open failed");
        assert!(clean.cleanup_errors.is_empty());
    }
}
