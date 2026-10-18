//! Bounded decoding of actual REQUEST SENSE bytes; no missing field is synthesized.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SenseFormat {
    Fixed,
    Descriptor,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Sense {
    pub format: SenseFormat,
    pub deferred: bool,
    pub key: u8,
    pub asc: u8,
    pub ascq: u8,
    pub actual_length: usize,
    pub declared_length: usize,
    /// Allocation may omit the tail while the reported header fields are complete.
    pub truncated: bool,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SenseError {
    #[error("Sense response has no complete header")]
    Header,
    #[error("Unsupported sense response code 0x{0:02x}")]
    ResponseCode(u8),
    #[error("Sense response does not contain its declared bytes and required fields")]
    Length,
}
/// Decode only fields present in a fixed or descriptor-format sense response.
///
/// # Errors
///
/// Returns an error for a header shorter than eight bytes, an unsupported response
/// code or fixed-format data without its required key/ASC/ASCQ fields.
pub fn decode_sense(bytes: &[u8]) -> Result<Sense, SenseError> {
    if bytes.len() < 8 {
        return Err(SenseError::Header);
    }
    let code = bytes[0] & 0x7f;
    let declared = 8 + usize::from(bytes[7]);
    let usable = declared.min(bytes.len());
    let (format, key, asc, ascq) = match code {
        0x70 | 0x71 => {
            if usable < 14 {
                return Err(SenseError::Length);
            }
            (SenseFormat::Fixed, bytes[2] & 0x0f, bytes[12], bytes[13])
        }
        0x72 | 0x73 => (SenseFormat::Descriptor, bytes[1] & 0x0f, bytes[2], bytes[3]),
        other => return Err(SenseError::ResponseCode(other)),
    };
    Ok(Sense {
        format,
        deferred: code == 0x71 || code == 0x73,
        key,
        asc,
        ascq,
        actual_length: bytes.len(),
        declared_length: declared,
        truncated: declared > bytes.len(),
    })
}
