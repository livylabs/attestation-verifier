use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("System time error: {0}")]
    SystemTime(String),

    #[error("Quote verification error: {0}")]
    Verification(String),

    #[error("Quote too short: expected at least {expected} bytes, got {actual}")]
    QuoteTooShort { expected: usize, actual: usize },

    #[error("Invalid TEE type: expected 0x00000081 (TDX), got 0x{actual:08x}")]
    InvalidTeeType { actual: u32 },

    #[error("Collateral fetch error: {0}")]
    CollateralFetch(String),
}

pub type Result<T> = std::result::Result<T, AttestationError>;
