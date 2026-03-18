#![doc = include_str!("../README.md")]

mod error;

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use dcap_qvl::collateral::get_collateral;
use dcap_qvl::verify::ring::verify;
pub use dcap_qvl::PHALA_PCCS_URL;
use serde::Deserialize;

pub use error::{AttestationError, Result};

const MIN_QUOTE_LEN: usize = 48;
pub const TDX_TEE_TYPE: u32 = 0x0000_0081;

#[derive(Deserialize)]
struct TdxQuoteBody {
    quote: String,
}

#[derive(Deserialize)]
struct TdxQuoteEnvelope {
    tdx: TdxQuoteBody,
}

/// Minimal verifier for Intel TDX quotes.
///
/// By default the verifier reads `PCCS_URL` from the environment and falls back
/// to [`PHALA_PCCS_URL`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verifier {
    pccs_url: String,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Verifier {
    /// Creates a verifier that fetches collaterals from the given PCCS endpoint.
    pub fn new(pccs_url: impl Into<String>) -> Self {
        Self {
            pccs_url: pccs_url.into(),
        }
    }

    /// Creates a verifier from `PCCS_URL`, or falls back to [`PHALA_PCCS_URL`].
    pub fn from_env() -> Self {
        let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
        Self::new(pccs_url)
    }

    /// Returns the PCCS URL used by this verifier.
    pub fn pccs_url(&self) -> &str {
        &self.pccs_url
    }

    /// Verifies a raw TDX quote.
    pub async fn verify_quote(&self, quote: &[u8]) -> Result<()> {
        self.verify_quote_at(quote, current_unix_time()?).await
    }

    /// Verifies a raw TDX quote at the provided Unix timestamp.
    pub async fn verify_quote_at(&self, quote: &[u8], unix_time: u64) -> Result<()> {
        ensure_tdx_quote(quote)?;

        let collateral = get_collateral(&self.pccs_url, quote)
            .await
            .map_err(|error| AttestationError::CollateralFetch(error.to_string()))?;

        verify(quote, &collateral, unix_time)
            .map_err(|error| AttestationError::Verification(error.to_string()))?;

        Ok(())
    }

    /// Decodes a raw quote from hex and verifies it.
    pub async fn verify_quote_hex(&self, quote_hex: &str) -> Result<()> {
        let quote = decode_quote_hex(quote_hex)?;
        self.verify_quote(&quote).await
    }

    /// Decodes a raw quote from base64 and verifies it.
    pub async fn verify_quote_base64(&self, quote_base64: &str) -> Result<()> {
        let quote = decode_quote_base64(quote_base64)?;
        self.verify_quote(&quote).await
    }

    /// Decodes and verifies a TDX JSON payload shaped like `{"tdx":{"quote":"..."}}`.
    pub async fn verify_tdx_quote_json(&self, tdx_quote_json: &str) -> Result<()> {
        let quote = decode_tdx_quote_json(tdx_quote_json)?;
        self.verify_quote(&quote).await
    }

    /// Decodes and verifies a hex-encoded TDX JSON payload shaped like
    /// `{"tdx":{"quote":"..."}}`.
    pub async fn verify_tdx_quote_json_hex(&self, tdx_quote_json_hex: &str) -> Result<()> {
        let quote = decode_tdx_quote_json_hex(tdx_quote_json_hex)?;
        self.verify_quote(&quote).await
    }
}

/// Verifies a raw TDX quote with the default verifier.
pub async fn verify_quote(quote: &[u8]) -> Result<()> {
    Verifier::default().verify_quote(quote).await
}

/// Verifies a raw TDX quote hex string with the default verifier.
pub async fn verify_quote_hex(quote_hex: &str) -> Result<()> {
    Verifier::default().verify_quote_hex(quote_hex).await
}

/// Verifies a raw TDX quote base64 string with the default verifier.
pub async fn verify_quote_base64(quote_base64: &str) -> Result<()> {
    Verifier::default().verify_quote_base64(quote_base64).await
}

/// Verifies a TDX JSON payload shaped like `{"tdx":{"quote":"..."}}` with the
/// default verifier.
pub async fn verify_tdx_quote_json(tdx_quote_json: &str) -> Result<()> {
    Verifier::default()
        .verify_tdx_quote_json(tdx_quote_json)
        .await
}

/// Verifies a hex-encoded TDX JSON payload shaped like `{"tdx":{"quote":"..."}}`
/// with the default verifier.
pub async fn verify_tdx_quote_json_hex(tdx_quote_json_hex: &str) -> Result<()> {
    Verifier::default()
        .verify_tdx_quote_json_hex(tdx_quote_json_hex)
        .await
}

/// Decodes a raw quote from hex.
pub fn decode_quote_hex(quote_hex: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(normalize_hex(quote_hex))?)
}

/// Decodes a raw quote from base64.
pub fn decode_quote_base64(quote_base64: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::STANDARD.decode(quote_base64.trim())?)
}

/// Decodes a TDX JSON payload shaped like `{"tdx":{"quote":"..."}}`.
pub fn decode_tdx_quote_json(tdx_quote_json: &str) -> Result<Vec<u8>> {
    let envelope: TdxQuoteEnvelope = serde_json::from_str(tdx_quote_json)?;
    decode_quote_base64(&envelope.tdx.quote)
}

/// Decodes a hex-encoded TDX JSON payload shaped like `{"tdx":{"quote":"..."}}`.
pub fn decode_tdx_quote_json_hex(tdx_quote_json_hex: &str) -> Result<Vec<u8>> {
    let json_bytes = decode_quote_hex(tdx_quote_json_hex)?;
    let json = String::from_utf8(json_bytes)?;
    decode_tdx_quote_json(&json)
}

fn normalize_hex(input: &str) -> &str {
    let trimmed = input.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
}

fn current_unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AttestationError::SystemTime(error.to_string()))?
        .as_secs())
}

fn ensure_tdx_quote(quote: &[u8]) -> Result<()> {
    if quote.len() < MIN_QUOTE_LEN {
        return Err(AttestationError::QuoteTooShort {
            expected: MIN_QUOTE_LEN,
            actual: quote.len(),
        });
    }

    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);
    if tee_type != TDX_TEE_TYPE {
        return Err(AttestationError::InvalidTeeType { actual: tee_type });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn decode_quote_hex_accepts_0x_prefix() {
        let quote = decode_quote_hex("0x00010203").unwrap();
        assert_eq!(quote, vec![0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn decode_tdx_quote_json_hex_extracts_raw_quote() {
        let example: Value = serde_json::from_str(include_str!("../example.json")).unwrap();
        let wrapped_quote_hex = example
            .pointer("/tdx_attestation/quote_hex")
            .and_then(Value::as_str)
            .unwrap();

        let quote = decode_tdx_quote_json_hex(wrapped_quote_hex).unwrap();

        assert!(quote.len() > MIN_QUOTE_LEN);
        assert_eq!(
            u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]),
            TDX_TEE_TYPE
        );
    }

    #[test]
    fn verify_quote_rejects_short_quote() {
        let result = ensure_tdx_quote(&[0u8; 16]);
        assert!(matches!(
            result,
            Err(AttestationError::QuoteTooShort {
                expected: MIN_QUOTE_LEN,
                actual: 16
            })
        ));
    }

    #[test]
    fn verify_quote_rejects_wrong_tee_type() {
        let mut quote = vec![0u8; MIN_QUOTE_LEN];
        quote[4..8].copy_from_slice(&0u32.to_le_bytes());

        let result = ensure_tdx_quote(&quote);
        assert!(matches!(
            result,
            Err(AttestationError::InvalidTeeType { actual: 0 })
        ));
    }

    #[tokio::test]
    #[ignore = "requires network access to PCCS"]
    async fn verifies_example_quote() {
        let example: Value = serde_json::from_str(include_str!("../example.json")).unwrap();
        let wrapped_quote_hex = example
            .pointer("/tdx_attestation/quote_hex")
            .and_then(Value::as_str)
            .unwrap();

        verify_tdx_quote_json_hex(wrapped_quote_hex).await.unwrap();
    }
}
