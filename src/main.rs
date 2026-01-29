mod error;

use serde::Deserialize;
use std::fs;
use hex;
use base64::{Engine as _, engine::general_purpose};
use serde_json;
use dcap_qvl::collateral::get_collateral;
use dcap_qvl::PHALA_PCCS_URL;
use dcap_qvl::verify::ring::verify;
use error::{AttestationError, Result};

#[derive(Deserialize, Debug)]
struct TdxQuoteData {
    #[allow(dead_code)]
    runtime_data: String,
    quote: String,
}

#[derive(Deserialize, Debug)]
struct TdxWrapper {
    tdx: TdxQuoteData,
}

#[derive(Deserialize, Debug)]
struct TdxAttestation {
    commit_hex: String,
    input_hash_hex: String,
    job_id: String,
    nonce_hex: String,
    output_hash_hex: String,
    quote_hex: String,
    reportdata_hex: String,
}

#[derive(Deserialize, Debug)]
struct AttestationData {
    job_id: String,
    attestation_hash_hex: String,
    secrets_hash_hex: String,
    tdx_attestation: TdxAttestation,
}

fn parse_tdx_attestation_json(quote_hex: &str) -> Result<Vec<u8>> {
    let json_bytes = hex::decode(quote_hex)?;
    let json_str = String::from_utf8(json_bytes)?;
    let tdx_wrapper: TdxWrapper = serde_json::from_str(&json_str)?;
    let quote_bytes = general_purpose::STANDARD.decode(&tdx_wrapper.tdx.quote)?;
    Ok(quote_bytes)
}

fn verify_attestation_structure(data: &AttestationData) -> Result<()> {
    if data.job_id != data.tdx_attestation.job_id {
        return Err(AttestationError::StructuralVerification {
            reason: "Job ID mismatch".to_string(),
        });
    }
    
    if data.attestation_hash_hex != data.tdx_attestation.input_hash_hex {
        return Err(AttestationError::StructuralVerification {
            reason: "Attestation hash mismatch".to_string(),
        });
    }
    
    if data.secrets_hash_hex != data.tdx_attestation.output_hash_hex {
        return Err(AttestationError::StructuralVerification {
            reason: "Secrets hash mismatch".to_string(),
        });
    }
    
    let expected_reportdata = format!("{}{}", 
        data.tdx_attestation.commit_hex,
        data.tdx_attestation.nonce_hex
    );
    
    if expected_reportdata != data.tdx_attestation.reportdata_hex {
        return Err(AttestationError::StructuralVerification {
            reason: "Reportdata construction mismatch".to_string(),
        });
    }
    
    Ok(())
}

async fn verify_dcap_quote(quote_bytes: &[u8]) -> Result<()> {
    if quote_bytes.len() < 48 {
        return Err(AttestationError::QuoteTooShort {
            expected: 48,
            actual: quote_bytes.len(),
        });
    }
    
    let tee_type = u32::from_le_bytes([
        quote_bytes[4], quote_bytes[5], quote_bytes[6], quote_bytes[7]
    ]);
    
    if tee_type != 0x00000081 {
        return Err(AttestationError::InvalidTeeType { actual: tee_type });
    }
    
    let pccs_url = std::env::var("PCCS_URL")
        .unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
    
    let collateral = get_collateral(&pccs_url, quote_bytes).await
        .map_err(|e| AttestationError::CollateralFetch(e.to_string()))?;
    
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    verify(quote_bytes, &collateral, current_time)
        .map_err(|e| AttestationError::Verification(e.to_string()))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let json_data = fs::read_to_string("example.json")?;
    let attestation: AttestationData = serde_json::from_str(&json_data)?;
    
    verify_attestation_structure(&attestation)?;
    
    let quote_bytes = parse_tdx_attestation_json(&attestation.tdx_attestation.quote_hex)?;
    verify_dcap_quote(&quote_bytes).await?;
    
    println!("✓ Verification PASSED");
    println!("Reportdata: {}", attestation.tdx_attestation.reportdata_hex);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_verify_valid_quote() {
        let json_data = std::fs::read_to_string("example.json").unwrap();
        let attestation: AttestationData = serde_json::from_str(&json_data).unwrap();
        let quote_bytes = parse_tdx_attestation_json(&attestation.tdx_attestation.quote_hex).unwrap();
        
        let result = verify_dcap_quote(&quote_bytes).await;
        assert!(result.is_ok(), "Valid quote should verify successfully");
    }
    
    #[tokio::test]
    async fn test_verify_invalid_quote() {
        let mut invalid_quote = vec![0u8; 1000];
        invalid_quote[4..8].copy_from_slice(&0x00000081u32.to_le_bytes());
        
        let result = verify_dcap_quote(&invalid_quote).await;
        assert!(result.is_err(), "Invalid quote should fail verification");
    }
    
    #[tokio::test]
    async fn test_verify_wrong_tee_type() {
        let json_data = std::fs::read_to_string("example.json").unwrap();
        let attestation: AttestationData = serde_json::from_str(&json_data).unwrap();
        let mut quote_bytes = parse_tdx_attestation_json(&attestation.tdx_attestation.quote_hex).unwrap();
        
        quote_bytes[4..8].copy_from_slice(&0x00000000u32.to_le_bytes());
        
        let result = verify_dcap_quote(&quote_bytes).await;
        assert!(result.is_err(), "Wrong TEE type should fail");
    }
}
