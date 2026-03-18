use attestation_verifier::{verify_tdx_quote_json_hex, Result};
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<()> {
    let example: Value = serde_json::from_str(&std::fs::read_to_string("example.json")?)?;
    let wrapped_quote_hex = example
        .pointer("/tdx_attestation/quote_hex")
        .and_then(Value::as_str)
        .expect("example.json missing /tdx_attestation/quote_hex");

    verify_tdx_quote_json_hex(wrapped_quote_hex).await?;
    println!("quote verified");

    Ok(())
}
