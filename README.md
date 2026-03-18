# attestation_verifier

Minimal Rust crate for verifying Intel TDX quotes with DCAP.

It is focused on the one thing you want to publish as a reusable crate:

- verify raw quote bytes
- verify raw quote hex
- verify the common wrapped payload shape `{"tdx":{"quote":"..."}}`
- verify the hex-encoded form of that wrapped payload, which matches the `quote_hex` field in this repo's `example.json`
- extract `report_data` from a raw quote

The crate fetches Intel collaterals through PCCS using [`dcap-qvl`](https://docs.rs/dcap-qvl/latest/dcap_qvl/). By default it reads `PCCS_URL` from the environment and falls back to `PHALA_PCCS_URL`.

## Install

```toml
[dependencies]
attestation_verifier = "0.1"
```

## Examples

Verify a raw quote hex string:

```rust
use attestation_verifier::verify_quote_hex;

async fn demo() -> attestation_verifier::Result<()> {
    verify_quote_hex("0x...").await?;
    Ok(())
}
```

Verify a wrapped TDX JSON payload:

```rust
use attestation_verifier::verify_tdx_quote_json;

async fn demo() -> attestation_verifier::Result<()> {
    let payload = r#"{"tdx":{"quote":"BASE64_QUOTE_HERE"}}"#;
    verify_tdx_quote_json(payload).await?;
    Ok(())
}
```

Verify the wrapped hex payload used by `example.json`:

```rust
use attestation_verifier::verify_tdx_quote_json_hex;

async fn demo() -> attestation_verifier::Result<()> {
    verify_tdx_quote_json_hex("7b226...").await?;
    Ok(())
}
```

Extract `report_data` as hex:

```rust
use attestation_verifier::{extract_report_data_hex, decode_tdx_quote_json_hex};

fn demo() -> attestation_verifier::Result<String> {
    let quote = decode_tdx_quote_json_hex("7b226...")?;
    extract_report_data_hex(&quote)
}
```

## Local Example

This repo includes [`example.json`](./example.json). The relevant field is:

```text
tdx_attestation.quote_hex
```

That field is not raw quote hex. It is hex-encoded JSON containing a base64 quote, so the matching API is:

```rust
use attestation_verifier::verify_tdx_quote_json_hex;
```

If you want the `report_data` from that same field, use:

```rust
use attestation_verifier::{decode_tdx_quote_json_hex, extract_report_data_hex};
```

## Notes

- Verification requires network access to a PCCS endpoint.
- The default test suite stays offline. The live verification test is marked `ignored`.
- If you want a different PCCS, set `PCCS_URL` or create `Verifier::new("https://your-pccs")`.
