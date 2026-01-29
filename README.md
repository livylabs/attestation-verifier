# TDX Attestation Verifier

Minimal Rust verifier for Intel TDX (Trust Domain Extensions) quotes using DCAP verification.

## What It Does

Verifies Intel TDX quotes by:
1. **Structural validation** - Validates job IDs, hashes, and reportdata consistency
2. **Quote parsing** - Extracts binary TDX quote from JSON attestation
3. **DCAP verification** - Cryptographically verifies quote using `dcap-qvl` with Intel collaterals

## Intel Components

- **TDX Quotes** - Binary attestation reports from TDX platforms
- **Intel PCS/PCCS** - Fetches collaterals (TCB Info, QE Identity, Root CA, CRLs)
- **dcap-qvl** - Rust library implementing Intel DCAP verification

## Usage

```bash
# Verify quote from example.json
cargo run

# Run tests
cargo test
```

An example Intel TDX quote is provided in `example.json`.

## Output

```
✓ Verification PASSED
Reportdata: 33e53c29727e76b8b927e69b84d201a4e78178b5603c83e02b744786c15a8b4cb5ca0e1f4a38d483c7ddbafefbce0bd3e2d38c05c97b0f2a68772690e3b4deae
```

The reportdata is the cryptographic commitment (commit + nonce) verified in the TDX quote.
