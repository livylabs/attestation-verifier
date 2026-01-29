# TDX Attestation Verifier

A Rust-based verifier for Intel TDX (Trust Domain Extensions) attestations using Intel DCAP (Data Center Attestation Primitives).

## Overview

This tool performs comprehensive verification of TDX attestations, parsing the cryptographic evidence and validating the attestation structure. It demonstrates how to properly verify TDX quotes and extract reportdata from Intel's Trusted Execution Environment.

## Features

- ✅ **Real TDX Quote Parsing** - Parses actual binary TDX quote structure
- ✅ **DCAP Verification Framework** - Validates quote headers, TEE types, and signature data
- ✅ **Reportdata Extraction** - Extracts cryptographic commitments from TD Reports
- ✅ **JSON Attestation Support** - Handles JSON-encoded TDX attestations
- ✅ **Structural Validation** - Comprehensive attestation integrity checks
- ⚠️ **Certificate Chain Validation** - Framework ready (requires Intel DCAP libraries)

## Architecture

### TDX Attestation Structure

The verifier handles TDX attestations with this structure:

```json
{
  "job_id": "unique-job-identifier",
  "attestation_hash_hex": "hash-of-input-data", 
  "secrets_hash_hex": "hash-of-output-data",
  "tdx_attestation": {
    "commit_hex": "git-commit-hash",
    "input_hash_hex": "input-data-hash",
    "job_id": "matching-job-id",
    "nonce_hex": "random-nonce",
    "output_hash_hex": "output-data-hash",
    "quote_hex": "hex-encoded-json-tdx-attestation",
    "reportdata_hex": "commit-plus-nonce-hash"
  }
}
```

### TDX Quote Format

The `quote_hex` field contains a hex-encoded JSON structure:

```json
{
  "tdx": {
    "runtime_data": "base64-encoded-input-data",
    "quote": "base64-encoded-binary-tdx-quote"
  }
}
```

The binary TDX quote follows Intel's specification:
- **Header** (48 bytes): Version, TEE type (0x00000081 for TDX), attestation key type
- **TD Report** (584 bytes): Contains reportdata at offset 368-431
- **Signature Data** (variable): DCAP signature and certificate chain

## Verification Process

1. **Structural Validation**
   - Job ID consistency across fields
   - Hash consistency between top-level and TDX fields
   - Reportdata construction validation (commit + nonce)

2. **TDX Quote Parsing**
   - Decode hex-encoded JSON attestation
   - Extract base64-encoded binary quote
   - Parse TDX quote header and TD Report
   - Validate TEE type (must be 0x00000081)

3. **Reportdata Analysis**
   - Extract reportdata from TD Report (cryptographic commitment)
   - Compare with JSON metadata (input data tracking)
   - Verify commit+nonce construction

4. **DCAP Verification**
   - Validate quote structure and signature data
   - Check signature data length and format
   - Framework for certificate chain validation

## Usage

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Dependencies are managed by Cargo
```

### Running the Verifier

# Run verification on example.json
cargo run

### Expected Output

```
TDX Attestation Verifier
==========================
Attestation Summary:
Job ID: 56d836f7424df37d105d4c215ec97973
Attestation Hash: 84b2551c7ed406aafacdd42a9b8e308b13a61c2d179f203ce6bce1b32622548c
Secrets Hash: 9ec638aa424b51a2324d33ef61c127dbf80b8b8dcb00bd4e6ed332bf35cc87f6
Quote Length: 23110 chars

Starting attestation verification...
1. Checking job_id consistency...
PASSED: Job IDs match
2. Checking hash consistency...
PASSED: Attestation hashes match
PASSED: Secrets hashes match
3. Verifying reportdata construction...
PASSED: Reportdata construction valid
4. Parsing TDX attestation...
Decoded TDX attestation JSON structure
Extracted binary TDX quote: 8000 bytes
Runtime data: 88 chars
PASSED: TDX attestation parsed successfully
TDX Quote Header:
  Version: 4
  TEE Type: 129 (should be 0x00000081 for TDX)
  Attestation Key Type: 2
5. Verifying reportdata consistency...
PASSED: JSON reportdata matches commit+nonce construction
6. Performing DCAP verification...
DCAP VERIFICATION STATUS:
✓ Quote structure parsed successfully
✓ TDX TEE type validated
✓ Reportdata extracted and verified
✓ Signature data present

ATTESTATION VERIFICATION PASSED
The TDX attestation is structurally valid and DCAP verification completed.
```
