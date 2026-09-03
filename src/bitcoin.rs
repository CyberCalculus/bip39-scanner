//! Bitcoin SegWit address construction via the audited `bech32` crate.
//!
//! Uses `bech32::segwit::encode`/`decode` which automatically selects
//! Bech32 (witness v0) vs Bech32m (witness v1+) and enforces program
//! length constraints and checksum validation.

use bech32::{Fe32, Hrp};

#[derive(Debug, Clone, PartialEq)]
pub enum AddressError {
    InvalidProgramLength { version: u8, length: usize },
    InvalidVersion(u8),
    DecodeError(String),
}

/// Encode a SegWit address. Witness v0 uses Bech32; v1+ uses Bech32m.
/// Validates program length per BIP141.
pub fn segwit_address(
    hrp: &str,
    witness_version: u8,
    witness_program: &[u8],
) -> Result<String, AddressError> {
    if witness_version > 16 {
        return Err(AddressError::InvalidVersion(witness_version));
    }
    let allowed = match witness_version {
        0 => witness_program.len() == 20 || witness_program.len() == 32,
        1 => witness_program.len() == 32,
        _ => witness_program.len() == 20 || witness_program.len() == 32,
    };
    if !allowed {
        return Err(AddressError::InvalidProgramLength {
            version: witness_version,
            length: witness_program.len(),
        });
    }

    let hrp = Hrp::parse(hrp).map_err(|e| AddressError::DecodeError(e.to_string()))?;

    if witness_version == 0 {
        bech32::segwit::encode_v0(hrp, witness_program)
            .map_err(|e| AddressError::DecodeError(e.to_string()))
    } else {
        let ver = Fe32::try_from(witness_version)
            .map_err(|_| AddressError::InvalidVersion(witness_version))?;
        bech32::segwit::encode(hrp, ver, witness_program)
            .map_err(|e| AddressError::DecodeError(e.to_string()))
    }
}

/// Decode a bech32/bech32m SegWit address and verify HRP, version,
/// program length, and checksum. The audited `bech32::segwit::decode`
/// function verifies the checksum (Bech32 for v0, Bech32m for v1+) and
/// returns the witness version + program.
pub fn segwit_decode(
    hrp: &str,
    addr: &str,
) -> Result<(u8, Vec<u8>), AddressError> {
    let expected_hrp = Hrp::parse(hrp).map_err(|e| AddressError::DecodeError(e.to_string()))?;
    let (parsed_hrp, ver, data) =
        bech32::segwit::decode(addr).map_err(|e| AddressError::DecodeError(e.to_string()))?;
    if parsed_hrp != expected_hrp {
        return Err(AddressError::DecodeError(format!(
            "HRP mismatch: expected {}, got {}",
            expected_hrp, parsed_hrp
        )));
    }
    let v = u8::from(ver);
    if v > 16 {
        return Err(AddressError::InvalidVersion(v));
    }
    Ok((v, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip173_p2wpkh_encode() {
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = segwit_address("bc", 0, &program).unwrap();
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_bip173_p2wpkh_decode() {
        let (v, program) =
            segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(v, 0);
        let expected = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(program, expected);
    }

    #[test]
    fn test_bip173_invalid_checksum_rejected() {
        let bad = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
        assert!(segwit_decode("bc", bad).is_err());
    }

    #[test]
    fn test_bip173_wrong_hrp_rejected() {
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert!(segwit_decode("tb", addr).is_err());
    }

    #[test]
    fn test_invalid_program_length() {
        let too_long = vec![0u8; 40];
        assert!(matches!(
            segwit_address("bc", 0, &too_long),
            Err(AddressError::InvalidProgramLength { version: 0, length: 40 })
        ));
    }
}