//! BIP32 hierarchical deterministic key derivation.
//!
//! All crypto delegated to audited crates:
//! - secp256k1: `k256::Scalar` (arithmetic) + `k256::ProjectivePoint` (pubkey)
//! - HMAC-SHA512: `hmac` + `sha2`
//! - HASH160: `ripemd` + `sha2`

use elliptic_curve::sec1::ToSec1Point;
use elliptic_curve::{FieldBytes, PrimeField};
use hmac::{Hmac, KeyInit, Mac};
use log::debug;
use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1};
use ripemd::{Digest as _, Ripemd160};
use sha2::{Sha256, Sha512};

use crate::bitcoin;

#[derive(Debug, Clone, PartialEq)]
pub enum Bip32Error {
    InvalidIl,
    ZeroChildKey,
    InvalidScalar,
    InvalidPath(String),
    AddressError(String),
}

impl std::fmt::Display for Bip32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bip32Error::InvalidIl => write!(f, "invalid I_L (>= n)"),
            Bip32Error::ZeroChildKey => write!(f, "child key is zero"),
            Bip32Error::InvalidScalar => write!(f, "invalid scalar"),
            Bip32Error::InvalidPath(p) => write!(f, "invalid derivation path: {}", p),
            Bip32Error::AddressError(e) => write!(f, "address error: {}", e),
        }
    }
}

/// BIP32 extended private key + chain code.
#[derive(Clone)]
pub struct ExtendedKey {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub index: u32,
    pub parent_fingerprint: [u8; 4],
}

impl ExtendedKey {
    pub fn new(key: [u8; 32], chain_code: [u8; 32]) -> Self {
        Self {
            key,
            chain_code,
            depth: 0,
            index: 0,
            parent_fingerprint: [0; 4],
        }
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let pubkey = derive_pubkey_compressed(&self.key);
        let mut sha = Sha256::new();
        sha.update(&pubkey);
        let sha = sha.finalize();
        let mut ripe = Ripemd160::new();
        ripe.update(&sha);
        let ripe = ripe.finalize();
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&ripe[..4]);
        fp
    }
}

/// Generator point G of secp256k1.
fn generator() -> ProjectivePoint {
    <ProjectivePoint as k256::elliptic_curve::group::Group>::generator()
}

/// Derive the 33-byte compressed secp256k1 public key for a 32-byte private key.
pub fn derive_pubkey_compressed(privkey: &[u8; 32]) -> [u8; 33] {
    let mut fb = FieldBytes::<Secp256k1>::default();
    fb.copy_from_slice(privkey);
    let scalar_opt = Scalar::from_repr(fb);
    let scalar = scalar_opt.unwrap();
    let pk = generator() * scalar;
    let encoded = pk.to_affine().to_sec1_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    out
}

/// HASH160 = RIPEMD160(SHA256(x)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut sha = Sha256::new();
    sha.update(data);
    let sha = sha.finalize();
    let mut ripe = Ripemd160::new();
    ripe.update(&sha);
    let ripe = ripe.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe[..20]);
    out
}

pub struct Bip32;

impl Bip32 {
    pub fn from_seed(seed: &[u8]) -> Result<ExtendedKey, Bip32Error> {
        debug!("BIP32: deriving master key from seed ({} bytes)", seed.len());
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(b"Bitcoin seed")
            .map_err(|_| Bip32Error::InvalidScalar)?;
        mac.update(seed);
        let bytes = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        chain_code.copy_from_slice(&bytes[32..64]);
        Ok(ExtendedKey::new(key, chain_code))
    }

    pub fn derive_child(parent: &ExtendedKey, index: u32) -> Result<ExtendedKey, Bip32Error> {
        let hardened = index >= 0x80000000;
        debug!("BIP32: deriving child {}{}", index & 0x7FFFFFFF, if hardened { "H" } else { "" });
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&parent.chain_code)
            .map_err(|_| Bip32Error::InvalidScalar)?;
        let mut data = Vec::with_capacity(37);
        if index >= 0x80000000 {
            data.push(0);
            data.extend_from_slice(&parent.key);
        } else {
            data.extend_from_slice(&derive_pubkey_compressed(&parent.key));
        }
        data.extend_from_slice(&index.to_be_bytes());
        mac.update(&data);
        let bytes = mac.finalize().into_bytes();
        let mut il = [0u8; 32];
        let mut ir = [0u8; 32];
        il.copy_from_slice(&bytes[..32]);
        ir.copy_from_slice(&bytes[32..64]);

        // Reject I_L >= n.
        let mut il_fb = FieldBytes::<Secp256k1>::default();
        il_fb.copy_from_slice(&il);
        let il_opt = Scalar::from_repr(il_fb);
        if bool::from(il_opt.is_none()) {
            return Err(Bip32Error::InvalidIl);
        }
        let il_scalar = il_opt.unwrap();

        let mut parent_fb = FieldBytes::<Secp256k1>::default();
        parent_fb.copy_from_slice(&parent.key);
        let parent_opt = Scalar::from_repr(parent_fb);
        let parent_scalar = if bool::from(parent_opt.is_none()) {
            return Err(Bip32Error::InvalidScalar);
        } else {
            parent_opt.unwrap()
        };

        let child_scalar = parent_scalar + il_scalar;
        if bool::from(child_scalar.is_zero()) {
            return Err(Bip32Error::ZeroChildKey);
        }

        let child_bytes = child_scalar.to_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&child_bytes);

        Ok(ExtendedKey {
            key,
            chain_code: ir,
            depth: parent.depth + 1,
            index,
            parent_fingerprint: parent.fingerprint(),
        })
    }

    pub fn derive_path(master: &ExtendedKey, path: &str) -> Result<ExtendedKey, Bip32Error> {
        let mut current = master.clone();
        for part in path.split('/') {
            if part == "m" || part.is_empty() {
                continue;
            }
            let (num_str, hardened) = match part.strip_suffix('\'') {
                Some(s) => (s, true),
                None => match part.strip_suffix('h') {
                    Some(s) => (s, true),
                    None => (part, false),
                },
            };
            let index: u32 = num_str
                .parse()
                .map_err(|e: std::num::ParseIntError| Bip32Error::InvalidPath(e.to_string()))?;
            let actual_index = if hardened { index + 0x80000000 } else { index };
            current = Self::derive_child(&current, actual_index)?;
        }
        Ok(current)
    }

    pub fn privkey_to_pubkey(privkey: &[u8; 32]) -> [u8; 33] {
        derive_pubkey_compressed(privkey)
    }

    pub fn pubkey_to_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
        hash160(pubkey)
    }

    /// SegWit v0 P2WPKH bech32 address for a 32-byte private key.
    pub fn privkey_to_address(privkey: &[u8; 32]) -> Result<String, Bip32Error> {
        let pubkey = Self::privkey_to_pubkey(privkey);
        let program = Self::pubkey_to_hash160(&pubkey);
        bitcoin::segwit_address("bc", 0, &program)
            .map_err(|e| Bip32Error::AddressError(format!("{:?}", e)))
    }
}

/// Re-export for callers who want a `Point` type alias.
pub type Point = AffinePoint;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_master_key() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed).unwrap();
        assert_eq!(master.depth, 0);
        assert!(!master.key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_derive_child() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed).unwrap();
        let child = Bip32::derive_child(&master, 0).unwrap();
        assert_eq!(child.depth, 1);
        assert_ne!(child.key, master.key);
    }

    #[test]
    fn test_derive_path() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed).unwrap();
        let derived = Bip32::derive_path(&master, "m/84'/0'/0'/0/0").unwrap();
        assert_eq!(derived.depth, 5);
    }

    /// BIP32 official vector 1, m/0H.
    #[test]
    fn test_bip32_vector_1_m0h() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed).unwrap();
        let child0 = Bip32::derive_child(&master, 0x80000000).unwrap();
        let expected_cc: [u8; 32] = [
            0x47, 0xfd, 0xac, 0xbd, 0x0f, 0x10, 0x97, 0x04,
            0x3b, 0x78, 0xc6, 0x3c, 0x20, 0xc3, 0x4e, 0xf4,
            0xed, 0x9a, 0x11, 0x1d, 0x98, 0x00, 0x47, 0xad,
            0x16, 0x28, 0x2c, 0x7a, 0xe6, 0x23, 0x61, 0x41,
        ];
        assert_eq!(child0.chain_code, expected_cc);
        let pk = Bip32::privkey_to_pubkey(&child0.key);
        let expected_pk: [u8; 33] = [
            0x03, 0x5a, 0x78, 0x46, 0x62, 0xa4, 0xa2, 0x0a,
            0x65, 0xbf, 0x6a, 0xab, 0x9a, 0xe9, 0x8a, 0x6c,
            0x06, 0x8a, 0x81, 0xc5, 0x2e, 0x4b, 0x03, 0x2c,
            0x0f, 0xb5, 0x40, 0x0c, 0x70, 0x6c, 0xfc, 0xcc,
            0x56,
        ];
        assert_eq!(pk, expected_pk);
    }

    /// BIP32 official vector 2 chain code at m/0/2147483647H/1.
    #[test]
    fn test_bip32_vector_2_long_path() {
        let seed = hex_literal::hex!("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        let master = Bip32::from_seed(&seed).unwrap();
        let c1 = Bip32::derive_child(&master, 0).unwrap();
        let c2 = Bip32::derive_child(&c1, 0x80000000u32 + 2147483647).unwrap();
        let c3 = Bip32::derive_child(&c2, 1).unwrap();
        let expected: [u8; 32] = [
            0xf3, 0x66, 0xf4, 0x8f, 0x1e, 0xa9, 0xf2, 0xd1,
            0xd3, 0xfe, 0x95, 0x8c, 0x95, 0xca, 0x84, 0xea,
            0x18, 0xe4, 0xc4, 0xdd, 0xb9, 0x36, 0x6c, 0x33,
            0x6c, 0x92, 0x7e, 0xb2, 0x46, 0xfb, 0x38, 0xcb,
        ];
        assert_eq!(c3.chain_code, expected);
    }

    #[test]
    fn test_address_privkey_1_p2wpkh() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let addr = Bip32::privkey_to_address(&pk).unwrap();
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }
}