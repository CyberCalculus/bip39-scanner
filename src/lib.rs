//! BIP39 mnemonic scanner library.
//!
//! All cryptographic primitives (BIP39 wordlist + checksum, BIP32 HD
//! derivation, secp256k1 point arithmetic, Bech32/Bech32m address
//! encoding, PBKDF2-HMAC-SHA512, RIPEMD-160, HASH160, and CSPRNG entropy)
//! use audited crates: `k256`, `bech32`, `getrandom`, `sha2`, `hmac`,
//! `pbkdf2`, `ripemd`. No crypto is implemented from scratch.

pub mod bip39;
pub mod bip32;
pub mod bitcoin;
pub mod config;
pub mod checkpoint;
pub mod ticket;
pub mod ui;