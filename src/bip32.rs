use crate::hmac::HmacSha512;
use crate::secp256k1::Secp256k1;

pub struct Bip32;

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
        let pubkey = Secp256k1::pubkey_from_privkey(&self.key);
        let hash = crate::sha256::Sha256::digest(&pubkey);
        let ripemd = crate::ripemd160::Ripemd160::digest(&hash);
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&ripemd[..4]);
        fp
    }

    pub fn serialize_private(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(78);
        out.extend_from_slice(&0x0488ADE4u32.to_be_bytes());
        out.push(self.depth);
        out.extend_from_slice(&self.parent_fingerprint);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.chain_code);
        out.push(0);
        out.extend_from_slice(&self.key);
        out
    }
}

impl Bip32 {
    pub fn from_seed(seed: &[u8]) -> ExtendedKey {
        let hmac = HmacSha512::new(b"Bitcoin seed");
        let hash = hmac.update(seed);

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&hash[..32]);
        chain_code.copy_from_slice(&hash[32..64]);

        ExtendedKey::new(key, chain_code)
    }

    pub fn derive_child(parent: &ExtendedKey, index: u32) -> ExtendedKey {
        let hmac = HmacSha512::new(&parent.chain_code);

        let mut data = Vec::with_capacity(37);

        if index >= 0x80000000 {
            data.push(0);
            data.extend_from_slice(&parent.key);
        } else {
            let pubkey = Secp256k1::pubkey_from_privkey(&parent.key);
            data.extend_from_slice(&pubkey);
        }
        data.extend_from_slice(&index.to_be_bytes());

        let hash = hmac.update(&data);

        let mut il = [0u8; 32];
        let mut chain_code = [0u8; 32];
        il.copy_from_slice(&hash[..32]);
        chain_code.copy_from_slice(&hash[32..64]);

        let mut key = [0u8; 32];
        let n = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x78, 0xB2, 0x55, 0x8D, 0x5E, 0x98,
        ];

        let mut carry = 0i32;
        for i in (0..32).rev() {
            let sum = parent.key[i] as i32 + il[i] as i32 + carry;
            key[i] = sum as u8;
            carry = sum >> 8;
        }

        if carry != 0 {
            for i in (0..32).rev() {
                let sum = key[i] as i32 + n[i] as i32 + carry;
                key[i] = sum as u8;
                carry = sum >> 8;
            }
        }

        ExtendedKey {
            key,
            chain_code,
            depth: parent.depth + 1,
            index,
            parent_fingerprint: parent.fingerprint(),
        }
    }

    pub fn derive_path(master: &ExtendedKey, path: &str) -> ExtendedKey {
        let mut current = master.clone();
        let parts: Vec<&str> = path.split('/').collect();

        for part in parts {
            if part == "m" || part.is_empty() {
                continue;
            }

            let hardened = part.ends_with("'") || part.ends_with("h");
            let num_str = if hardened {
                &part[..part.len() - 1]
            } else {
                part
            };

            let index: u32 = num_str.parse().expect("Invalid derivation index");
            let actual_index = if hardened {
                index + 0x80000000
            } else {
                index
            };

            current = Self::derive_child(&current, actual_index);
        }

        current
    }

    pub fn privkey_to_pubkey(privkey: &[u8; 32]) -> [u8; 33] {
        Secp256k1::pubkey_from_privkey(privkey)
    }

    pub fn pubkey_to_hash160(pubkey: &[u8; 33]) -> [u8; 20] {
        crate::ripemd160::Ripemd160::hash160(pubkey)
    }

    pub fn privkey_to_address(privkey: &[u8; 32]) -> Result<String, String> {
        let pubkey = Self::privkey_to_pubkey(privkey);
        let hash = Self::pubkey_to_hash160(&pubkey);
        crate::bech32::Bech32::address("bc", &hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_master_key() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed);
        assert_eq!(master.depth, 0);
        assert!(!master.key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_derive_child() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed);
        let child = Bip32::derive_child(&master, 0);
        assert_eq!(child.depth, 1);
        assert_ne!(child.key, master.key);
    }

    #[test]
    fn test_derive_path() {
        let seed = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let master = Bip32::from_seed(&seed);
        let derived = Bip32::derive_path(&master, "m/84'/0'/0'/0/0");
        assert_eq!(derived.depth, 5);
    }

    #[test]
    fn test_address_generation() {
        let privkey = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let addr = Bip32::privkey_to_address(&privkey).unwrap();
        assert!(addr.starts_with("bc1q"));
    }
}
