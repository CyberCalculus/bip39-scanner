const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub struct Bech32;

impl Bech32 {
    pub fn encode(hrp: &str, data: &[u8], witness_version: u8) -> Result<String, String> {
        let conv = Self::convert_bits(data, 8, 5, true)?;
        let mut combined = vec![witness_version];
        combined.extend_from_slice(&conv);

        let checksum = Self::create_checksum(hrp, &combined);
        combined.extend_from_slice(&checksum);

        let encoded: String = combined
            .iter()
            .map(|&b| CHARSET[b as usize] as char)
            .collect();

        let sep = Self::separator().to_owned();
        Ok(format!("{}{}", hrp, sep + &encoded))
    }

    fn separator() -> &'static str {
        "1"
    }

    fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
        let hrp_bytes: Vec<u8> = hrp.bytes().map(|b| (b >> 5) | (b << 3)).collect();
        let mut values = Vec::new();
        values.extend_from_slice(&hrp_bytes);
        values.push(0);
        values.extend_from_slice(data);
        values.extend_from_slice(&[0; 6]);

        let mut poly = 1;
        for v in values {
            poly ^= v as u32;
            for _ in 0..5 {
                if poly & 1 != 0 {
                    poly = (poly >> 1) ^ 0x3B6A57B2;
                } else {
                    poly >>= 1;
                }
            }
        }
        poly ^= 1;

        let mut checksum = Vec::with_capacity(6);
        for i in 0..6 {
            checksum.push(((poly >> (5 * (5 - i))) & 31) as u8);
        }
        checksum
    }

    pub fn convert_bits(data: &[u8], from: u8, to: u8, pad: bool) -> Result<Vec<u8>, String> {
        let mut acc: u64 = 0;
        let mut bits: u32 = 0;
        let mut result = Vec::new();
        let max: u64 = (1u64 << to) - 1;

        for &byte in data {
            if from < 8 && byte >> from != 0 {
                return Err("Invalid data".into());
            }
            acc = (acc << from) | byte as u64;
            bits += from as u32;
            while bits >= to as u32 {
                bits -= to as u32;
                result.push(((acc >> bits) & max) as u8);
            }
        }

        if pad {
            if bits > 0 {
                result.push(((acc << (to as u32 - bits)) & max) as u8);
            }
        } else if bits >= from as u32 {
            return Err("Non-zero padding".into());
        } else if (acc << (to as u32 - bits)) & max != 0 {
            return Err("Non-zero padding".into());
        }

        Ok(result)
    }

    pub fn decode(_hrp: &str, bech32: &str) -> Result<(Vec<u8>, u8), String> {
        let sep = Self::separator();
        let pos = bech32
            .rfind(sep)
            .ok_or("Missing separator")?;

        let data_part = &bech32[pos + 1..];

        let mut values = Vec::new();
        for c in data_part.chars() {
            let b = CHARSET
                .iter()
                .position(|&ch| ch as char == c)
                .ok_or("Invalid bech32 character")?;
            values.push(b as u8);
        }

        if values.len() < 6 {
            return Err("Invalid bech32 data".into());
        }

        let witness_version = values[0];
        let data = &values[1..values.len() - 6];
        let _checksum = &values[values.len() - 6..];

        let conv = Self::convert_bits(data, 5, 8, false)?;
        Ok((conv, witness_version))
    }

    pub fn address(hrp: &str, witness_program: &[u8]) -> Result<String, String> {
        Self::encode(hrp, witness_program, 0)
    }
}
