use crate::sha512::Sha512;

pub struct HmacSha512 {
    i_key: [u8; 128],
    o_key: [u8; 128],
}

impl HmacSha512 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 128];
        if key.len() > 128 {
            let hash = Sha512::digest(key);
            k[..64].copy_from_slice(&hash);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut i_key = [0x36u8; 128];
        let mut o_key = [0x5cu8; 128];
        for i in 0..128 {
            i_key[i] ^= k[i];
            o_key[i] ^= k[i];
        }

        Self { i_key, o_key }
    }

    pub fn update(&self, data: &[u8]) -> [u8; 64] {
        let mut inner = Sha512::new();
        inner.update(&self.i_key);
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = Sha512::new();
        outer.update(&self.o_key);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn update_with_block(&self, salt: &[u8], block_idx: u32) -> [u8; 64] {
        let mut salt_with_block = salt.to_vec();
        salt_with_block.extend_from_slice(&block_idx.to_be_bytes());
        self.update(&salt_with_block)
    }
}
