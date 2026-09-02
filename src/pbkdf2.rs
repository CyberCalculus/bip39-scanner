use crate::hmac::HmacSha512;

pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let hmac = HmacSha512::new(password);
    let h_len = 64;
    let blocks = (dk_len + h_len - 1) / h_len;
    let mut dk = Vec::with_capacity(blocks * h_len);

    for block_idx in 1..=blocks as u32 {
        let mut u = hmac.update_with_block(salt, block_idx);
        let mut t = u;

        for _ in 1..iterations {
            u = hmac.update(&u);
            for i in 0..h_len {
                t[i] ^= u[i];
            }
        }

        dk.extend_from_slice(&t);
    }

    dk.truncate(dk_len);
    dk
}
