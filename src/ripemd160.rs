use crate::sha256::Sha256;

// RIPEMD-160 constants
const K_LEFT: [u32; 5] = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const K_RIGHT: [u32; 5] = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

// Message word selection order (16 per round, 5 rounds = 80 steps)
const R_LEFT: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const R_RIGHT: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

// Per-step rotation amounts (s for the left line, sp for the right line).
// Source: standard RIPEMD-160 reference, verified against hashlib.
const S_LEFT: [u32; 80] = [
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
];

const S_RIGHT: [u32; 80] = [
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
];

#[inline]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    // Standard RIPEMD-160 round functions. The right line reuses this
    // same function family but indexes it with (79 - j), which traverses
    // the rounds in reverse (round 4 → round 0).
    match j / 16 {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

fn compress_block(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut al = h[0];
    let mut bl = h[1];
    let mut cl = h[2];
    let mut dl = h[3];
    let mut el = h[4];

    let mut ar = h[0];
    let mut br = h[1];
    let mut cr = h[2];
    let mut dr = h[3];
    let mut er = h[4];

    for j in 0..80 {
        let round = j / 16;

        // Left line: state rotation (al, bl, cl, dl, el) ← (el, t, bl, rol(cl,10), dl)
        let t = al
            .wrapping_add(f(j, bl, cl, dl))
            .wrapping_add(x[R_LEFT[j]])
            .wrapping_add(K_LEFT[round]);
        let t = t.rotate_left(S_LEFT[j]).wrapping_add(el);
        let new_al = el;
        let new_bl = t;
        let new_cl = bl;
        let new_dl = cl.rotate_left(10);
        let new_el = dl;
        al = new_al;
        bl = new_bl;
        cl = new_cl;
        dl = new_dl;
        el = new_el;

        // Right line: same state rotation scheme. The round function is f
// with index (79 - j), traversing the rounds in reverse.
        let t = ar
            .wrapping_add(f(79 - j, br, cr, dr))
            .wrapping_add(x[R_RIGHT[j]])
            .wrapping_add(K_RIGHT[round]);
        let t = t.rotate_left(S_RIGHT[j]).wrapping_add(er);
        let new_ar = er;
        let new_br = t;
        let new_cr = br;
        let new_dr = cr.rotate_left(10);
        let new_er = dr;
        ar = new_ar;
        br = new_br;
        cr = new_cr;
        dr = new_dr;
        er = new_er;
    }

    // Final mixing of the two parallel lines
    let t = h[1].wrapping_add(cl).wrapping_add(dr);
    h[1] = h[2].wrapping_add(dl).wrapping_add(er);
    h[2] = h[3].wrapping_add(el).wrapping_add(ar);
    h[3] = h[4].wrapping_add(al).wrapping_add(br);
    h[4] = h[0].wrapping_add(bl).wrapping_add(cr);
    h[0] = t;
}

pub struct Ripemd160;

impl Ripemd160 {
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

        let msg_len = data.len();
        let bit_len = (msg_len as u64) * 8;

        // Pad: append 0x80, then zero-pad until length ≡ 56 mod 64, then 8-byte LE length
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_le_bytes());

        for chunk in msg.chunks_exact(64) {
            let block: &[u8; 64] = chunk.try_into().unwrap();
            compress_block(&mut h, block);
        }

        let mut out = [0u8; 20];
        out[0..4].copy_from_slice(&h[0].to_le_bytes());
        out[4..8].copy_from_slice(&h[1].to_le_bytes());
        out[8..12].copy_from_slice(&h[2].to_le_bytes());
        out[12..16].copy_from_slice(&h[3].to_le_bytes());
        out[16..20].copy_from_slice(&h[4].to_le_bytes());
        out
    }

    pub fn hash160(data: &[u8]) -> [u8; 20] {
        let sha = Sha256::digest(data);
        Self::digest(&sha)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ripemd_empty() {
        let hash = Ripemd160::digest(b"");
        assert_eq!(
            hex(&hash),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn test_ripemd_abc() {
        let hash = Ripemd160::digest(b"abc");
        assert_eq!(
            hex(&hash),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn test_ripemd_message() {
        let hash = Ripemd160::digest(b"message");
        assert_eq!(
            hex(&hash),
            "1dddbe1bea18cfda41f3fa4e6e66dbbbab93774e"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}