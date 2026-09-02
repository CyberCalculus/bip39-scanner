#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub limbs: [u32; 8],
}

pub const P: Field = Field {
    limbs: [
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    ],
};

const N: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
    0xBAAEDCE6AF48A03B,
    0xFD278B82558D5E9,
];

impl Field {
    pub const ZERO: Field = Field { limbs: [0; 8] };
    pub const ONE: Field = Field {
        limbs: [1, 0, 0, 0, 0, 0, 0, 0],
    };

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u32; 8];
        for i in 0..8 {
            let offset = (7 - i) * 4;
            limbs[i] = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
        }
        Self { limbs }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let offset = (7 - i) * 4;
            bytes[offset..offset + 4].copy_from_slice(&self.limbs[i].to_be_bytes());
        }
        bytes
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    pub fn div2(&mut self) {
        for i in 0..7 {
            self.limbs[i] = (self.limbs[i] >> 1) | (self.limbs[i + 1] << 31);
        }
        self.limbs[7] >>= 1;
    }

    pub fn mul2(&mut self) {
        let mut carry = 0u32;
        for i in 0..8 {
            let val = (self.limbs[i] as u64) * 2 + carry as u64;
            self.limbs[i] = val as u32;
            carry = (val >> 32) as u32;
        }
        if carry > 0 || *self >= P {
            self.sub_p();
        }
    }

    pub fn add(&self, other: &Field) -> Field {
        let mut result = Field { limbs: [0; 8] };
        let mut carry = 0u64;
        for i in 0..8 {
            let val = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            result.limbs[i] = val as u32;
            carry = val >> 32;
        }
        if carry > 0 || result >= P {
            result.sub_p();
        }
        result
    }

    fn sub_p(&mut self) {
        let mut borrow: i64 = 0;
        for i in 0..8 {
            let diff = self.limbs[i] as i64 - P.limbs[i] as i64 - borrow;
            if diff >= 0 {
                self.limbs[i] = diff as u32;
                borrow = 0;
            } else {
                self.limbs[i] = (diff + (1i64 << 32)) as u32;
                borrow = 1;
            }
        }
    }

    pub fn sub(&self, other: &Field) -> Field {
        let mut result = [0u64; 8];
        let mut borrow: i64 = 0;
        for i in 0..8 {
            let diff = self.limbs[i] as i64 - other.limbs[i] as i64 - borrow;
            if diff >= 0 {
                result[i] = diff as u64;
                borrow = 0;
            } else {
                result[i] = (diff + (1i64 << 32)) as u64;
                borrow = 1;
            }
        }
        let mut limbs = [0u32; 8];
        for i in 0..8 {
            limbs[i] = result[i] as u32;
        }
        let mut out = Field { limbs };
        if borrow != 0 {
            out = out.add(&P);
        }
        out
    }

    pub fn mul(&self, other: &Field) -> Field {
        // Schoolbook multiplication: accumulate the 512-bit product as 16 u32 limbs,
        // each holding the low 32 bits of the running sum.
        let mut acc: [u64; 16] = [0; 16];
        for i in 0..8 {
            let mut carry: u64 = 0;
            for j in 0..8 {
                let prod = self.limbs[i] as u64 * other.limbs[j] as u64;
                let s = acc[i + j] + prod + carry;
                acc[i + j] = s & 0xFFFFFFFF;
                carry = s >> 32;
            }
            acc[i + 8] += carry;
        }

        // Debug only when running tests
        #[cfg(test)]
        {
            eprintln!("DEBUG mul acc[0..8]:  = {:x?}", &acc[0..8]);
            eprintln!("DEBUG mul acc[8..16]: = {:x?}", &acc[8..16]);
        }

        // secp256k1 prime p = 2^256 - 2^32 - 977.
// So 2^256 ≡ 2^32 + 977 (mod p), and the high-half contribution reduces
// to x_high * (2^32 + 977). Multiplying acc_high by 0x3D1 alone would
// only account for the 977 term and miss the 2^32 term entirely.
        const C: u128 = (1u128 << 32) + 977; // 2^32 + 977
        // Use u128 for the accumulator: each limb's contribution can reach
        // up to ~2^65 (32-bit limb * ~33-bit constant), so 8 of them need ~67
        // bits of headroom — well within u128.
        let mut r: [u128; 9] = [0; 9];
        for i in 0..8 {
            r[i] += acc[i] as u128 + acc[i + 8] as u128 * C;
        }
        // Propagate carries.
        for i in 0..8 {
            let carry = r[i] >> 32;
            r[i] &= 0xFFFFFFFF;
            r[i + 1] += carry;
        }

        let mut limbs = [0u32; 8];
        for i in 0..8 {
            limbs[i] = r[i] as u32;
        }
        let mut result = Field { limbs };

        // Final reduction if >= p: subtract p once (or twice in rare cases).
        let mut sub_count = 0;
        while result >= P {
            result = result.sub(&P);
            sub_count += 1;
            if sub_count > 2 {
                break;
            }
        }
        result
    }

    pub fn inv(&self) -> Field {
        // Fermat's little theorem: a^(-1) ≡ a^(p-2) (mod p) for prime p.
        // secp256k1 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        // so p - 2 is the field prime minus 2. We square-and-multiply.
        let p_minus_2: [u8; 32] = [
            0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2D,
        ];
        self.pow(&p_minus_2)
    }

    pub fn pow(&self, exp: &[u8]) -> Field {
        let mut result = Field::ONE;
        let mut base = *self;
        for &byte in exp.iter().rev() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
            }
        }
        result
    }

    pub fn is_on_curve_g(&self) -> bool {
        let y2 = self.mul(self);
        let x3 = self.mul(&self).mul(self);
        let seven = Field {
            limbs: [7, 0, 0, 0, 0, 0, 0, 0],
        };
        let rhs = x3.add(&seven);
        y2 == rhs
    }

    pub fn negate(&self) -> Field {
        if self.is_zero() {
            *self
        } else {
            P.sub(self)
        }
    }

    pub fn set_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl PartialOrd for Field {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Field {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..8).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Field,
    pub y: Field,
    pub infinity: bool,
}

impl Point {
    pub const INFINITY: Point = Point {
        x: Field::ZERO,
        y: Field::ZERO,
        infinity: true,
    };

    pub fn new(x: Field, y: Field) -> Option<Self> {
        if x.is_zero() && y.is_zero() {
            return Some(Self::INFINITY);
        }
        if y.mul(&y) == x.mul(&x).mul(&x).add(&Field { limbs: [7, 0, 0, 0, 0, 0, 0, 0] }) {
            Some(Self { x, y, infinity: false })
        } else {
            None
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    pub fn double(&self) -> Point {
        if self.is_infinity() {
            return *self;
        }

        if self.y.is_zero() {
            return Self::INFINITY;
        }

        let two = Field { limbs: [2, 0, 0, 0, 0, 0, 0, 0] };

        let x2 = self.x.mul(&self.x);
        let three_x2 = x2.add(&x2).add(&x2);

        let lambda_num = three_x2;
        let lambda_den = self.y.mul(&two);

        let lambda_den_inv = lambda_den.inv();
        let lambda = lambda_num.mul(&lambda_den_inv);

        let x3 = lambda.mul(&lambda).sub(&self.x).sub(&self.x);

        let dx = self.x.sub(&x3);
        let dy = self.y.sub(&lambda.mul(&dx));

        Self { x: x3, y: dy, infinity: false }
    }

    pub fn add(&self, other: &Point) -> Point {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        if self.x == other.x && self.y == other.y {
            return self.double();
        }
        if self.x == other.x {
            return Self::INFINITY;
        }

        let dx = other.y.sub(&self.y);
        let dy = other.x.sub(&self.x);
        let lambda = dx.mul(&dy.inv());

        let x3 = lambda.mul(&lambda).sub(&self.x).sub(&other.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);

        Self { x: x3, y: y3, infinity: false }
    }

    pub fn mul(&self, scalar: &Scalar) -> Point {
        let mut result = Self::INFINITY;
        let mut base = *self;

        for &byte in scalar.bytes.iter().rev() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.double();
            }
        }
        result
    }

    pub fn to_bytes_compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        if self.infinity {
            out[0] = 0x00;
            return out;
        }
        let prefix = if self.y.limbs[0] & 1 == 0 { 0x02 } else { 0x03 };
        out[0] = prefix;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out
    }
}

#[derive(Clone, Debug)]
pub struct Scalar {
    pub bytes: [u8; 32],
}

impl Scalar {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }

    pub fn from_u64(val: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&val.to_le_bytes());
        Self { bytes }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

pub struct Secp256k1;

impl Secp256k1 {
    pub fn g() -> Point {
        let x = Field::from_bytes(&[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
            0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xC2, 0x3A, 0x75,
            0x5E, 0x2C, 0xC7, 0x6D, 0x0A, 0x1E, 0x2E, 0xD5,
        ]);
        let y = Field::from_bytes(&[
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
            0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
            0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
            0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
        ]);
        Point { x, y, infinity: false }
    }

    pub fn pubkey_from_privkey(privkey: &[u8; 32]) -> [u8; 33] {
        let scalar = Scalar::from_bytes(privkey);
        let point = Self::g().mul(&scalar);
        point.to_bytes_compressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_add_zero() {
        let a = Field::from_bytes(&[1; 32]);
        let b = Field::ZERO;
        assert_eq!(a.add(&b), a);
    }

    #[test]
    fn test_field_mul_one() {
        let a = Field::from_bytes(&[42; 32]);
        let b = Field::ONE;
        assert_eq!(a.mul(&b), a);
    }

    #[test]
    fn test_gx_squared() {
        // Gx² mod p should be 0x8550e7d238fcf3086ba9adcf0fb52a9de3652194d06cb5bb38d50229b854fc49
        let g = Secp256k1::g();
        let gx2 = g.x.mul(&g.x);
        let gx2_bytes = gx2.to_bytes();
        let expected = [
            0x85, 0x50, 0xe7, 0xd2, 0x38, 0xfc, 0xf3, 0x08,
            0x6b, 0xa9, 0xad, 0xcf, 0x0f, 0xb5, 0x2a, 0x9d,
            0xe3, 0x65, 0x21, 0x94, 0xd0, 0x6c, 0xb5, 0xbb,
            0x38, 0xd5, 0x02, 0x29, 0xb8, 0x54, 0xfc, 0x49,
        ];
        assert_eq!(gx2_bytes, expected);
    }

    #[test]
    fn test_gx_times_one() {
        let g = Secp256k1::g();
        let one = Field::ONE;
        let result = g.x.mul(&one);
        assert_eq!(result.limbs, g.x.limbs, "Gx * 1 should equal Gx");
    }

    #[test]
    fn test_gx_times_two() {
        // 2 * Gx raw (2*Gx < p, so no reduction needed).
        // Expected: 0xF37CCCFDF3B97758AB40C52B9D0E160E0537F9B65B9C51B2B3E502B62DF02F30
        let g = Secp256k1::g();
        let two = Field { limbs: [2, 0, 0, 0, 0, 0, 0, 0] };
        let result = g.x.mul(&two);
        let result_bytes = result.to_bytes();
        let expected = [
            0xF3, 0x7C, 0xCC, 0xFD, 0xF3, 0xB9, 0x77, 0x58,
            0xAB, 0x40, 0xC5, 0x2A, 0x9D, 0x0E, 0x16, 0x0E,
            0x05, 0x37, 0xF9, 0xB6, 0x5B, 0x9C, 0x51, 0xB2,
            0xB3, 0xE5, 0x02, 0xB6, 0x2D, 0xF0, 0x2F, 0x30,
        ];
        assert_eq!(result_bytes, expected, "Gx * 2");
    }

    #[test]
    fn test_point_at_infinity() {
        let g = Secp256k1::g();
        let mut scalar_bytes = [0u8; 32];
        let result = g.mul(&Scalar::from_bytes(&scalar_bytes));
        assert!(result.is_infinity());
    }

    #[test]
    fn test_g_on_curve() {
        let g = Secp256k1::g();
        let y2 = g.y.mul(&g.y);
        let x3 = g.x.mul(&g.x).mul(&g.x);
        let seven = Field { limbs: [7, 0, 0, 0, 0, 0, 0, 0] };
        assert_eq!(y2, x3.add(&seven));
    }

    #[test]
    fn test_pubkey_generation() {
        let privkey = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let pubkey = Secp256k1::pubkey_from_privkey(&privkey);
        assert_eq!(pubkey[0], 0x02);
    }
}
