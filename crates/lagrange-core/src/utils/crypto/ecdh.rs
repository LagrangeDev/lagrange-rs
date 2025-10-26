use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{
    Concat, Encoding, Integer, Limb, NonZero, Odd, PrecomputeInverter, RandomMod, Split, Uint,
    U192, U256,
};

/// Elliptic curve parameters
#[derive(Debug, Clone)]
pub struct EllipticCurve<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    /// Prime modulus
    pub p: NonZero<Uint<LIMBS>>,
    /// Curve parameter a
    pub a: Uint<LIMBS>,
    /// Curve parameter b
    pub b: Uint<LIMBS>,
    /// Generator point
    pub g: EllipticPoint<LIMBS>,
    /// Order of the generator
    pub n: NonZero<Uint<LIMBS>>,
}

/// The Prime256V1 curve (NIST P-256)
pub const PRIME256V1: EllipticCurve<4, 8, 6> = EllipticCurve {
    p: NonZero::<Uint<_>>::new_unwrap(U256::from_be_hex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    )),
    a: U256::from_be_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
    b: U256::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    g: EllipticPoint {
        x: U256::from_be_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        y: U256::from_be_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    },
    n: NonZero::<Uint<_>>::new_unwrap(U256::from_be_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    )),
};

/// The Secp192K1 curve (192-bit Koblitz curve)
pub const SECP192K1: EllipticCurve<3, 6, 5> = EllipticCurve {
    p: NonZero::<Uint<_>>::new_unwrap(U192::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffeffffee37",
    )),
    a: U192::from_be_hex("000000000000000000000000000000000000000000000000"),
    b: U192::from_be_hex("000000000000000000000000000000000000000000000003"),
    g: EllipticPoint {
        x: U192::from_be_hex("db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d"),
        y: U192::from_be_hex("9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),
    },
    n: NonZero::<Uint<_>>::new_unwrap(U192::from_be_hex(
        "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    )),
};

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    /// Adds two points on the elliptic curve
    fn point_add(
        &self,
        p1: &EllipticPoint<LIMBS>,
        p2: &EllipticPoint<LIMBS>,
    ) -> EllipticPoint<LIMBS> {
        // Identity element checks
        if p1.is_identity() {
            return p2.clone();
        }
        if p2.is_identity() {
            return p1.clone();
        }

        let x1 = &p1.x;
        let y1 = &p1.y;
        let x2 = &p2.x;
        let y2 = &p2.y;

        // Calculate slope (m)
        let m = if x1 == x2 {
            if y1 == y2 {
                // Point doubling: m = (3x₁² + a) / (2y₁)
                let three_x1_sq = x1.mul_mod(x1, &self.p).mul_mod(&Uint::from(3u8), &self.p);
                let numerator = three_x1_sq.add_mod(&self.a, &self.p);
                let denominator = y1.mul_mod(&Uint::from(2u8), &self.p);
                let denominator_inv = denominator.inv_mod(&self.p).unwrap();
                numerator.mul_mod(&denominator_inv, &self.p)
            } else {
                // Points are inverses, result is identity
                return EllipticPoint::identity();
            }
        } else {
            // Point addition: m = (y₁ - y₂) / (x₁ - x₂)
            let numerator = y1.sub_mod(y2, &self.p);
            let denominator = x1.sub_mod(x2, &self.p);
            let denominator_inv = denominator.inv_mod(&self.p).unwrap();
            numerator.mul_mod(&denominator_inv, &self.p)
        };

        // Calculate result point
        // xᵣ = m² - x₁ - x₂
        let xr = m
            .mul_mod(&m, &self.p)
            .sub_mod(x1, &self.p)
            .sub_mod(x2, &self.p);

        // yᵣ = m(x₁ - xᵣ) - y₁
        let yr = m
            .mul_mod(&x1.sub_mod(&xr, &self.p), &self.p)
            .sub_mod(y1, &self.p);

        EllipticPoint { x: xr, y: yr }
    }

    /// Scalar multiplication using double-and-add algorithm
    fn scalar_multiply(
        &self,
        point: &EllipticPoint<LIMBS>,
        scalar: &Uint<LIMBS>,
    ) -> EllipticPoint<LIMBS> {
        let mut result = EllipticPoint::identity();
        let mut temp = point.clone();

        for i in 0..LIMBS * Limb::BITS as usize - 1 {
            if scalar.bit(i as u32).into() {
                result = self.point_add(&result, &temp);
            }
            temp = self.point_add(&temp, &temp);
        }
        result
    }

    /// Verifies that a point lies on the curve
    pub fn verify_point(&self, point: &EllipticPoint<LIMBS>) -> bool {
        if point.is_identity() {
            return true;
        }

        // Verify: y² = x³ + ax + b (mod p)
        let left = point.y.mul_mod(&point.y, &self.p);
        let x3 = point
            .x
            .mul_mod(&point.x, &self.p)
            .mul_mod(&point.x, &self.p);
        let ax = self.a.mul_mod(&point.x, &self.p);
        let right = x3.add_mod(&ax, &self.p).add_mod(&self.b, &self.p);
        left == right
    }
}

/// Elliptic curve point
#[derive(Debug, Clone, PartialEq)]
pub struct EllipticPoint<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub x: Uint<LIMBS>,
    pub y: Uint<LIMBS>,
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize> EllipticPoint<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    const SIZE: usize = LIMBS * Limb::BYTES;
    /// Creates a new elliptic curve point
    pub fn new(x: Uint<LIMBS>, y: Uint<LIMBS>) -> Self {
        Self { x, y }
    }

    /// Creates the identity (point at infinity)
    pub fn identity() -> Self {
        Self {
            x: Uint::ZERO,
            y: Uint::ZERO,
        }
    }

    /// Checks if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.x == Uint::ZERO && self.y == Uint::ZERO
    }

    /// Converts the point to compressed format (SEC1)
    /// Format: 0x02/0x03 (even/odd y) + x coordinate
    pub fn to_compressed(&self, coord_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + coord_size);

        // Prefix: 0x02 if y is even, 0x03 if y is odd
        let prefix = if self.y.is_even().into() { 0x02 } else { 0x03 };

        result.push(prefix);

        // Add x coordinate (padded to coord_size)
        let x_bytes = Encoding::to_be_bytes(&self.x);
        let padding = coord_size.saturating_sub(x_bytes.as_ref().len());
        result.extend(std::iter::repeat(0).take(padding));
        result.extend_from_slice(x_bytes.as_ref());

        result
    }

    /// Converts the point to uncompressed format (SEC1)
    /// Format: 0x04 + x coordinate + y coordinate
    pub fn to_uncompressed(&self, coord_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 2 * coord_size);

        result.push(0x04);

        // Add x coordinate (padded to coord_size)
        let x_bytes = Encoding::to_be_bytes(&self.x);
        let x_padding = coord_size.saturating_sub(x_bytes.as_ref().len());
        result.extend(std::iter::repeat(0).take(x_padding));
        result.extend_from_slice(x_bytes.as_ref());

        // Add y coordinate (padded to coord_size)
        let y_bytes = Encoding::to_be_bytes(&self.y);
        let y_padding = coord_size.saturating_sub(y_bytes.as_ref().len());
        result.extend(std::iter::repeat(0).take(y_padding));
        result.extend_from_slice(y_bytes.as_ref());

        result
    }

    /// Parses a point from SEC1 format (compressed or uncompressed)
    pub fn from_bytes(
        data: &[u8],
        _curve: &EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>,
    ) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("Empty point data");
        }

        match data[0] {
            0x04 => {
                // Uncompressed format
                if data.len() != Self::SIZE * 2 + 1 {
                    return Err("Invalid uncompressed point length");
                }

                let x = Uint::<LIMBS>::from_be_slice(&data[1..1 + Self::SIZE]);
                let y = Uint::<LIMBS>::from_be_slice(&data[1 + Self::SIZE..]);

                Ok(Self::new(x, y))
            }
            0x02 | 0x03 => {
                // Compressed format - we'd need to decompress which requires
                // solving y² = x³ + ax + b for y
                // For now, return error
                Err("Compressed point format not yet supported for parsing")
            }
            _ => Err("Invalid point format prefix"),
        }
    }
}

/// ECDH provider with manual elliptic curve implementation
pub struct EcdhProvider<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    curve: EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>,
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const UNSAT_LIMBS: usize>
    EcdhProvider<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>> + Encoding,
    Odd<Uint<LIMBS>>: PrecomputeInverter<Inverter = SafeGcdInverter<LIMBS, UNSAT_LIMBS>>,
{
    const SIZE: usize = LIMBS * Limb::BYTES;
    /// Creates a new ECDH provider with the specified curve
    pub fn new(curve: EllipticCurve<LIMBS, WIDE_LIMBS, UNSAT_LIMBS>) -> Self {
        Self { curve }
    }

    /// Generates a random secret key
    pub fn generate_secret(&self) -> Uint<LIMBS> {
        Uint::<LIMBS>::random_mod(&mut OsRng, &self.curve.n)
    }

    /// Computes the public key from a secret
    pub fn get_public_key(&self, secret: &Uint<LIMBS>) -> EllipticPoint<LIMBS> {
        self.curve.scalar_multiply(&self.curve.g, secret)
    }

    /// Generates a new key pair and returns the public key in specified format
    pub fn generate_public_key(&self, compressed: bool) -> Vec<u8> {
        let secret = self.generate_secret();
        let public = self.get_public_key(&secret);

        if compressed {
            public.to_compressed(Self::SIZE)
        } else {
            public.to_uncompressed(Self::SIZE)
        }
    }

    /// Performs ECDH key exchange
    /// - secret: Your private key bytes
    /// - peer_public: Peer's public key (point or bytes)
    /// - hash_with_md5: If true, returns MD5 hash of the shared x-coordinate
    pub fn key_exchange(
        &self,
        secret: &Uint<LIMBS>,
        peer_public: &[u8],
        hash_with_md5: bool,
    ) -> Result<Vec<u8>, &'static str> {
        // Parse peer's public key
        let peer_point = EllipticPoint::from_bytes(peer_public, &self.curve)?;

        // Verify peer's public key is on the curve
        if !self.curve.verify_point(&peer_point) {
            return Err("Peer public key is not on the curve");
        }

        // Perform scalar multiplication
        let shared_point = self.curve.scalar_multiply(&peer_point, secret);

        // Use x-coordinate as shared secret
        let shared_secret = Encoding::to_be_bytes(&shared_point.x);

        if hash_with_md5 {
            Ok(md5::compute(shared_secret).0.to_vec())
        } else {
            Ok(shared_secret.as_ref().to_vec())
        }
    }

    /// Packs a public key point into bytes
    pub fn pack_public_key(&self, point: &EllipticPoint<LIMBS>, compressed: bool) -> Vec<u8> {
        if compressed {
            point.to_compressed(Self::SIZE)
        } else {
            point.to_uncompressed(Self::SIZE)
        }
    }

    /// Unpacks a public key from bytes into a point
    pub fn unpack_public_key(&self, data: &[u8]) -> Result<EllipticPoint<LIMBS>, &'static str> {
        EllipticPoint::from_bytes(data, &self.curve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_point_validation() {
        let curve = PRIME256V1;

        // Generator should be on the curve
        assert!(curve.verify_point(&curve.g));

        // Random point should not be on the curve
        let random_point = EllipticPoint::new(Uint::from(12345u32), Uint::from(67890u32));
        assert!(!curve.verify_point(&random_point));
    }

    #[test]
    fn test_point_addition() {
        let curve = PRIME256V1;

        // G + G = 2G
        let doubled = curve.point_add(&curve.g, &curve.g);
        assert!(curve.verify_point(&doubled));

        // G + identity = G
        let identity = EllipticPoint::identity();
        let result = curve.point_add(&curve.g, &identity);
        assert_eq!(result, curve.g);
    }

    #[test]
    fn test_scalar_multiplication() {
        let curve = PRIME256V1;

        // 1 * G = G
        let result = curve.scalar_multiply(&curve.g, &Uint::from(1u32));
        assert_eq!(result, curve.g);

        // 2 * G should be on the curve
        let result = curve.scalar_multiply(&curve.g, &Uint::from(2u32));
        assert!(curve.verify_point(&result));
    }

    #[test]
    fn test_ecdh_key_exchange() {
        let provider = EcdhProvider::new(PRIME256V1);

        // Generate Alice's keypair
        let alice_secret = provider.generate_secret();
        let alice_public = provider.get_public_key(&alice_secret);

        // Generate Bob's keypair
        let bob_secret = provider.generate_secret();
        let bob_public = provider.get_public_key(&bob_secret);

        // Pack public keys
        let alice_public_bytes = alice_public.to_uncompressed(32);
        let bob_public_bytes = bob_public.to_uncompressed(32);

        // Perform key exchange
        let alice_shared = provider
            .key_exchange(&alice_secret, &bob_public_bytes, false)
            .unwrap();

        let bob_shared = provider
            .key_exchange(&bob_secret, &alice_public_bytes, false)
            .unwrap();

        // Both should compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_point_serialization() {
        let curve = PRIME256V1;

        // Test uncompressed format
        let uncompressed = curve.g.to_uncompressed(32);
        assert_eq!(uncompressed.len(), 65); // 1 + 32 + 32
        assert_eq!(uncompressed[0], 0x04);

        // Test compressed format
        let compressed = curve.g.to_compressed(32);
        assert_eq!(compressed.len(), 33); // 1 + 32
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn test_point_deserialization() {
        let curve = PRIME256V1;
        let provider = EcdhProvider::new(PRIME256V1);

        // Serialize and deserialize
        let original = curve.g.clone();
        let serialized = original.to_uncompressed(32);
        let deserialized = provider.unpack_public_key(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }
}
