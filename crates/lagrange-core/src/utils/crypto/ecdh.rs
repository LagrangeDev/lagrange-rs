use num_bigint::{BigInt, Sign};
use rand::Rng;

/// Elliptic curve parameters
#[derive(Debug, Clone)]
pub struct EllipticCurve {
    /// Prime modulus
    pub p: BigInt,
    /// Curve parameter a
    pub a: BigInt,
    /// Curve parameter b
    pub b: BigInt,
    /// Generator point
    pub g: EllipticPoint,
    /// Order of the generator
    pub n: BigInt,
}

impl EllipticCurve {
    /// Creates the Secp192K1 curve (192-bit Koblitz curve)
    pub fn secp192k1() -> Self {
        let p =
            BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16).unwrap();

        let a = BigInt::from(0);
        let b = BigInt::from(3);

        let gx =
            BigInt::parse_bytes(b"DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", 16).unwrap();

        let gy =
            BigInt::parse_bytes(b"9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", 16).unwrap();

        let n =
            BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16).unwrap();

        Self {
            p,
            a,
            b,
            g: EllipticPoint { x: gx, y: gy },
            n,
        }
    }

    /// Creates the Prime256V1 curve (NIST P-256)
    pub fn prime256v1() -> Self {
        let p = BigInt::parse_bytes(
            b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();

        let a = BigInt::parse_bytes(
            b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            16,
        )
        .unwrap();

        let b = BigInt::parse_bytes(
            b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            16,
        )
        .unwrap();

        let gx = BigInt::parse_bytes(
            b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            16,
        )
        .unwrap();

        let gy = BigInt::parse_bytes(
            b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            16,
        )
        .unwrap();

        let n = BigInt::parse_bytes(
            b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        .unwrap();

        Self {
            p,
            a,
            b,
            g: EllipticPoint { x: gx, y: gy },
            n,
        }
    }

    /// Modular reduction ensuring positive result
    fn mod_positive(&self, value: &BigInt) -> BigInt {
        let mut result = value % &self.p;
        if result.sign() == Sign::Minus {
            result += &self.p;
        }
        result
    }

    /// Modular inverse using Fermat's Little Theorem: a^(p-2) mod p
    fn mod_inverse(&self, a: &BigInt) -> BigInt {
        if a.sign() == Sign::Minus {
            let pos = self.mod_positive(a);
            return &self.p - self.mod_inverse(&pos);
        }

        // Use Fermat's little theorem: a^(p-2) mod p
        a.modpow(&(&self.p - 2), &self.p)
    }

    /// Computes modular square root using Tonelli-Shanks algorithm
    /// Returns None if n is not a quadratic residue
    fn mod_sqrt(&self, n: &BigInt) -> Option<BigInt> {
        let n = self.mod_positive(n);

        // Special case: if n is 0
        if n == BigInt::from(0) {
            return Some(BigInt::from(0));
        }

        // Check if n is a quadratic residue using Euler's criterion: n^((p-1)/2) ≡ 1 (mod p)
        let exp = (&self.p - 1) / 2;
        let legendre = n.modpow(&exp, &self.p);
        if legendre != BigInt::from(1) {
            return None; // Not a quadratic residue
        }

        // For primes p ≡ 3 (mod 4), we can use the simple formula: y = n^((p+1)/4) mod p
        if &self.p % 4 == BigInt::from(3) {
            let exp = (&self.p + 1) / 4;
            return Some(n.modpow(&exp, &self.p));
        }

        // General Tonelli-Shanks algorithm for p ≡ 1 (mod 4)
        // Express p - 1 = 2^s * q where q is odd
        let mut q = &self.p - 1;
        let mut s = 0;
        while &q % 2 == BigInt::from(0) {
            q /= 2;
            s += 1;
        }

        // Find a quadratic non-residue z
        let mut z = BigInt::from(2);
        while z.modpow(&exp, &self.p) != &self.p - 1 {
            z += 1;
        }

        let mut m = s;
        let mut c = z.modpow(&q, &self.p);
        let mut t = n.modpow(&q, &self.p);
        let mut r = n.modpow(&((&q + 1) / 2), &self.p);

        loop {
            if t == BigInt::from(0) {
                return Some(BigInt::from(0));
            }
            if t == BigInt::from(1) {
                return Some(r);
            }

            // Find the least i such that t^(2^i) = 1
            let mut i = 1;
            let mut temp = self.mod_positive(&(&t * &t));
            while temp != BigInt::from(1) && i < m {
                temp = self.mod_positive(&(&temp * &temp));
                i += 1;
            }

            let two = BigInt::from(2);
            let b = c.modpow(&two.pow((m - i - 1) as u32), &self.p);
            m = i;
            c = self.mod_positive(&(&b * &b));
            t = self.mod_positive(&(&t * &c));
            r = self.mod_positive(&(&r * &b));
        }
    }

    /// Adds two points on the elliptic curve
    fn point_add(&self, p1: &EllipticPoint, p2: &EllipticPoint) -> EllipticPoint {
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
                let numerator = self.mod_positive(&(3 * x1 * x1 + &self.a));
                let denominator = self.mod_positive(&(2 * y1));
                let denominator_inv = self.mod_inverse(&denominator);
                self.mod_positive(&(numerator * denominator_inv))
            } else {
                // Points are inverses, result is identity
                return EllipticPoint::identity();
            }
        } else {
            // Point addition: m = (y₁ - y₂) / (x₁ - x₂)
            let numerator = self.mod_positive(&(y1 - y2));
            let denominator = self.mod_positive(&(x1 - x2));
            let denominator_inv = self.mod_inverse(&denominator);
            self.mod_positive(&(numerator * denominator_inv))
        };

        // Calculate result point
        // xᵣ = m² - x₁ - x₂
        let xr = self.mod_positive(&(&m * &m - x1 - x2));

        // yᵣ = m(x₁ - xᵣ) - y₁
        let yr = self.mod_positive(&(&m * (x1 - &xr) - y1));

        EllipticPoint { x: xr, y: yr }
    }

    /// Scalar multiplication using double-and-add algorithm
    fn scalar_multiply(&self, point: &EllipticPoint, scalar: &BigInt) -> EllipticPoint {
        let mut result = EllipticPoint::identity();
        let mut temp = point.clone();
        let mut k = scalar.clone();

        while k > BigInt::from(0) {
            if &k % 2 == BigInt::from(1) {
                result = self.point_add(&result, &temp);
            }
            temp = self.point_add(&temp, &temp);
            k >>= 1;
        }

        result
    }

    /// Verifies that a point lies on the curve
    pub fn verify_point(&self, point: &EllipticPoint) -> bool {
        if point.is_identity() {
            return true;
        }

        let left = self.mod_positive(&(&point.y * &point.y));
        let right =
            self.mod_positive(&(&point.x * &point.x * &point.x + &self.a * &point.x + &self.b));
        left == right
    }
}

/// Elliptic curve point
#[derive(Debug, Clone, PartialEq)]
pub struct EllipticPoint {
    pub x: BigInt,
    pub y: BigInt,
}

impl EllipticPoint {
    /// Creates a new elliptic curve point
    pub fn new(x: BigInt, y: BigInt) -> Self {
        Self { x, y }
    }

    /// Creates the identity (point at infinity)
    pub fn identity() -> Self {
        Self {
            x: BigInt::from(0),
            y: BigInt::from(0),
        }
    }

    /// Checks if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.x == BigInt::from(0) && self.y == BigInt::from(0)
    }

    /// Converts the point to compressed format (SEC1)
    /// Format: 0x02/0x03 (even/odd y) + x coordinate
    pub fn to_compressed(&self, coord_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + coord_size);

        let y_bytes = self.y.to_bytes_be().1;
        let prefix = if y_bytes.last().map(|b| b & 1).unwrap_or(0) == 0 {
            0x02
        } else {
            0x03
        };

        result.push(prefix);

        let x_bytes = self.x.to_bytes_be().1;
        let padding = coord_size.saturating_sub(x_bytes.len());
        result.extend(std::iter::repeat_n(0, padding));
        result.extend_from_slice(&x_bytes);

        result
    }

    /// Converts the point to uncompressed format (SEC1)
    /// Format: 0x04 + x coordinate + y coordinate
    pub fn to_uncompressed(&self, coord_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 2 * coord_size);

        result.push(0x04);

        let x_bytes = self.x.to_bytes_be().1;
        let x_padding = coord_size.saturating_sub(x_bytes.len());
        result.extend(std::iter::repeat_n(0, x_padding));
        result.extend_from_slice(&x_bytes);

        let y_bytes = self.y.to_bytes_be().1;
        let y_padding = coord_size.saturating_sub(y_bytes.len());
        result.extend(std::iter::repeat_n(0, y_padding));
        result.extend_from_slice(&y_bytes);

        result
    }

    /// Parses a point from SEC1 format (compressed or uncompressed)
    pub fn from_bytes(data: &[u8], curve: &EllipticCurve) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("Empty point data");
        }

        match data[0] {
            0x04 => {
                if data.len() < 3 {
                    return Err("Invalid uncompressed point length");
                }

                let coord_size = (data.len() - 1) / 2;
                let x = BigInt::from_bytes_be(Sign::Plus, &data[1..1 + coord_size]);
                let y = BigInt::from_bytes_be(Sign::Plus, &data[1 + coord_size..]);

                Ok(Self::new(x, y))
            }
            0x02 | 0x03 => {
                if data.len() < 2 {
                    return Err("Invalid compressed point length");
                }

                let is_odd = data[0] == 0x03;
                let x = BigInt::from_bytes_be(Sign::Plus, &data[1..]);

                let x_cubed = curve.mod_positive(&(&x * &x * &x));
                let ax = curve.mod_positive(&(&curve.a * &x));
                let y_squared = curve.mod_positive(&(x_cubed + ax + &curve.b));

                let y_candidate = curve
                    .mod_sqrt(&y_squared)
                    .ok_or("Point x-coordinate does not correspond to a valid curve point")?;

                let y_bytes = y_candidate.to_bytes_be().1;
                let candidate_is_odd = y_bytes.last().map(|b| b & 1 == 1).unwrap_or(false);

                let y = if candidate_is_odd == is_odd {
                    y_candidate
                } else {
                    curve.mod_positive(&(&curve.p - &y_candidate))
                };

                Ok(Self::new(x, y))
            }
            _ => Err("Invalid point format prefix"),
        }
    }
}

/// ECDH provider with manual elliptic curve implementation
pub struct EcdhProvider {
    curve: EllipticCurve,
    coord_size: usize,
    secret: BigInt,
    public: EllipticPoint,
}

impl EcdhProvider {
    /// Creates a new ECDH provider with the specified curve and generates a random key pair
    pub fn new(curve_type: EllipticCurveType) -> Self {
        let (curve, coord_size) = match curve_type {
            EllipticCurveType::Secp192K1 => (EllipticCurve::secp192k1(), 24), // 192 bits = 24 bytes
            EllipticCurveType::Prime256V1 => (EllipticCurve::prime256v1(), 32), // 256 bits = 32 bytes
        };

        let mut rng = rand::thread_rng();
        let mut secret_bytes = vec![0u8; coord_size];
        rng.fill(&mut secret_bytes[..]);
        let secret = BigInt::from_bytes_be(Sign::Plus, &secret_bytes);

        let public = curve.scalar_multiply(&curve.g, &secret);

        Self {
            curve,
            coord_size,
            secret,
            public,
        }
    }

    /// Creates a provider for Prime256V1 (P-256) curve
    pub fn prime256v1() -> Self {
        Self::new(EllipticCurveType::Prime256V1)
    }

    /// Creates a provider for Secp192K1 curve
    pub fn secp192k1() -> Self {
        Self::new(EllipticCurveType::Secp192K1)
    }

    /// Creates a new ECDH provider with a custom secret key
    pub fn with_secret(curve_type: EllipticCurveType, secret_bytes: &[u8]) -> Self {
        let (curve, coord_size) = match curve_type {
            EllipticCurveType::Secp192K1 => (EllipticCurve::secp192k1(), 24),
            EllipticCurveType::Prime256V1 => (EllipticCurve::prime256v1(), 32),
        };

        // Parse secret from bytes
        let secret = BigInt::from_bytes_be(Sign::Plus, secret_bytes);

        // Compute public key
        let public = curve.scalar_multiply(&curve.g, &secret);

        Self {
            curve,
            coord_size,
            secret,
            public,
        }
    }

    /// Returns a reference to the stored public key point
    pub fn public_key(&self) -> &EllipticPoint {
        &self.public
    }

    /// Returns the public key in byte format (compressed or uncompressed)
    pub fn public_key_bytes(&self, compressed: bool) -> Vec<u8> {
        if compressed {
            self.public.to_compressed(self.coord_size)
        } else {
            self.public.to_uncompressed(self.coord_size)
        }
    }

    /// Returns the secret key as bytes
    pub fn secret_bytes(&self) -> Vec<u8> {
        let (_, bytes) = self.secret.to_bytes_be();
        let mut result = vec![0u8; self.coord_size];
        let offset = self.coord_size.saturating_sub(bytes.len());
        result[offset..].copy_from_slice(&bytes);
        result
    }

    /// Generates a random secret key
    pub fn generate_secret(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut secret = vec![0u8; self.coord_size];
        rng.fill(&mut secret[..]);
        secret
    }

    /// Computes the public key from a secret
    pub fn get_public_key(&self, secret: &[u8]) -> EllipticPoint {
        let secret_int = BigInt::from_bytes_be(Sign::Plus, secret);
        self.curve.scalar_multiply(&self.curve.g, &secret_int)
    }

    /// Generates a new key pair and returns the public key in specified format
    pub fn generate_public_key(&self, compressed: bool) -> Vec<u8> {
        let secret = self.generate_secret();
        let public = self.get_public_key(&secret);

        if compressed {
            public.to_compressed(self.coord_size)
        } else {
            public.to_uncompressed(self.coord_size)
        }
    }

    /// Performs ECDH key exchange using the stored secret key
    /// - peer_public: Peer's public key (point or bytes)
    /// - hash_with_md5: If true, returns MD5 hash of the shared x-coordinate
    pub fn key_exchange(
        &self,
        peer_public: &[u8],
        hash_with_md5: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let peer_point = EllipticPoint::from_bytes(peer_public, &self.curve)?;

        if !self.curve.verify_point(&peer_point) {
            return Err("Peer public key is not on the curve");
        }

        let shared_point = self.curve.scalar_multiply(&peer_point, &self.secret);
        let shared_secret = shared_point.x.to_bytes_be().1;

        if hash_with_md5 {
            Ok(md5::compute(&shared_secret).0.to_vec())
        } else {
            Ok(shared_secret)
        }
    }

    /// Packs a public key point into bytes
    pub fn pack_public_key(&self, point: &EllipticPoint, compressed: bool) -> Vec<u8> {
        if compressed {
            point.to_compressed(self.coord_size)
        } else {
            point.to_uncompressed(self.coord_size)
        }
    }

    /// Unpacks a public key from bytes into a point
    pub fn unpack_public_key(&self, data: &[u8]) -> Result<EllipticPoint, &'static str> {
        EllipticPoint::from_bytes(data, &self.curve)
    }
}

/// Elliptic curve type selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurveType {
    Secp192K1,
    Prime256V1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_point_validation() {
        let curve = EllipticCurve::prime256v1();
        assert!(curve.verify_point(&curve.g));

        let random_point = EllipticPoint::new(BigInt::from(12345), BigInt::from(67890));
        assert!(!curve.verify_point(&random_point));
    }

    #[test]
    fn test_point_addition() {
        let curve = EllipticCurve::prime256v1();

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
        let curve = EllipticCurve::prime256v1();

        // 1 * G = G
        let result = curve.scalar_multiply(&curve.g, &BigInt::from(1));
        assert_eq!(result, curve.g);

        // 2 * G should be on the curve
        let result = curve.scalar_multiply(&curve.g, &BigInt::from(2));
        assert!(curve.verify_point(&result));
    }

    #[test]
    fn test_ecdh_key_exchange() {
        // Create Alice's provider with her own keypair
        let alice = EcdhProvider::prime256v1();

        // Create Bob's provider with his own keypair
        let bob = EcdhProvider::prime256v1();

        // Get public keys in byte format
        let alice_public_bytes = alice.public_key_bytes(false);
        let bob_public_bytes = bob.public_key_bytes(false);

        // Perform key exchange using stored secrets
        let alice_shared = alice.key_exchange(&bob_public_bytes, false).unwrap();

        let bob_shared = bob.key_exchange(&alice_public_bytes, false).unwrap();

        // Both should compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_point_serialization() {
        let curve = EllipticCurve::prime256v1();

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
        let curve = EllipticCurve::prime256v1();
        let provider = EcdhProvider::prime256v1();

        // Serialize and deserialize
        let original = curve.g.clone();
        let serialized = original.to_uncompressed(32);
        let deserialized = provider.unpack_public_key(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_compressed_point_deserialization() {
        let curve = EllipticCurve::prime256v1();
        let provider = EcdhProvider::prime256v1();

        // Test with generator point
        let original = curve.g.clone();
        let compressed = original.to_compressed(32);
        let deserialized = provider.unpack_public_key(&compressed).unwrap();

        // Verify the deserialized point matches the original
        assert_eq!(original.x, deserialized.x);
        assert_eq!(original.y, deserialized.y);
        assert!(curve.verify_point(&deserialized));
    }

    #[test]
    fn test_compressed_point_round_trip() {
        let curve = EllipticCurve::prime256v1();

        // Test with multiple points
        for scalar in [1, 2, 3, 7, 100] {
            let point = curve.scalar_multiply(&curve.g, &BigInt::from(scalar));

            // Compress and decompress
            let compressed = point.to_compressed(32);
            let decompressed = EllipticPoint::from_bytes(&compressed, &curve).unwrap();

            // Verify the round trip
            assert_eq!(point.x, decompressed.x);
            assert_eq!(point.y, decompressed.y);
            assert!(curve.verify_point(&decompressed));
        }
    }

    #[test]
    fn test_compressed_vs_uncompressed() {
        let curve = EllipticCurve::prime256v1();

        // Create a random point
        let point = curve.scalar_multiply(&curve.g, &BigInt::from(42));

        // Serialize in both formats
        let compressed = point.to_compressed(32);
        let uncompressed = point.to_uncompressed(32);

        // Deserialize both
        let from_compressed = EllipticPoint::from_bytes(&compressed, &curve).unwrap();
        let from_uncompressed = EllipticPoint::from_bytes(&uncompressed, &curve).unwrap();

        // Both should yield the same point
        assert_eq!(from_compressed.x, from_uncompressed.x);
        assert_eq!(from_compressed.y, from_uncompressed.y);
        assert_eq!(from_compressed, point);
        assert_eq!(from_uncompressed, point);
    }

    #[test]
    fn test_ecdh_with_compressed_keys() {
        // Create Alice's and Bob's providers
        let alice = EcdhProvider::prime256v1();
        let bob = EcdhProvider::prime256v1();

        // Exchange compressed public keys
        let alice_compressed = alice.public_key_bytes(true);
        let bob_compressed = bob.public_key_bytes(true);

        // Perform key exchange with compressed keys
        let alice_shared = alice.key_exchange(&bob_compressed, false).unwrap();
        let bob_shared = bob.key_exchange(&alice_compressed, false).unwrap();

        // Both should compute the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_secp192k1_compressed_points() {
        let curve = EllipticCurve::secp192k1();

        // Test with secp192k1 curve
        for scalar in [1, 5, 13] {
            let point = curve.scalar_multiply(&curve.g, &BigInt::from(scalar));

            // Compress and decompress with 24-byte coordinates
            let compressed = point.to_compressed(24);
            let decompressed = EllipticPoint::from_bytes(&compressed, &curve).unwrap();

            // Verify
            assert_eq!(point.x, decompressed.x);
            assert_eq!(point.y, decompressed.y);
            assert!(curve.verify_point(&decompressed));
        }
    }
}
