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

        // Verify: y² = x³ + ax + b (mod p)
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

        // Prefix: 0x02 if y is even, 0x03 if y is odd
        let y_bytes = self.y.to_bytes_be().1;
        let prefix = if y_bytes.last().map(|b| b & 1).unwrap_or(0) == 0 {
            0x02
        } else {
            0x03
        };

        result.push(prefix);

        // Add x coordinate (padded to coord_size)
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

        // Add x coordinate (padded to coord_size)
        let x_bytes = self.x.to_bytes_be().1;
        let x_padding = coord_size.saturating_sub(x_bytes.len());
        result.extend(std::iter::repeat_n(0, x_padding));
        result.extend_from_slice(&x_bytes);

        // Add y coordinate (padded to coord_size)
        let y_bytes = self.y.to_bytes_be().1;
        let y_padding = coord_size.saturating_sub(y_bytes.len());
        result.extend(std::iter::repeat_n(0, y_padding));
        result.extend_from_slice(&y_bytes);

        result
    }

    /// Parses a point from SEC1 format (compressed or uncompressed)
    pub fn from_bytes(data: &[u8], _curve: &EllipticCurve) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("Empty point data");
        }

        match data[0] {
            0x04 => {
                // Uncompressed format
                if data.len() < 3 {
                    return Err("Invalid uncompressed point length");
                }

                let coord_size = (data.len() - 1) / 2;
                let x = BigInt::from_bytes_be(Sign::Plus, &data[1..1 + coord_size]);
                let y = BigInt::from_bytes_be(Sign::Plus, &data[1 + coord_size..]);

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
pub struct EcdhProvider {
    curve: EllipticCurve,
    coord_size: usize,
}

impl EcdhProvider {
    /// Creates a new ECDH provider with the specified curve
    pub fn new(curve_type: EllipticCurveType) -> Self {
        match curve_type {
            EllipticCurveType::Secp192K1 => Self {
                curve: EllipticCurve::secp192k1(),
                coord_size: 24, // 192 bits = 24 bytes
            },
            EllipticCurveType::Prime256V1 => Self {
                curve: EllipticCurve::prime256v1(),
                coord_size: 32, // 256 bits = 32 bytes
            },
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

    /// Performs ECDH key exchange
    /// - secret: Your private key bytes
    /// - peer_public: Peer's public key (point or bytes)
    /// - hash_with_md5: If true, returns MD5 hash of the shared x-coordinate
    pub fn key_exchange(
        &self,
        secret: &[u8],
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
        let secret_int = BigInt::from_bytes_be(Sign::Plus, secret);
        let shared_point = self.curve.scalar_multiply(&peer_point, &secret_int);

        // Use x-coordinate as shared secret
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
    /// Secp192K1 (192-bit Koblitz curve)
    Secp192K1,
    /// Prime256V1 (NIST P-256)
    Prime256V1,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_point_validation() {
        let curve = EllipticCurve::prime256v1();

        // Generator should be on the curve
        assert!(curve.verify_point(&curve.g));

        // Random point should not be on the curve
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
        let provider = EcdhProvider::prime256v1();

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
}
