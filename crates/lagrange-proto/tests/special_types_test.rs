use bytes::BytesMut;
use lagrange_proto::*;
use lagrange_proto::{Fixed32, Fixed64, SFixed32, SFixed64, SInt32, SInt64};

// SInt32 Tests

#[test]
fn test_sint32_all_boundary_values() {
    let values = [
        i32::MIN,
        i32::MIN + 1,
        -2147483647,
        -1073741824,
        -1000000,
        -10000,
        -1000,
        -100,
        -10,
        -2,
        -1,
        0,
        1,
        2,
        10,
        100,
        1000,
        10000,
        1000000,
        1073741823,
        2147483646,
        i32::MAX - 1,
        i32::MAX,
    ];

    for &val in &values {
        let sint = SInt32(val);
        let mut buf = BytesMut::new();
        sint.encode(&mut buf).unwrap();

        let decoded = SInt32::decode(&buf).unwrap();
        assert_eq!(sint, decoded, "Failed for SInt32 value: {}", val);
    }
}

#[test]
fn test_sint32_from_into() {
    let val = SInt32::from(-12345);
    assert_eq!(val.0, -12345);

    let i: i32 = val.into();
    assert_eq!(i, -12345);
}

#[test]
fn test_sint32_default() {
    let default = SInt32::default();
    assert_eq!(default.0, 0);
}

#[test]
fn test_sint32_ordering() {
    let a = SInt32(-100);
    let b = SInt32(-50);
    let c = SInt32(0);
    let d = SInt32(50);

    assert!(a < b);
    assert!(b < c);
    assert!(c < d);
}

#[test]
fn test_sint32_hash() {
    use std::collections::HashMap;

    let mut map = HashMap::new();
    map.insert(SInt32(-1), "negative one");
    map.insert(SInt32(0), "zero");
    map.insert(SInt32(1), "positive one");

    assert_eq!(map.get(&SInt32(-1)), Some(&"negative one"));
    assert_eq!(map.get(&SInt32(0)), Some(&"zero"));
    assert_eq!(map.get(&SInt32(1)), Some(&"positive one"));
}

#[test]
fn test_sint32_encoded_size() {
    // Test that encoded_size matches actual encoding
    let test_values = [
        (SInt32(0), 1),
        (SInt32(-1), 1),
        (SInt32(1), 1),
        (SInt32(-64), 1),      // zigzag(-64) = 127, fits in 1 byte
        (SInt32(63), 1),       // zigzag(63) = 126, fits in 1 byte
        (SInt32(-65), 2),      // zigzag(-65) = 129, needs 2 bytes
        (SInt32(64), 2),       // zigzag(64) = 128, needs 2 bytes
        (SInt32(i32::MIN), 5), // zigzag(i32::MIN) = u32::MAX, needs 5 bytes
        (SInt32(i32::MAX), 5), // zigzag(i32::MAX) = u32::MAX - 1, needs 5 bytes
    ];

    for (sint, expected_size) in test_values {
        let mut buf = BytesMut::new();
        sint.encode(&mut buf).unwrap();
        assert_eq!(sint.encoded_size(), buf.len());
        assert_eq!(
            buf.len(),
            expected_size,
            "SInt32({}) should encode to {} bytes",
            sint.0,
            expected_size
        );
    }
}

// SInt64 Tests

#[test]
fn test_sint64_all_boundary_values() {
    let values = [
        i64::MIN,
        i64::MIN + 1,
        -9223372036854775807,
        -4611686018427387904,
        -1000000000000,
        -1000000,
        -1000,
        -1,
        0,
        1,
        1000,
        1000000,
        1000000000000,
        4611686018427387903,
        9223372036854775806,
        i64::MAX - 1,
        i64::MAX,
    ];

    for &val in &values {
        let sint = SInt64(val);
        let mut buf = BytesMut::new();
        sint.encode(&mut buf).unwrap();

        let decoded = SInt64::decode(&buf).unwrap();
        assert_eq!(sint, decoded, "Failed for SInt64 value: {}", val);
    }
}

#[test]
fn test_sint64_from_into() {
    let val = SInt64::from(-123456789);
    assert_eq!(val.0, -123456789);

    let i: i64 = val.into();
    assert_eq!(i, -123456789);
}

#[test]
fn test_sint64_default() {
    let default = SInt64::default();
    assert_eq!(default.0, 0);
}

// Fixed32 Tests

#[test]
fn test_fixed32_all_boundary_values() {
    let values = [
        0u32,
        1,
        255,
        256,
        65535,
        65536,
        16777215,
        16777216,
        4294967294,
        u32::MAX,
    ];

    for &val in &values {
        let fixed = Fixed32(val);
        let mut buf = BytesMut::new();
        fixed.encode(&mut buf).unwrap();

        assert_eq!(buf.len(), 4, "Fixed32 should always encode to 4 bytes");

        let decoded = Fixed32::decode(&buf).unwrap();
        assert_eq!(fixed, decoded, "Failed for Fixed32 value: {}", val);
    }
}

#[test]
fn test_fixed32_from_into() {
    let val = Fixed32::from(0xDEADBEEF);
    assert_eq!(val.0, 0xDEADBEEF);

    let u: u32 = val.into();
    assert_eq!(u, 0xDEADBEEF);
}

#[test]
fn test_fixed32_default() {
    let default = Fixed32::default();
    assert_eq!(default.0, 0);
}

#[test]
fn test_fixed32_endianness() {
    let val = Fixed32(0x12345678);
    let mut buf = BytesMut::new();
    val.encode(&mut buf).unwrap();

    // Little-endian encoding
    assert_eq!(buf[0], 0x78);
    assert_eq!(buf[1], 0x56);
    assert_eq!(buf[2], 0x34);
    assert_eq!(buf[3], 0x12);
}

#[test]
fn test_fixed32_encoded_size() {
    let values = [Fixed32(0), Fixed32(1), Fixed32(u32::MAX)];

    for val in values {
        assert_eq!(val.encoded_size(), 4);

        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 4);
    }
}

// Fixed64 Tests

#[test]
fn test_fixed64_all_boundary_values() {
    let values = [
        0u64,
        1,
        255,
        65535,
        16777215,
        4294967295,
        1099511627775,
        281474976710655,
        72057594037927935,
        18446744073709551614,
        u64::MAX,
    ];

    for &val in &values {
        let fixed = Fixed64(val);
        let mut buf = BytesMut::new();
        fixed.encode(&mut buf).unwrap();

        assert_eq!(buf.len(), 8, "Fixed64 should always encode to 8 bytes");

        let decoded = Fixed64::decode(&buf).unwrap();
        assert_eq!(fixed, decoded, "Failed for Fixed64 value: {}", val);
    }
}

#[test]
fn test_fixed64_from_into() {
    let val = Fixed64::from(0xDEADBEEFCAFEBABE);
    assert_eq!(val.0, 0xDEADBEEFCAFEBABE);

    let u: u64 = val.into();
    assert_eq!(u, 0xDEADBEEFCAFEBABE);
}

#[test]
fn test_fixed64_default() {
    let default = Fixed64::default();
    assert_eq!(default.0, 0);
}

#[test]
fn test_fixed64_endianness() {
    let val = Fixed64(0x123456789ABCDEF0);
    let mut buf = BytesMut::new();
    val.encode(&mut buf).unwrap();

    // Little-endian encoding
    assert_eq!(buf[0], 0xF0);
    assert_eq!(buf[1], 0xDE);
    assert_eq!(buf[2], 0xBC);
    assert_eq!(buf[3], 0x9A);
    assert_eq!(buf[4], 0x78);
    assert_eq!(buf[5], 0x56);
    assert_eq!(buf[6], 0x34);
    assert_eq!(buf[7], 0x12);
}

#[test]
fn test_fixed64_encoded_size() {
    let values = [Fixed64(0), Fixed64(1), Fixed64(u64::MAX)];

    for val in values {
        assert_eq!(val.encoded_size(), 8);

        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }
}

// SFixed32 Tests

#[test]
fn test_sfixed32_all_boundary_values() {
    let values = [
        i32::MIN,
        i32::MIN + 1,
        -1000000,
        -1000,
        -1,
        0,
        1,
        1000,
        1000000,
        i32::MAX - 1,
        i32::MAX,
    ];

    for &val in &values {
        let sfixed = SFixed32(val);
        let mut buf = BytesMut::new();
        sfixed.encode(&mut buf).unwrap();

        assert_eq!(buf.len(), 4, "SFixed32 should always encode to 4 bytes");

        let decoded = SFixed32::decode(&buf).unwrap();
        assert_eq!(sfixed, decoded, "Failed for SFixed32 value: {}", val);
    }
}

#[test]
fn test_sfixed32_from_into() {
    let val = SFixed32::from(-12345);
    assert_eq!(val.0, -12345);

    let i: i32 = val.into();
    assert_eq!(i, -12345);
}

#[test]
fn test_sfixed32_default() {
    let default = SFixed32::default();
    assert_eq!(default.0, 0);
}

#[test]
fn test_sfixed32_encoded_size() {
    let values = [SFixed32(i32::MIN), SFixed32(0), SFixed32(i32::MAX)];

    for val in values {
        assert_eq!(val.encoded_size(), 4);

        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 4);
    }
}

// SFixed64 Tests

#[test]
fn test_sfixed64_all_boundary_values() {
    let values = [
        i64::MIN,
        i64::MIN + 1,
        -1000000000000,
        -1000000,
        -1,
        0,
        1,
        1000000,
        1000000000000,
        i64::MAX - 1,
        i64::MAX,
    ];

    for &val in &values {
        let sfixed = SFixed64(val);
        let mut buf = BytesMut::new();
        sfixed.encode(&mut buf).unwrap();

        assert_eq!(buf.len(), 8, "SFixed64 should always encode to 8 bytes");

        let decoded = SFixed64::decode(&buf).unwrap();
        assert_eq!(sfixed, decoded, "Failed for SFixed64 value: {}", val);
    }
}

#[test]
fn test_sfixed64_from_into() {
    let val = SFixed64::from(-123456789);
    assert_eq!(val.0, -123456789);

    let i: i64 = val.into();
    assert_eq!(i, -123456789);
}

#[test]
fn test_sfixed64_default() {
    let default = SFixed64::default();
    assert_eq!(default.0, 0);
}

#[test]
fn test_sfixed64_encoded_size() {
    let values = [SFixed64(i64::MIN), SFixed64(0), SFixed64(i64::MAX)];

    for val in values {
        assert_eq!(val.encoded_size(), 8);

        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }
}

// Comparison Tests

#[test]
fn test_sint_vs_regular_int_size_efficiency() {
    // Small negative numbers should be more efficient with SInt32
    let small_negative = -100i32;

    let mut sint_buf = BytesMut::new();
    SInt32(small_negative).encode(&mut sint_buf).unwrap();

    // Regular i32 uses zigzag too in our implementation
    let mut regular_buf = BytesMut::new();
    small_negative.encode(&mut regular_buf).unwrap();

    // Both should use zigzag encoding and be the same
    assert_eq!(sint_buf.len(), regular_buf.len());
}

#[test]
fn test_fixed_vs_varint_size_comparison() {
    // For small values, varint is more efficient
    let small_val = 100u32;

    let mut varint_buf = BytesMut::new();
    small_val.encode(&mut varint_buf).unwrap();

    let mut fixed_buf = BytesMut::new();
    Fixed32(small_val).encode(&mut fixed_buf).unwrap();

    assert!(
        varint_buf.len() < fixed_buf.len(),
        "Varint should be smaller for small values"
    );
    assert_eq!(fixed_buf.len(), 4); // Fixed32 always 4 bytes
}

#[test]
fn test_fixed_vs_varint_large_values() {
    // For large values, fixed might be better
    let large_val = u32::MAX;

    let mut varint_buf = BytesMut::new();
    large_val.encode(&mut varint_buf).unwrap();

    let mut fixed_buf = BytesMut::new();
    Fixed32(large_val).encode(&mut fixed_buf).unwrap();

    // Both should be close in size for large values
    assert_eq!(varint_buf.len(), 5); // Max varint for u32
    assert_eq!(fixed_buf.len(), 4); // Always 4
}

#[test]
fn test_all_types_zero_value() {
    let mut buf = BytesMut::new();

    SInt32(0).encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 1);

    buf.clear();
    SInt64(0).encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 1);

    buf.clear();
    Fixed32(0).encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 4);

    buf.clear();
    Fixed64(0).encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 8);

    buf.clear();
    SFixed32(0).encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 4);

    buf.clear();
    SFixed64(0).encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 8);
}

#[test]
fn test_all_types_max_value() {
    let mut buf = BytesMut::new();

    SInt32(i32::MAX).encode(&mut buf).unwrap();
    let decoded = SInt32::decode(&buf).unwrap();
    assert_eq!(decoded.0, i32::MAX);

    buf.clear();
    SInt64(i64::MAX).encode(&mut buf).unwrap();
    let decoded = SInt64::decode(&buf).unwrap();
    assert_eq!(decoded.0, i64::MAX);

    buf.clear();
    Fixed32(u32::MAX).encode(&mut buf).unwrap();
    let decoded = Fixed32::decode(&buf).unwrap();
    assert_eq!(decoded.0, u32::MAX);

    buf.clear();
    Fixed64(u64::MAX).encode(&mut buf).unwrap();
    let decoded = Fixed64::decode(&buf).unwrap();
    assert_eq!(decoded.0, u64::MAX);

    buf.clear();
    SFixed32(i32::MAX).encode(&mut buf).unwrap();
    let decoded = SFixed32::decode(&buf).unwrap();
    assert_eq!(decoded.0, i32::MAX);

    buf.clear();
    SFixed64(i64::MAX).encode(&mut buf).unwrap();
    let decoded = SFixed64::decode(&buf).unwrap();
    assert_eq!(decoded.0, i64::MAX);
}

#[test]
fn test_all_types_min_value() {
    let mut buf = BytesMut::new();

    SInt32(i32::MIN).encode(&mut buf).unwrap();
    let decoded = SInt32::decode(&buf).unwrap();
    assert_eq!(decoded.0, i32::MIN);

    buf.clear();
    SInt64(i64::MIN).encode(&mut buf).unwrap();
    let decoded = SInt64::decode(&buf).unwrap();
    assert_eq!(decoded.0, i64::MIN);

    buf.clear();
    SFixed32(i32::MIN).encode(&mut buf).unwrap();
    let decoded = SFixed32::decode(&buf).unwrap();
    assert_eq!(decoded.0, i32::MIN);

    buf.clear();
    SFixed64(i64::MIN).encode(&mut buf).unwrap();
    let decoded = SFixed64::decode(&buf).unwrap();
    assert_eq!(decoded.0, i64::MIN);
}

#[test]
fn test_type_debug_display() {
    // Verify Debug trait works
    let sint32 = SInt32(-123);
    let debug_str = format!("{:?}", sint32);
    assert!(debug_str.contains("-123"));

    let fixed64 = Fixed64(0xDEADBEEF);
    let debug_str = format!("{:?}", fixed64);
    assert!(
        debug_str.contains("DEADBEEF")
            || debug_str.contains("deadbeef")
            || debug_str.contains("3735928559")
    );
}

#[test]
fn test_type_clone() {
    let sint = SInt32(-42);
    let cloned = sint;
    assert_eq!(sint, cloned);

    let fixed = Fixed64(12345);
    let cloned = fixed;
    assert_eq!(fixed, cloned);
}

#[test]
fn test_type_copy() {
    let sint = SInt32(-42);
    let copied = sint;
    assert_eq!(sint, copied);

    let fixed = Fixed32(12345);
    let copied = fixed;
    assert_eq!(fixed, copied);
}
