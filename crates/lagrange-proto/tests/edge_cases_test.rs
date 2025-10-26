
use lagrange_proto::*;
use bytes::BytesMut;

// Note: u8 and u16 don't have ProtoEncode/ProtoDecode implementations
// These types are tested through the varint module directly in varint_comprehensive_test.rs

#[test]
fn test_varint_boundary_u32() {
    let values = [
        0u32,          // Minimum
        127,           // Max 1-byte
        128,           // Min 2-byte
        16383,         // Max 2-byte
        16384,         // Min 3-byte
        2097151,       // Max 3-byte
        2097152,       // Min 4-byte
        268435455,     // Max 4-byte
        268435456,     // Min 5-byte
        u32::MAX - 1,  // Near maximum
        u32::MAX,      // Maximum
    ];

    for &val in &values {
        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        let decoded = u32::decode(&buf).unwrap();
        assert_eq!(decoded, val, "Failed round-trip for u32 value: {}", val);
    }
}

#[test]
fn test_varint_boundary_u64() {
    let values = [
        0u64,
        127,
        128,
        16383,
        16384,
        2097151,
        2097152,
        268435455,
        268435456,
        34359738367,      // Max 5-byte
        34359738368,      // Min 6-byte
        4398046511103,    // Max 6-byte
        4398046511104,    // Min 7-byte
        562949953421311,  // Max 7-byte
        562949953421312,  // Min 8-byte
        72057594037927935,    // Max 8-byte
        72057594037927936,    // Min 9-byte
        9223372036854775807,  // Max 9-byte (i64::MAX as u64)
        9223372036854775808,  // Min 10-byte
        u64::MAX - 1,
        u64::MAX,
    ];

    for &val in &values {
        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        let decoded = u64::decode(&buf).unwrap();
        assert_eq!(decoded, val, "Failed round-trip for u64 value: {}", val);
    }
}

#[test]
fn test_zigzag_i32_boundaries() {
    let values = [
        i32::MIN,
        i32::MIN + 1,
        -2147483647,
        -1000000,
        -1000,
        -100,
        -2,
        -1,
        0,
        1,
        2,
        100,
        1000,
        1000000,
        2147483646,
        i32::MAX - 1,
        i32::MAX,
    ];

    for &val in &values {
        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        let decoded = i32::decode(&buf).unwrap();
        assert_eq!(decoded, val, "Failed round-trip for i32 value: {}", val);
    }
}

#[test]
fn test_zigzag_i64_boundaries() {
    let values = [
        i64::MIN,
        i64::MIN + 1,
        -9223372036854775807,
        -1000000000000,
        -1000000,
        -1,
        0,
        1,
        1000000,
        1000000000000,
        9223372036854775806,
        i64::MAX - 1,
        i64::MAX,
    ];

    for &val in &values {
        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        let decoded = i64::decode(&buf).unwrap();
        assert_eq!(decoded, val, "Failed round-trip for i64 value: {}", val);
    }
}

#[test]
fn test_zigzag_alternating_signs() {
    // Test alternating positive and negative values
    for i in -100..100 {
        let mut buf = BytesMut::new();
        i.encode(&mut buf).unwrap();
        let decoded = i32::decode(&buf).unwrap();
        assert_eq!(decoded, i);
    }
}

#[test]
fn test_float_special_values() {
    let values = [
        0.0f32,
        -0.0f32,
        1.0f32,
        -1.0f32,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        f32::MIN,
        f32::MAX,
        f32::MIN_POSITIVE,
        f32::EPSILON,
    ];

    for &val in &values {
        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        let decoded = f32::decode(&buf).unwrap();

        if val.is_nan() {
            assert!(decoded.is_nan(), "NaN should decode to NaN");
        } else {
            assert_eq!(decoded, val, "Failed round-trip for f32 value: {}", val);
        }
    }
}

#[test]
fn test_double_special_values() {
    let values = [
        0.0f64,
        -0.0f64,
        1.0f64,
        -1.0f64,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::EPSILON,
    ];

    for &val in &values {
        let mut buf = BytesMut::new();
        val.encode(&mut buf).unwrap();
        let decoded = f64::decode(&buf).unwrap();

        if val.is_nan() {
            assert!(decoded.is_nan(), "NaN should decode to NaN");
        } else {
            assert_eq!(decoded, val, "Failed round-trip for f64 value: {}", val);
        }
    }
}

#[test]
fn test_empty_string() {
    let s = String::new();
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1); // Just the length prefix (0)

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_empty_bytes() {
    let bytes = Vec::<u8>::new();
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1); // Just the length prefix (0)

    let decoded = Vec::<u8>::decode(&buf).unwrap();
    assert_eq!(decoded, bytes);
}

#[test]
fn test_large_string() {
    // Test string with 10k characters
    let s = "a".repeat(10000);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
    assert_eq!(decoded.len(), 10000);
}

#[test]
fn test_large_bytes() {
    // Test bytes with 10k elements
    let bytes = vec![0xAB; 10000];
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    let decoded = Vec::<u8>::decode(&buf).unwrap();
    assert_eq!(decoded, bytes);
    assert_eq!(decoded.len(), 10000);
}

#[test]
fn test_unicode_string_edge_cases() {
    let test_cases = vec![
        "Hello, World!",                    // ASCII
        "你好世界",                         // Chinese
        "こんにちは",                       // Japanese
        "안녕하세요",                       // Korean
        "Привет",                          // Russian
        "مرحبا",                           // Arabic (RTL)
        "שלום",                            // Hebrew (RTL)
        "😀😃😄😁",                        // Emoji
        "👨‍👩‍👧‍👦",                  // Family emoji with ZWJ
        "A̐",                              // Combining diacritical marks
        "\u{0000}",                        // Null character
        "\u{FFFF}",                        // Max BMP character
        "🔥💯✨",                           // Modern emoji
    ];

    for s in test_cases {
        let mut buf = BytesMut::new();
        s.encode(&mut buf).unwrap();
        let decoded = String::decode(&buf).unwrap();
        assert_eq!(decoded, s, "Failed for string: {}", s);
    }
}

#[test]
fn test_string_length_boundaries() {
    // Test strings at varint length boundaries
    let lengths = [0, 1, 127, 128, 16383, 16384];

    for len in lengths {
        let s = "x".repeat(len);
        let mut buf = BytesMut::new();
        s.encode(&mut buf).unwrap();
        let decoded = String::decode(&buf).unwrap();
        assert_eq!(decoded.len(), len);
    }
}

#[test]
fn test_wire_type_conversion_all_valid() {
    use lagrange_proto::wire::WireType;

    assert_eq!(WireType::from_u8(0).unwrap(), WireType::Varint);
    assert_eq!(WireType::from_u8(1).unwrap(), WireType::Fixed64);
    assert_eq!(WireType::from_u8(2).unwrap(), WireType::LengthDelimited);
    assert_eq!(WireType::from_u8(3).unwrap(), WireType::StartGroup);
    assert_eq!(WireType::from_u8(4).unwrap(), WireType::EndGroup);
    assert_eq!(WireType::from_u8(5).unwrap(), WireType::Fixed32);
}

#[test]
fn test_wire_type_invalid_values() {
    use lagrange_proto::wire::WireType;

    for invalid in 6u8..=255 {
        assert!(WireType::from_u8(invalid).is_err(),
                "Wire type {} should be invalid", invalid);
    }
}

#[test]
fn test_key_tag_zero_invalid() {
    use lagrange_proto::wire::Key;

    // Tag 0 is invalid
    let result = Key::decode(0);
    assert!(result.is_err(), "Tag 0 should be invalid");
}

#[test]
fn test_key_large_tag_numbers() {
    use lagrange_proto::wire::{Key, WireType};

    let large_tags = [
        1,
        15,          // Max 1-byte key
        16,          // Min 2-byte key
        2047,        // Max 2-byte key
        2048,        // Min 3-byte key
        268435455,   // Max valid field number
    ];

    for tag in large_tags {
        let key = Key::new(tag, WireType::Varint);
        let encoded = key.encode();
        let decoded = Key::decode(encoded).unwrap();
        assert_eq!(decoded.tag, tag);
        assert_eq!(decoded.wire_type, WireType::Varint);
    }
}

#[test]
fn test_bool_true_false() {
    let mut buf = BytesMut::new();

    true.encode(&mut buf).unwrap();
    false.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 2);
    assert_eq!(buf[0], 1);
    assert_eq!(buf[1], 0);
}

#[test]
fn test_option_none_encodes_nothing() {
    let none: Option<u32> = None;
    let mut buf = BytesMut::new();
    none.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 0, "None should encode to empty buffer");
    assert_eq!(none.encoded_size(), 0);
}

#[test]
fn test_option_some_encodes_value() {
    let some: Option<u32> = Some(42);
    let mut buf = BytesMut::new();
    some.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1);
    assert_eq!(buf[0], 42);
    assert_eq!(some.encoded_size(), 1);
}

#[test]
fn test_empty_vec_encodes_nothing() {
    let empty: Vec<u32> = vec![];
    let mut buf = BytesMut::new();
    empty.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 0, "Empty Vec should encode to empty buffer");
    assert_eq!(empty.encoded_size(), 0);
}

#[test]
fn test_single_element_vec() {
    let vec = vec![123u32];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // Vec<T> doesn't include length prefix in the encode implementation,
    // it just encodes elements
    assert_eq!(buf.len(), 1);
}

#[test]
fn test_varint_encoded_size_accuracy() {
    use lagrange_proto::helpers::get_varint_length_u32;

    let test_cases = [
        (0u32, 1),
        (1, 1),
        (127, 1),
        (128, 2),
        (255, 2),
        (16383, 2),
        (16384, 3),
        (2097151, 3),
        (2097152, 4),
        (268435455, 4),
        (268435456, 5),
        (u32::MAX, 5),
    ];

    for (value, expected_len) in test_cases {
        assert_eq!(get_varint_length_u32(value), expected_len,
                  "Incorrect length for value {}", value);
        assert_eq!(value.encoded_size(), expected_len);
    }
}

#[test]
fn test_varint_encoded_size_u64_accuracy() {
    use lagrange_proto::helpers::get_varint_length_u64;

    let test_cases = [
        (0u64, 1),
        (127, 1),
        (128, 2),
        (16383, 2),
        (16384, 3),
        (34359738367, 5),
        (34359738368, 6),
        (4398046511103, 6),
        (4398046511104, 7),
        (562949953421311, 7),
        (562949953421312, 8),
        (72057594037927935, 8),
        (72057594037927936, 9),
        (9223372036854775807, 9),
        (9223372036854775808, 10),
        (u64::MAX, 10),
    ];

    for (value, expected_len) in test_cases {
        assert_eq!(get_varint_length_u64(value), expected_len,
                  "Incorrect length for value {}", value);
        assert_eq!(value.encoded_size(), expected_len);
    }
}

#[test]
fn test_string_encoded_size_accuracy() {
    let s1 = "".to_string();
    let s2 = "a".to_string();
    let s3 = "x".repeat(127);
    let s4 = "x".repeat(128);
    let s5 = "x".repeat(16383);
    let s6 = "x".repeat(16384);

    let test_strings = [&s1, &s2, &s3, &s4, &s5, &s6];

    for s in test_strings {
        let mut buf = BytesMut::new();
        s.encode(&mut buf).unwrap();
        assert_eq!(s.encoded_size(), buf.len(),
                  "Size mismatch for string of length {}", s.len());
    }
}

#[test]
fn test_bytes_slice_encoding() {
    let data: &[u8] = &[1, 2, 3, 4, 5];
    let mut buf = BytesMut::new();
    data.encode(&mut buf).unwrap();

    // Should be: length (1 byte for value 5) + data (5 bytes)
    assert_eq!(buf.len(), 6);
    assert_eq!(buf[0], 5); // Length
    assert_eq!(&buf[1..], data);
}

#[test]
fn test_bytes_type_roundtrip() {
    use bytes::Bytes;

    let original = Bytes::from(vec![1, 2, 3, 4, 5]);
    let mut buf = BytesMut::new();
    original.encode(&mut buf).unwrap();

    let decoded = Bytes::decode(&buf).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_bytesmut_type_roundtrip() {
    use bytes::BytesMut;

    let mut original = BytesMut::new();
    original.extend_from_slice(&[1, 2, 3, 4, 5]);

    let mut buf = BytesMut::new();
    original.encode(&mut buf).unwrap();

    // Note: We can't decode directly to BytesMut, but we can test encoding
    assert_eq!(buf[0], 5); // Length
    assert_eq!(&buf[1..], &[1, 2, 3, 4, 5]);
}

#[test]
fn test_consecutive_encoding() {
    // Test encoding multiple values consecutively
    let mut buf = BytesMut::new();

    42u32.encode(&mut buf).unwrap();
    "hello".encode(&mut buf).unwrap();
    true.encode(&mut buf).unwrap();

    // Verify buffer contains all values
    assert!(buf.len() > 0);

    // We can decode in order
    let val1 = u32::decode(&buf[0..1]).unwrap();
    assert_eq!(val1, 42);
}

#[test]
fn test_negative_zero_float() {
    let pos_zero = 0.0f32;
    let neg_zero = -0.0f32;

    let mut buf1 = BytesMut::new();
    let mut buf2 = BytesMut::new();

    pos_zero.encode(&mut buf1).unwrap();
    neg_zero.encode(&mut buf2).unwrap();

    // -0.0 and 0.0 have different bit patterns
    assert_ne!(buf1.as_ref(), buf2.as_ref());

    let decoded1 = f32::decode(&buf1).unwrap();
    let decoded2 = f32::decode(&buf2).unwrap();

    assert_eq!(decoded1.to_bits(), pos_zero.to_bits());
    assert_eq!(decoded2.to_bits(), neg_zero.to_bits());
}

#[test]
fn test_negative_zero_double() {
    let pos_zero = 0.0f64;
    let neg_zero = -0.0f64;

    let mut buf1 = BytesMut::new();
    let mut buf2 = BytesMut::new();

    pos_zero.encode(&mut buf1).unwrap();
    neg_zero.encode(&mut buf2).unwrap();

    assert_ne!(buf1.as_ref(), buf2.as_ref());

    let decoded1 = f64::decode(&buf1).unwrap();
    let decoded2 = f64::decode(&buf2).unwrap();

    assert_eq!(decoded1.to_bits(), pos_zero.to_bits());
    assert_eq!(decoded2.to_bits(), neg_zero.to_bits());
}
