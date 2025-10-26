use lagrange_proto::varint::*;

#[test]
fn test_varint_u8_all_boundaries() {
    // Test every boundary for u8 varint encoding
    let test_cases = vec![
        (0u8, 1), // Min value, 1 byte
        (1, 1),
        (126, 1),
        (127, 1), // Max 1-byte value
        (128, 2), // Min 2-byte value
        (129, 2),
        (254, 2),
        (255, 2), // Max value, 2 bytes
    ];

    for (value, expected_len) in test_cases {
        let (buf, len) = encode(value);
        assert_eq!(len, expected_len, "Incorrect length for u8 value {}", value);

        let (decoded, dec_len) = decode::<u8>(&buf[..len]).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(dec_len, len);
    }
}

#[test]
fn test_varint_u16_all_boundaries() {
    let test_cases = vec![
        (0u16, 1),
        (127, 1),
        (128, 2),
        (255, 2),
        (256, 2),
        (16383, 2), // Max 2-byte
        (16384, 3), // Min 3-byte
        (32767, 3),
        (32768, 3),
        (65534, 3),
        (65535, 3), // Max value
    ];

    for (value, expected_len) in test_cases {
        let (buf, len) = encode(value);
        assert_eq!(
            len, expected_len,
            "Incorrect length for u16 value {}",
            value
        );

        let (decoded, dec_len) = decode::<u16>(&buf[..len]).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(dec_len, len);
    }
}

#[test]
fn test_varint_u32_exhaustive_boundaries() {
    let test_cases = vec![
        // 1-byte values
        (0u32, 1),
        (1, 1),
        (63, 1),
        (127, 1),
        // 2-byte values
        (128, 2),
        (129, 2),
        (255, 2),
        (256, 2),
        (8191, 2),
        (16383, 2),
        // 3-byte values
        (16384, 3),
        (16385, 3),
        (32768, 3),
        (1048575, 3),
        (2097151, 3),
        // 4-byte values
        (2097152, 4),
        (2097153, 4),
        (134217727, 4),
        (268435455, 4),
        // 5-byte values
        (268435456, 5),
        (268435457, 5),
        (1073741824, 5),
        (2147483647, 5), // i32::MAX
        (2147483648, 5),
        (4294967294, 5),
        (4294967295, 5), // u32::MAX
    ];

    for (value, expected_len) in test_cases {
        let (buf, len) = encode(value);
        assert_eq!(
            len, expected_len,
            "Incorrect length for u32 value {}",
            value
        );

        let (decoded, dec_len) = decode::<u32>(&buf[..len]).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(dec_len, len);
    }
}

#[test]
fn test_varint_u64_exhaustive_boundaries() {
    let test_cases = vec![
        (0u64, 1),
        (127, 1),
        (128, 2),
        (16383, 2),
        (16384, 3),
        (2097151, 3),
        (2097152, 4),
        (268435455, 4),
        (268435456, 5),
        (34359738367, 5), // Max 5-byte
        (34359738368, 6), // Min 6-byte
        (4398046511103, 6),
        (4398046511104, 7),
        (562949953421311, 7),
        (562949953421312, 8),
        (72057594037927935, 8),
        (72057594037927936, 9),
        (9223372036854775807, 9), // i64::MAX
        (9223372036854775808, 10),
        (18446744073709551614, 10),
        (18446744073709551615, 10), // u64::MAX
    ];

    for (value, expected_len) in test_cases {
        let (buf, len) = encode(value);
        assert_eq!(
            len, expected_len,
            "Incorrect length for u64 value {}",
            value
        );

        let (decoded, dec_len) = decode::<u64>(&buf[..len]).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(dec_len, len);
    }
}

#[test]
fn test_zigzag_i32_exhaustive() {
    let test_cases = vec![
        (i32::MIN, 10),
        (i32::MIN + 1, 10),
        (-1073741824, 5),
        (-1048576, 4),
        (-16384, 3),
        (-128, 2),
        (-64, 2),
        (-2, 1),
        (-1, 1),
        (0, 1),
        (1, 1),
        (63, 2),
        (127, 2),
        (16383, 3),
        (1048575, 4),
        (1073741823, 5),
        (i32::MAX - 1, 5),
        (i32::MAX, 5),
    ];

    for (value, _expected_len) in test_cases {
        let (buf, len) = encode_zigzag::<u32>(value);
        let (decoded, dec_len) = decode_zigzag::<u32>(&buf[..len]).unwrap();
        assert_eq!(decoded, value, "ZigZag failed for i32 value {}", value);
        assert_eq!(dec_len, len);
    }
}

#[test]
fn test_zigzag_i64_exhaustive() {
    let test_cases = vec![
        i64::MIN,
        i64::MIN + 1,
        -4611686018427387904,
        -1073741824,
        -16384,
        -128,
        -1,
        0,
        1,
        127,
        16383,
        1073741823,
        4611686018427387903,
        i64::MAX - 1,
        i64::MAX,
    ];

    for value in test_cases {
        let (buf, len) = encode_zigzag::<u64>(value);
        let (decoded, dec_len) = decode_zigzag::<u64>(&buf[..len]).unwrap();
        assert_eq!(decoded, value, "ZigZag failed for i64 value {}", value);
        assert_eq!(dec_len, len);
    }
}

#[test]
fn test_zigzag_encode_patterns() {
    // Verify zigzag encoding maps negative numbers to odd, positive to even
    assert_eq!(zigzag_encode_i32(0), 0);
    assert_eq!(zigzag_encode_i32(-1), 1);
    assert_eq!(zigzag_encode_i32(1), 2);
    assert_eq!(zigzag_encode_i32(-2), 3);
    assert_eq!(zigzag_encode_i32(2), 4);
    assert_eq!(zigzag_encode_i32(i32::MAX), 4294967294);
    assert_eq!(zigzag_encode_i32(i32::MIN), 4294967295);
}

#[test]
fn test_zigzag_decode_patterns() {
    // Verify zigzag decoding
    assert_eq!(zigzag_decode_i32(0), 0);
    assert_eq!(zigzag_decode_i32(1), -1);
    assert_eq!(zigzag_decode_i32(2), 1);
    assert_eq!(zigzag_decode_i32(3), -2);
    assert_eq!(zigzag_decode_i32(4), 2);
    assert_eq!(zigzag_decode_i32(4294967294), i32::MAX);
    assert_eq!(zigzag_decode_i32(4294967295), i32::MIN);
}

#[test]
fn test_zigzag_i64_encode_patterns() {
    assert_eq!(zigzag_encode_i64(0), 0);
    assert_eq!(zigzag_encode_i64(-1), 1);
    assert_eq!(zigzag_encode_i64(1), 2);
    assert_eq!(zigzag_encode_i64(-2), 3);
    assert_eq!(zigzag_encode_i64(2), 4);
    assert_eq!(zigzag_encode_i64(i64::MAX), 18446744073709551614);
    assert_eq!(zigzag_encode_i64(i64::MIN), 18446744073709551615);
}

#[test]
fn test_zigzag_i64_decode_patterns() {
    assert_eq!(zigzag_decode_i64(0), 0);
    assert_eq!(zigzag_decode_i64(1), -1);
    assert_eq!(zigzag_decode_i64(2), 1);
    assert_eq!(zigzag_decode_i64(3), -2);
    assert_eq!(zigzag_decode_i64(4), 2);
    assert_eq!(zigzag_decode_i64(18446744073709551614), i64::MAX);
    assert_eq!(zigzag_decode_i64(18446744073709551615), i64::MIN);
}

#[test]
fn test_zigzag_roundtrip_range_i32() {
    // Test a range of values
    for i in -10000..10000 {
        let encoded = zigzag_encode_i32(i);
        let decoded = zigzag_decode_i32(encoded);
        assert_eq!(decoded, i);
    }
}

#[test]
fn test_decode_len_matches_decode() {
    // Verify that decode_len returns the same length as decode
    let test_values = vec![
        0u32,
        1,
        127,
        128,
        255,
        256,
        16383,
        16384,
        2097151,
        2097152,
        268435455,
        268435456,
        u32::MAX,
    ];

    for value in test_values {
        let (buf, encode_len) = encode(value);

        let decode_result = decode::<u32>(&buf[..encode_len]);
        assert!(decode_result.is_ok());
        let (_, actual_len) = decode_result.unwrap();

        let len_result = decode_len::<u32>(&buf[..encode_len]);
        assert!(len_result.is_ok());
        let len_only = len_result.unwrap();

        assert_eq!(
            len_only, actual_len,
            "decode_len mismatch for value {}",
            value
        );
        assert_eq!(len_only, encode_len);
    }
}

#[test]
fn test_decode_len_all_lengths_u32() {
    // Test decode_len for each possible varint length
    let test_cases = vec![
        (0u32, 1),
        (127, 1),
        (128, 2),
        (16383, 2),
        (16384, 3),
        (2097151, 3),
        (2097152, 4),
        (268435455, 4),
        (268435456, 5),
        (u32::MAX, 5),
    ];

    for (value, expected_len) in test_cases {
        let (buf, _) = encode(value);
        let len = decode_len::<u32>(&buf).unwrap();
        assert_eq!(len, expected_len);
    }
}

#[test]
fn test_decode_len_all_lengths_u64() {
    let test_cases = vec![
        (0u64, 1),
        (127, 1),
        (16383, 2),
        (2097151, 3),
        (268435455, 4),
        (34359738367, 5),
        (4398046511103, 6),
        (562949953421311, 7),
        (72057594037927935, 8),
        (9223372036854775807, 9),
        (u64::MAX, 10),
    ];

    for (value, expected_len) in test_cases {
        let (buf, _) = encode(value);
        let len = decode_len::<u64>(&buf).unwrap();
        assert_eq!(len, expected_len);
    }
}

#[test]
fn test_encode_to_slice_u32() {
    let mut buf = [0u8; 16];

    let len = encode_to_slice(0u32, &mut buf);
    assert_eq!(len, 1);
    assert_eq!(buf[0], 0);

    let len = encode_to_slice(127u32, &mut buf);
    assert_eq!(len, 1);
    assert_eq!(buf[0], 127);

    let len = encode_to_slice(128u32, &mut buf);
    assert_eq!(len, 2);
    assert_eq!(buf[0], 0x80);
    assert_eq!(buf[1], 0x01);

    let len = encode_to_slice(u32::MAX, &mut buf);
    assert_eq!(len, 5);
}

#[test]
fn test_encode_to_slice_u64() {
    let mut buf = [0u8; 16];

    let len = encode_to_slice(u64::MAX, &mut buf);
    assert_eq!(len, 10);

    // Verify it decodes correctly
    let (decoded, dec_len) = decode::<u64>(&buf[..len]).unwrap();
    assert_eq!(decoded, u64::MAX);
    assert_eq!(dec_len, 10);
}

#[test]
fn test_varint_decode_exact_buffer() {
    // Test decoding when buffer is exactly the right size
    let (buf, len) = encode(12345u32);
    let result = decode::<u32>(&buf[..len]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().0, 12345);
}

#[test]
fn test_varint_decode_extra_bytes() {
    // Test decoding when buffer has extra bytes
    let mut buf = [0u8; 20];
    let len = encode_to_slice(12345u32, &mut buf);

    // Add extra data after the varint
    buf[len] = 0xFF;
    buf[len + 1] = 0xAA;

    let (decoded, dec_len) = decode::<u32>(&buf).unwrap();
    assert_eq!(decoded, 12345);
    assert_eq!(dec_len, len);
}

#[test]
fn test_varint_consecutive_values() {
    // Test encoding consecutive values to verify no off-by-one errors
    for i in 0..1000u32 {
        let (buf, len) = encode(i);
        let (decoded, _) = decode::<u32>(&buf[..len]).unwrap();
        assert_eq!(decoded, i);
    }
}

#[test]
fn test_varint_powers_of_two() {
    // Test powers of 2 and values around them
    for exp in 0..32 {
        let value = 1u32 << exp;

        // Test the power of 2
        let (buf, len) = encode(value);
        let (decoded, _) = decode::<u32>(&buf[..len]).unwrap();
        assert_eq!(decoded, value);

        // Test value - 1
        if value > 0 {
            let (buf, len) = encode(value - 1);
            let (decoded, _) = decode::<u32>(&buf[..len]).unwrap();
            assert_eq!(decoded, value - 1);
        }

        // Test value + 1
        if value < u32::MAX {
            let (buf, len) = encode(value + 1);
            let (decoded, _) = decode::<u32>(&buf[..len]).unwrap();
            assert_eq!(decoded, value + 1);
        }
    }
}

#[test]
fn test_varint_u64_powers_of_two() {
    for exp in 0..64 {
        let value = 1u64 << exp;

        let (buf, len) = encode(value);
        let (decoded, _) = decode::<u64>(&buf[..len]).unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn test_varint_decode_single_byte_values() {
    // All single-byte varints (0-127)
    for i in 0..=127u8 {
        let buf = [i];
        let (decoded, len) = decode::<u32>(&buf).unwrap();
        assert_eq!(decoded, i as u32);
        assert_eq!(len, 1);
    }
}

#[test]
fn test_varint_max_values_all_types() {
    // u8
    let (buf, len) = encode(u8::MAX);
    let (decoded, _) = decode::<u8>(&buf[..len]).unwrap();
    assert_eq!(decoded, u8::MAX);

    // u16
    let (buf, len) = encode(u16::MAX);
    let (decoded, _) = decode::<u16>(&buf[..len]).unwrap();
    assert_eq!(decoded, u16::MAX);

    // u32
    let (buf, len) = encode(u32::MAX);
    let (decoded, _) = decode::<u32>(&buf[..len]).unwrap();
    assert_eq!(decoded, u32::MAX);

    // u64
    let (buf, len) = encode(u64::MAX);
    let (decoded, _) = decode::<u64>(&buf[..len]).unwrap();
    assert_eq!(decoded, u64::MAX);
}

#[test]
fn test_varint_min_values_all_types() {
    // All types have min value of 0
    let (buf, len) = encode(0u8);
    assert_eq!(len, 1);
    let (decoded, _) = decode::<u8>(&buf[..len]).unwrap();
    assert_eq!(decoded, 0u8);

    let (buf, len) = encode(0u16);
    assert_eq!(len, 1);
    let (decoded, _) = decode::<u16>(&buf[..len]).unwrap();
    assert_eq!(decoded, 0u16);

    let (buf, len) = encode(0u32);
    assert_eq!(len, 1);
    let (decoded, _) = decode::<u32>(&buf[..len]).unwrap();
    assert_eq!(decoded, 0u32);

    let (buf, len) = encode(0u64);
    assert_eq!(len, 1);
    let (decoded, _) = decode::<u64>(&buf[..len]).unwrap();
    assert_eq!(decoded, 0u64);
}

#[test]
fn test_zigzag_symmetric_values() {
    // Test that positive and negative values of same magnitude encode to adjacent values
    for i in 1..100 {
        let pos_encoded = zigzag_encode_i32(i);
        let neg_encoded = zigzag_encode_i32(-i);

        // Positive values encode to even numbers, negatives to odd
        assert_eq!(pos_encoded % 2, 0);
        assert_eq!(neg_encoded % 2, 1);

        // They should be adjacent (within 1 of each other)
        assert!((pos_encoded as i64 - neg_encoded as i64).abs() <= 1);
    }
}

#[test]
fn test_varint_decode_error_conditions() {
    // Empty buffer
    let empty: &[u8] = &[];
    assert!(decode::<u32>(empty).is_err());

    // Truncated varint
    let truncated = &[0x80]; // Continuation bit set, but no next byte
    assert!(decode::<u32>(truncated).is_err());

    // Too many bytes for u32
    let too_long = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    assert!(decode::<u32>(too_long).is_err());

    // All continuation bits (no terminator) within valid length
    let no_term = &[0x80, 0x80, 0x80, 0x80];
    let result = decode::<u32>(no_term);
    // Should error (either InvalidVarint or UnexpectedEof)
    assert!(result.is_err());
}

#[test]
fn test_zigzag_special_values_i32() {
    // Test special boundary values
    let special = vec![
        (i32::MIN, u32::MAX),
        (i32::MAX, u32::MAX - 1),
        (0, 0),
        (-1, 1),
        (1, 2),
    ];

    for (signed, expected_unsigned) in special {
        let encoded = zigzag_encode_i32(signed);
        assert_eq!(encoded, expected_unsigned);

        let decoded = zigzag_decode_i32(encoded);
        assert_eq!(decoded, signed);
    }
}

#[test]
fn test_zigzag_special_values_i64() {
    let special = vec![
        (i64::MIN, u64::MAX),
        (i64::MAX, u64::MAX - 1),
        (0, 0),
        (-1, 1),
        (1, 2),
    ];

    for (signed, expected_unsigned) in special {
        let encoded = zigzag_encode_i64(signed);
        assert_eq!(encoded, expected_unsigned);

        let decoded = zigzag_decode_i64(encoded);
        assert_eq!(decoded, signed);
    }
}
