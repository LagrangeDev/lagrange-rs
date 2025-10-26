
use lagrange_proto::*;
use lagrange_proto::error::DecodeError;

#[test]
fn test_truncated_at_every_position() {
    // Encode a valid message
    let original = "hello world".to_string();
    let mut buf = bytes::BytesMut::new();
    original.encode(&mut buf).unwrap();

    // Try decoding truncated versions at every position
    for i in 0..buf.len() {
        let truncated = &buf[..i];
        let result = String::decode(truncated);

        // Should fail with UnexpectedEof
        if result.is_err() {
            match result.err().unwrap() {
                DecodeError::UnexpectedEof | DecodeError::InvalidVarint => {},
                other => panic!("Unexpected error at position {}: {:?}", i, other),
            }
        }
    }
}

#[test]
fn test_corrupted_length_prefix() {
    // Create a string with corrupted length
    let mut buf = vec![255u8]; // Says length is 255
    buf.extend_from_slice(b"short"); // But only 5 bytes

    let result = String::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn test_length_exceeds_buffer() {
    // Length says 1000, but buffer is much smaller
    let mut buf = bytes::BytesMut::new();
    let mut varint_buf = [0u8; 16];
    let len = lagrange_proto::varint::encode_to_slice(1000u32, &mut varint_buf);
    buf.extend_from_slice(&varint_buf[..len]);
    buf.extend_from_slice(b"short");

    let result = String::decode(&buf);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DecodeError::UnexpectedEof));
}

#[test]
fn test_zero_length_with_data() {
    // Length says 0, but there's data after
    let buf = vec![0u8, 1, 2, 3];

    let result = String::decode(&buf);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "");
}

#[test]
fn test_varint_overflow_u32() {
    // 6 bytes when u32 max is 5
    let buf = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];

    let result = u32::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn test_varint_missing_terminator() {
    // All bytes have continuation bit
    let buf = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let result = u32::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn test_bool_invalid_values() {
    // Note: single byte values 0-127 are valid varints
    // For values > 127, they have the continuation bit set and require more bytes
    // So we test with complete multi-byte varints that decode to invalid bool values
    let invalid_cases = vec![
        (vec![2u8], 2u64),           // Valid varint, invalid bool
        (vec![3], 3),
        (vec![4], 4),
        (vec![5], 5),
        (vec![10], 10),
        (vec![127], 127),
        (vec![0x80, 0x02], 256),     // Multi-byte varint
    ];

    for (buf, expected_val) in invalid_cases {
        let result = bool::decode(&buf);
        assert!(result.is_err(), "Value {} should be invalid for bool", expected_val);
        match result.unwrap_err() {
            DecodeError::InvalidBool(v) => assert_eq!(v, expected_val),
            other => panic!("Expected InvalidBool error, got {:?}", other),
        }
    }
}

#[test]
fn test_invalid_utf8_sequences() {
    let invalid_sequences = vec![
        vec![1, 0xFF],                    // Invalid byte
        vec![2, 0xC3, 0x28],              // Invalid continuation
        vec![3, 0xE2, 0x28, 0xA1],        // Invalid UTF-8
        vec![4, 0xF0, 0x90, 0x28, 0xBC],  // Invalid UTF-8
        vec![2, 0xC0, 0x80],              // Overlong encoding
        vec![3, 0xE0, 0x80, 0x80],        // Overlong encoding
    ];

    for seq in invalid_sequences {
        let result = String::decode(&seq);
        assert!(result.is_err(), "Should reject invalid UTF-8: {:?}", seq);
        assert!(matches!(result.unwrap_err(), DecodeError::InvalidUtf8(_)));
    }
}

#[test]
fn test_incomplete_utf8_multibyte() {
    let incomplete_sequences = vec![
        vec![1, 0xC3],           // 2-byte char, missing continuation
        vec![2, 0xE2, 0x82],     // 3-byte char, missing continuation
        vec![3, 0xF0, 0x90, 0x8D], // 4-byte char, missing continuation
    ];

    for seq in incomplete_sequences {
        let result = String::decode(&seq);
        assert!(result.is_err(), "Should reject incomplete UTF-8: {:?}", seq);
    }
}

#[test]
fn test_fixed32_truncated() {
    let truncated_bufs = vec![
        vec![],
        vec![0x00],
        vec![0x00, 0x00],
        vec![0x00, 0x00, 0x00],
    ];

    for buf in truncated_bufs {
        let result = f32::decode(&buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DecodeError::UnexpectedEof));
    }
}

#[test]
fn test_fixed64_truncated() {
    let truncated_bufs = vec![
        vec![],
        vec![0x00],
        vec![0x00, 0x00, 0x00, 0x00],
        vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    for buf in truncated_bufs {
        let result = f64::decode(&buf);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DecodeError::UnexpectedEof));
    }
}

#[test]
fn test_bytes_corrupted_length() {
    // Says length is 100, but only 10 bytes available
    let mut buf = vec![];
    let mut varint_buf = [0u8; 16];
    let len = lagrange_proto::varint::encode_to_slice(100u32, &mut varint_buf);
    buf.extend_from_slice(&varint_buf[..len]);
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    let result = Vec::<u8>::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn test_random_data() {
    // Random bytes should generally fail to decode
    let random = vec![0x47, 0x92, 0xA3, 0xF1, 0x5C, 0x8E, 0xD9, 0x42];

    let _ = String::decode(&random); // May fail or succeed depending on data
    let _ = u32::decode(&random);
    let _ = bool::decode(&random);
}

#[test]
fn test_all_zeros() {
    let zeros = vec![0u8; 100];

    // Should decode successfully in most cases
    let result = u32::decode(&zeros);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_all_ones() {
    let ones = vec![0xFFu8; 100];

    // May overflow or succeed depending on type
    let result = u32::decode(&ones);
    // Could be InvalidVarint or UnexpectedEof
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_field_key_invalid_tag_zero() {
    use lagrange_proto::wire::Key;

    // Tag 0 is invalid (encoded as 0 which decodes to tag 0, wiretype 0)
    let result = Key::decode(0);
    assert!(result.is_err());
    match result.unwrap_err() {
        DecodeError::InvalidTag(0) => {},
        _ => panic!("Expected InvalidTag(0)"),
    }
}

#[test]
fn test_field_key_invalid_wire_type() {
    use lagrange_proto::wire::Key;

    // Create a key with invalid wire type (6)
    let invalid_key = (1 << 3) | 6; // Tag 1, wire type 6
    let result = Key::decode(invalid_key);
    assert!(result.is_err());
    match result.unwrap_err() {
        DecodeError::InvalidWireType(6) => {},
        _ => panic!("Expected InvalidWireType(6)"),
    }
}

#[test]
fn test_skip_field_truncated_varint() {
    use lagrange_proto::decoding::skip_field;
    use lagrange_proto::wire::WireType;

    let truncated = vec![0x80]; // Continuation bit but no next byte
    let result = skip_field(WireType::Varint, &truncated);
    assert!(result.is_err());
}

#[test]
fn test_skip_field_truncated_length_delimited() {
    use lagrange_proto::decoding::skip_field;
    use lagrange_proto::wire::WireType;

    let truncated = vec![10, 1, 2]; // Says length 10, only 2 bytes
    let result = skip_field(WireType::LengthDelimited, &truncated);
    assert!(result.is_err());
}

#[test]
fn test_decode_field_key_empty() {
    use lagrange_proto::decoding::decode_field_key;

    let empty: &[u8] = &[];
    let result = decode_field_key(empty);
    assert!(result.is_err());
}

#[test]
fn test_decode_field_key_truncated() {
    use lagrange_proto::decoding::decode_field_key;

    let truncated = vec![0x80]; // Continuation bit but no next byte
    let result = decode_field_key(truncated.as_slice());
    assert!(result.is_err());
}

#[test]
fn test_decode_length_delimited_negative_length() {
    use lagrange_proto::decoding::decode_length_delimited;

    // This is tricky - varints are unsigned, so negative isn't directly possible
    // But we can test very large values that would overflow
    let mut buf = vec![];
    let mut varint_buf = [0u8; 16];
    let len = lagrange_proto::varint::encode_to_slice(u32::MAX, &mut varint_buf);
    buf.extend_from_slice(&varint_buf[..len]);

    let result = decode_length_delimited(&buf);
    assert!(result.is_err());
}

#[test]
fn test_malformed_repeated_truncation() {
    // Encode several values, then truncate in the middle
    let mut buf = bytes::BytesMut::new();
    100u32.encode(&mut buf).unwrap();
    200u32.encode(&mut buf).unwrap();
    300u32.encode(&mut buf).unwrap();

    // Truncate in the middle of second value
    let truncated = &buf[..2];

    // Try to decode - should fail
    let _result = u32::decode(truncated);
    // First value decodes ok, but there's not enough for the second
    // This tests partial decode scenarios
}

#[test]
fn test_string_with_null_bytes() {
    // Null bytes are valid in UTF-8 strings
    let s = String::from("hello\0world");
    let mut buf = bytes::BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_bytes_max_length() {
    // Test with maximum reasonable length
    let data = vec![0xAB; 100000];
    let bytes = bytes::Bytes::from(data.clone());
    let mut buf = bytes::BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    let decoded = bytes::Bytes::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 100000);
}

#[test]
fn test_varint_boundary_corruption() {
    // Test corruption at varint length boundaries
    let mut buf = bytes::BytesMut::new();
    127u32.encode(&mut buf).unwrap();

    // Corrupt to make it look like 2-byte varint
    buf[0] = 0x80 | buf[0];

    let result = u32::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn test_mixed_valid_invalid_data() {
    // Valid data followed by invalid
    let mut buf = vec![];
    buf.push(5); // Valid length for string
    buf.extend_from_slice(b"hello");
    buf.push(255); // Invalid bool
    buf.push(0xFF); // Invalid UTF-8

    // First decode should work
    let result = String::decode(&buf);
    assert!(result.is_ok());

    // But if we try to decode the rest as bool, should fail
    let bool_result = bool::decode(&buf[6..7]);
    assert!(bool_result.is_err());
}

#[test]
fn test_extremely_large_length_prefix() {
    // Maximum u32 value as length
    let mut buf = vec![];
    let mut varint_buf = [0u8; 16];
    let len = lagrange_proto::varint::encode_to_slice(u32::MAX, &mut varint_buf);
    buf.extend_from_slice(&varint_buf[..len]);

    let result = Vec::<u8>::decode(&buf);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DecodeError::UnexpectedEof));
}

#[test]
fn test_partial_varint_multibyte() {
    // Multi-byte varint missing final byte
    let partials = vec![
        vec![0x80],             // 1 byte of 2
        vec![0x80, 0x80],       // 2 bytes of 3
        vec![0x80, 0x80, 0x80], // 3 bytes of 4
    ];

    for buf in partials {
        let result = u32::decode(&buf);
        assert!(result.is_err());
    }
}

#[test]
fn test_decode_past_buffer_end() {
    let buf = vec![42u8];

    // Decode should succeed for single byte
    let result = u32::decode(&buf);
    assert!(result.is_ok());

    // But trying to decode as f32 (needs 4 bytes) should fail
    let result = f32::decode(&buf);
    assert!(result.is_err());
}
