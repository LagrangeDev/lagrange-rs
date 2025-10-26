
use lagrange_proto::*;
use lagrange_proto::error::{DecodeError, EncodeError, ProtoError};
use lagrange_proto::wire::WireType;

#[test]
fn test_decode_empty_buffer() {
    let empty: &[u8] = &[];

    // Attempting to decode from empty buffer should fail
    let result = u32::decode(empty);
    assert!(result.is_err());
    match result {
        Err(DecodeError::UnexpectedEof) => {},
        _ => panic!("Expected UnexpectedEof error"),
    }
}

#[test]
fn test_decode_truncated_varint() {
    // A varint with continuation bit set but no next byte
    let truncated = &[0x80];

    let result = u32::decode(truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_truncated_string() {
    // String length says 10, but only 5 bytes available
    let truncated = &[10, b'h', b'e', b'l', b'l', b'o'];

    let result = String::decode(truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_truncated_bytes() {
    // Bytes length says 10, but only 3 bytes available
    let truncated = &[10, 1, 2, 3];

    let result = Vec::<u8>::decode(truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_truncated_f32() {
    // f32 requires 4 bytes, provide only 3
    let truncated = &[0x00, 0x00, 0x80];

    let result = f32::decode(truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_truncated_f64() {
    // f64 requires 8 bytes, provide only 7
    let truncated = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let result = f64::decode(truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_invalid_bool_value_2() {
    // Bool should only be 0 or 1, test value 2
    let invalid_bool = &[2];

    let result = bool::decode(invalid_bool);
    assert!(result.is_err());
    match result {
        Err(DecodeError::InvalidBool(val)) => assert_eq!(val, 2),
        _ => panic!("Expected InvalidBool error"),
    }
}

#[test]
fn test_decode_invalid_bool_value_255() {
    // Test invalid bool value (255 as single byte is value 127 with continuation bit)
    // Actually 255 = 0xFF which would be parsed as incomplete varint
    // Let's use a complete 2-byte varint that decodes to a value > 1
    let invalid_bool = &[0x80, 0x02]; // This is varint for 256

    let result = bool::decode(invalid_bool);
    assert!(result.is_err());
    match result {
        Err(DecodeError::InvalidBool(_)) => {},
        _ => panic!("Expected InvalidBool error"),
    }
}

#[test]
fn test_decode_invalid_bool_large_varint() {
    // Multi-byte varint that's not 0 or 1
    let invalid_bool = &[0x80, 0x01]; // Varint for 128

    let result = bool::decode(invalid_bool);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::InvalidBool(_))));
}

#[test]
fn test_decode_invalid_utf8() {
    // Invalid UTF-8 sequence
    let invalid_utf8 = &[
        5,           // Length: 5 bytes
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB,  // Invalid UTF-8
    ];

    let result = String::decode(invalid_utf8);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::InvalidUtf8(_))));
}

#[test]
fn test_decode_invalid_utf8_incomplete_sequence() {
    // Incomplete multi-byte UTF-8 sequence
    let invalid = &[
        2,          // Length: 2 bytes
        0xC3,       // Start of 2-byte sequence
        0xFF,       // Invalid continuation byte
    ];

    let result = String::decode(invalid);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::InvalidUtf8(_))));
}

#[test]
fn test_invalid_wire_type() {
    let result = WireType::from_u8(6);
    assert!(result.is_err());
    match result {
        Err(DecodeError::InvalidWireType(val)) => assert_eq!(val, 6),
        _ => panic!("Expected InvalidWireType error"),
    }
}

#[test]
fn test_invalid_wire_type_255() {
    let result = WireType::from_u8(255);
    assert!(result.is_err());
    match result {
        Err(DecodeError::InvalidWireType(val)) => assert_eq!(val, 255),
        _ => panic!("Expected InvalidWireType error"),
    }
}

#[test]
fn test_invalid_tag_zero() {
    use lagrange_proto::wire::Key;

    let result = Key::decode(0);
    assert!(result.is_err());
    match result {
        Err(DecodeError::InvalidTag(tag)) => assert_eq!(tag, 0),
        _ => panic!("Expected InvalidTag error"),
    }
}

#[test]
fn test_skip_field_varint_truncated() {
    use lagrange_proto::decoding::skip_field;

    let truncated = &[0x80]; // Varint with continuation bit but no next byte

    let result = skip_field(WireType::Varint, truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_skip_field_fixed32_truncated() {
    use lagrange_proto::decoding::skip_field;

    let truncated = &[1, 2, 3]; // Only 3 bytes, need 4

    let result = skip_field(WireType::Fixed32, truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_skip_field_fixed64_truncated() {
    use lagrange_proto::decoding::skip_field;

    let truncated = &[1, 2, 3, 4, 5, 6, 7]; // Only 7 bytes, need 8

    let result = skip_field(WireType::Fixed64, truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_skip_field_length_delimited_truncated_length() {
    use lagrange_proto::decoding::skip_field;

    let truncated = &[0x80]; // Varint length with continuation but no next byte

    let result = skip_field(WireType::LengthDelimited, truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_skip_field_length_delimited_truncated_data() {
    use lagrange_proto::decoding::skip_field;

    let truncated = &[10, 1, 2, 3]; // Says length 10, only 3 bytes

    let result = skip_field(WireType::LengthDelimited, truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_skip_field_start_group_unsupported() {
    use lagrange_proto::decoding::skip_field;

    let data = &[1, 2, 3];

    let result = skip_field(WireType::StartGroup, data);
    assert!(result.is_err());
    match result {
        Err(DecodeError::Custom(msg)) => {
            assert!(msg.contains("Groups are not supported") || msg.contains("not supported"));
        },
        _ => panic!("Expected Custom error for unsupported groups"),
    }
}

#[test]
fn test_skip_field_end_group_unsupported() {
    use lagrange_proto::decoding::skip_field;

    let data = &[1, 2, 3];

    let result = skip_field(WireType::EndGroup, data);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::Custom(_))));
}

#[test]
fn test_field_reader_empty_buffer() {
    use lagrange_proto::decoding::FieldReader;

    let empty: &[u8] = &[];
    let mut reader = FieldReader::new(empty);

    assert!(!reader.has_remaining());

    let result = reader.read_field_key();
    assert!(result.is_err());
}

#[test]
fn test_field_reader_truncated_key() {
    use lagrange_proto::decoding::FieldReader;

    let truncated = &[0x80]; // Key with continuation bit but no next byte
    let mut reader = FieldReader::new(truncated);

    let result = reader.read_field_key();
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_field_reader_truncated_varint() {
    use lagrange_proto::decoding::FieldReader;

    let data = &[0x08, 0x80]; // Field tag 1, truncated varint value
    let mut reader = FieldReader::new(data);

    reader.read_field_key().unwrap();

    let result = reader.read_varint();
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_field_reader_truncated_fixed32() {
    use lagrange_proto::decoding::FieldReader;

    let data = &[0x2D, 1, 2, 3]; // Fixed32 field, only 3 bytes
    let mut reader = FieldReader::new(data);

    reader.read_field_key().unwrap();

    let result = reader.read_fixed32();
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_field_reader_truncated_fixed64() {
    use lagrange_proto::decoding::FieldReader;

    let data = &[0x29, 1, 2, 3, 4, 5, 6, 7]; // Fixed64 field, only 7 bytes
    let mut reader = FieldReader::new(data);

    reader.read_field_key().unwrap();

    let result = reader.read_fixed64();
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_field_reader_truncated_length_delimited() {
    use lagrange_proto::decoding::FieldReader;

    let data = &[0x0A, 10, 1, 2, 3]; // Length-delimited, says 10 bytes, only 3
    let mut reader = FieldReader::new(data);

    reader.read_field_key().unwrap();

    let result = reader.read_length_delimited();
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_field_reader_read_field_data_groups_unsupported() {
    use lagrange_proto::decoding::FieldReader;

    let data = &[1, 2, 3];
    let mut reader = FieldReader::new(data);

    let result = reader.read_field_data(WireType::StartGroup);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::Custom(_))));

    let result = reader.read_field_data(WireType::EndGroup);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::Custom(_))));
}

#[test]
fn test_varint_decode_overflow_u32() {
    // Varint that's too large for u32 (6 bytes when u32 max is 5)
    let overlong = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    let result = u32::decode(overlong);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::InvalidVarint)));
}

#[test]
fn test_varint_decode_missing_terminator() {
    // 5 bytes all with continuation bit set (invalid for u32)
    let no_terminator = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    let result = u32::decode(no_terminator);
    assert!(result.is_err());
    // Could be either InvalidVarint or UnexpectedEof depending on implementation
    assert!(matches!(result, Err(DecodeError::InvalidVarint) | Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_varint_decode_u64_overflow() {
    // 11 bytes when u64 max is 10
    let overlong = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    let result = u64::decode(overlong);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::InvalidVarint)));
}

#[test]
fn test_decode_error_display() {
    let err = DecodeError::UnexpectedEof;
    let display = format!("{}", err);
    assert!(display.contains("Unexpected end of input"));

    let err = DecodeError::InvalidWireType(6);
    let display = format!("{}", err);
    assert!(display.contains("Invalid wire type"));
    assert!(display.contains("6"));

    let err = DecodeError::InvalidTag(0);
    let display = format!("{}", err);
    assert!(display.contains("Invalid field tag"));

    let err = DecodeError::InvalidVarint;
    let display = format!("{}", err);
    assert!(display.contains("Invalid varint encoding"));

    let err = DecodeError::InvalidBool(42);
    let display = format!("{}", err);
    assert!(display.contains("Invalid boolean value"));
    assert!(display.contains("42"));
}

#[test]
fn test_encode_error_display() {
    let err = EncodeError::InvalidTag(0);
    let display = format!("{}", err);
    assert!(display.contains("Invalid field tag"));

    let err = EncodeError::BufferTooSmall;
    let display = format!("{}", err);
    assert!(display.contains("Buffer too small"));

    let err = EncodeError::Custom("test error".to_string());
    let display = format!("{}", err);
    assert!(display.contains("test error"));
}

#[test]
fn test_proto_error_from_decode_error() {
    let decode_err = DecodeError::UnexpectedEof;
    let proto_err: ProtoError = decode_err.into();

    let display = format!("{}", proto_err);
    assert!(display.contains("Decode error"));
}

#[test]
fn test_proto_error_from_encode_error() {
    let encode_err = EncodeError::BufferTooSmall;
    let proto_err: ProtoError = encode_err.into();

    let display = format!("{}", proto_err);
    assert!(display.contains("Encode error"));
}

#[test]
fn test_proto_error_from_io_error() {
    use std::io;

    let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "test");
    let proto_err: ProtoError = io_err.into();

    let display = format!("{}", proto_err);
    assert!(display.contains("Decode error"));
}

#[test]
fn test_custom_decode_error() {
    let err = DecodeError::Custom("custom message".to_string());
    let display = format!("{}", err);
    assert_eq!(display, "custom message");
}

#[test]
fn test_custom_encode_error() {
    let err = EncodeError::Custom("custom encode message".to_string());
    let display = format!("{}", err);
    assert_eq!(display, "custom encode message");
}

#[test]
fn test_missing_field_error() {
    let err = DecodeError::MissingField("required_field");
    let display = format!("{}", err);
    assert!(display.contains("Required field missing"));
    assert!(display.contains("required_field"));
}

#[test]
fn test_unknown_field_error() {
    let err = DecodeError::UnknownField(999);
    let display = format!("{}", err);
    assert!(display.contains("Unknown field"));
    assert!(display.contains("999"));
}

#[test]
fn test_invalid_enum_value_error() {
    let err = DecodeError::InvalidEnumValue(42);
    let display = format!("{}", err);
    assert!(display.contains("Invalid enum value"));
    assert!(display.contains("42"));
}

#[test]
fn test_decode_fixed32_empty() {
    use lagrange_proto::decoding::decode_fixed32_field;

    let empty: &[u8] = &[];
    let result = decode_fixed32_field(empty);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_fixed64_empty() {
    use lagrange_proto::decoding::decode_fixed64_field;

    let empty: &[u8] = &[];
    let result = decode_fixed64_field(empty);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_length_delimited_empty() {
    use lagrange_proto::decoding::decode_length_delimited;

    let empty: &[u8] = &[];
    let result = decode_length_delimited(empty);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_length_delimited_truncated() {
    use lagrange_proto::decoding::decode_length_delimited;

    let truncated = &[5, 1, 2]; // Says 5 bytes, only 2 available
    let result = decode_length_delimited(truncated);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_varint_decode_len_empty() {
    use lagrange_proto::varint::decode_len;

    let empty: &[u8] = &[];
    let result = decode_len::<u32>(empty);
    assert!(result.is_err());
    assert!(matches!(result, Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_varint_decode_len_no_terminator() {
    use lagrange_proto::varint::decode_len;

    // All bytes have continuation bit set
    let no_terminator = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = decode_len::<u32>(no_terminator);
    assert!(result.is_err());
    // Should be either InvalidVarint or UnexpectedEof
    assert!(matches!(result, Err(DecodeError::InvalidVarint) | Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_varint_decode_len_truncated() {
    use lagrange_proto::varint::decode_len;

    // 2 bytes with continuation, but buffer only has 2 bytes
    let truncated = &[0x80, 0x80];
    let result = decode_len::<u32>(truncated);
    assert!(result.is_err());
}
