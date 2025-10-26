use bytes::BytesMut;
use lagrange_proto::decoding::FieldReader;
use lagrange_proto::encoding::{
    encode_fixed32_field, encode_fixed64_field, encode_length_delimited, encode_varint_field,
};
use lagrange_proto::wire::WireType;

#[test]
fn test_field_reader_basic_usage() {
    let mut buf = BytesMut::new();

    // Encode several fields
    encode_varint_field(1, 42, &mut buf).unwrap();
    encode_varint_field(2, 100, &mut buf).unwrap();
    encode_varint_field(3, 200, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Read first field
    assert!(reader.has_remaining());
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::Varint);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 42);

    // Read second field
    assert!(reader.has_remaining());
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 2);
    assert_eq!(wire_type, WireType::Varint);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 100);

    // Read third field
    assert!(reader.has_remaining());
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 3);
    assert_eq!(wire_type, WireType::Varint);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 200);

    // No more data
    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_skip_varint() {
    let mut buf = BytesMut::new();

    encode_varint_field(1, 42, &mut buf).unwrap();
    encode_varint_field(2, 100, &mut buf).unwrap();
    encode_varint_field(3, 200, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Read and skip first field
    let (_, wire_type) = reader.read_field_key().unwrap();
    reader.skip_field(wire_type).unwrap();

    // Should now be at second field
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 2);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 100);
}

#[test]
fn test_field_reader_skip_fixed32() {
    let mut buf = BytesMut::new();

    encode_fixed32_field(1, 0xDEADBEEF, &mut buf).unwrap();
    encode_varint_field(2, 42, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Skip fixed32 field
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::Fixed32);
    reader.skip_field(wire_type).unwrap();

    // Should be at varint field
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 2);
    assert_eq!(wire_type, WireType::Varint);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 42);
}

#[test]
fn test_field_reader_skip_fixed64() {
    let mut buf = BytesMut::new();

    encode_fixed64_field(1, 0xDEADBEEFCAFEBABE, &mut buf).unwrap();
    encode_varint_field(2, 42, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Skip fixed64 field
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::Fixed64);
    reader.skip_field(wire_type).unwrap();

    // Should be at varint field
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 2);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 42);
}

#[test]
fn test_field_reader_skip_length_delimited() {
    let mut buf = BytesMut::new();

    encode_length_delimited(1, b"hello world", &mut buf).unwrap();
    encode_varint_field(2, 42, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Skip length-delimited field
    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::LengthDelimited);
    reader.skip_field(wire_type).unwrap();

    // Should be at varint field
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 2);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 42);
}

#[test]
fn test_field_reader_read_fixed32() {
    let mut buf = BytesMut::new();

    encode_fixed32_field(1, 0x12345678, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::Fixed32);

    let value = reader.read_fixed32().unwrap();
    assert_eq!(value, 0x12345678);

    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_read_fixed64() {
    let mut buf = BytesMut::new();

    encode_fixed64_field(1, 0x123456789ABCDEF0, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::Fixed64);

    let value = reader.read_fixed64().unwrap();
    assert_eq!(value, 0x123456789ABCDEF0);

    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_read_length_delimited() {
    let mut buf = BytesMut::new();

    let data = b"test data";
    encode_length_delimited(1, data, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::LengthDelimited);

    let result = reader.read_length_delimited().unwrap();
    assert_eq!(result, data);

    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_read_length_delimited_slice() {
    let mut buf = BytesMut::new();

    let data = b"test data";
    encode_length_delimited(1, data, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    reader.read_field_key().unwrap();

    let (start, len) = reader.read_length_delimited_slice().unwrap();
    assert!(start < buf.len());
    assert!(len > 0);

    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_advance() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(b"0123456789");

    let mut reader = FieldReader::new(&buf);

    assert_eq!(reader.remaining().len(), 10);

    reader.advance(3);
    assert_eq!(reader.remaining().len(), 7);
    assert_eq!(reader.remaining()[0], b'3');

    reader.advance(5);
    assert_eq!(reader.remaining().len(), 2);
    assert_eq!(reader.remaining()[0], b'8');

    reader.advance(2);
    assert_eq!(reader.remaining().len(), 0);
    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_remaining() {
    let data = b"test data";
    let reader = FieldReader::new(data);

    let remaining = reader.remaining();
    assert_eq!(remaining, data);
}

#[test]
fn test_field_reader_empty_buffer() {
    let empty: &[u8] = &[];
    let reader = FieldReader::new(empty);

    assert!(!reader.has_remaining());
    assert_eq!(reader.remaining().len(), 0);
}

#[test]
fn test_field_reader_multiple_skip_operations() {
    let mut buf = BytesMut::new();

    // Add various field types
    encode_varint_field(1, 100, &mut buf).unwrap();
    encode_fixed32_field(2, 0xDEADBEEF, &mut buf).unwrap();
    encode_fixed64_field(3, 0xCAFEBABE, &mut buf).unwrap();
    encode_length_delimited(4, b"data", &mut buf).unwrap();
    encode_varint_field(5, 42, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Skip all fields except the last
    for _ in 0..4 {
        let (_, wire_type) = reader.read_field_key().unwrap();
        reader.skip_field(wire_type).unwrap();
    }

    // Should be at field 5
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 5);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 42);
}

#[test]
fn test_field_reader_read_field_data_varint() {
    let mut buf = BytesMut::new();
    encode_varint_field(1, 12345, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (_, wire_type) = reader.read_field_key().unwrap();
    let data = reader.read_field_data(wire_type).unwrap();

    // Verify the data can be decoded
    assert!(!data.is_empty());
}

#[test]
fn test_field_reader_read_field_data_fixed32() {
    let mut buf = BytesMut::new();
    encode_fixed32_field(1, 0x12345678, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (_, wire_type) = reader.read_field_key().unwrap();
    let data = reader.read_field_data(wire_type).unwrap();

    // Fixed32 should be exactly 4 bytes
    assert_eq!(data.len(), 4);
}

#[test]
fn test_field_reader_read_field_data_fixed64() {
    let mut buf = BytesMut::new();
    encode_fixed64_field(1, 0x123456789ABCDEF0, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (_, wire_type) = reader.read_field_key().unwrap();
    let data = reader.read_field_data(wire_type).unwrap();

    // Fixed64 should be exactly 8 bytes
    assert_eq!(data.len(), 8);
}

#[test]
fn test_field_reader_read_field_data_length_delimited() {
    let mut buf = BytesMut::new();
    encode_length_delimited(1, b"test data", &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (_, wire_type) = reader.read_field_key().unwrap();
    let data = reader.read_field_data(wire_type).unwrap();

    // Should include the length prefix and the data
    assert!(data.len() > 9);
}

#[test]
fn test_field_reader_large_tag_number() {
    let mut buf = BytesMut::new();

    // Use a large tag number
    encode_varint_field(268435455, 42, &mut buf).unwrap(); // Max valid field number

    let mut reader = FieldReader::new(&buf);

    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 268435455);
    let value = reader.read_varint().unwrap();
    assert_eq!(value, 42);
}

#[test]
fn test_field_reader_consecutive_same_tag() {
    let mut buf = BytesMut::new();

    // Multiple fields with same tag (used for repeated fields)
    encode_varint_field(1, 100, &mut buf).unwrap();
    encode_varint_field(1, 200, &mut buf).unwrap();
    encode_varint_field(1, 300, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let mut values = Vec::new();
    while reader.has_remaining() {
        let (tag, _) = reader.read_field_key().unwrap();
        assert_eq!(tag, 1);
        values.push(reader.read_varint().unwrap());
    }

    assert_eq!(values, vec![100, 200, 300]);
}

#[test]
fn test_field_reader_mixed_field_types() {
    let mut buf = BytesMut::new();

    // Mix of all field types
    encode_varint_field(1, 42, &mut buf).unwrap();
    encode_fixed64_field(2, 0x1234567890ABCDEF, &mut buf).unwrap();
    encode_length_delimited(3, b"string", &mut buf).unwrap();
    encode_fixed32_field(4, 0xDEADBEEF, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    // Read varint
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(reader.read_varint().unwrap(), 42);

    // Read fixed64
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 2);
    assert_eq!(reader.read_fixed64().unwrap(), 0x1234567890ABCDEF);

    // Read length delimited
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 3);
    assert_eq!(reader.read_length_delimited().unwrap(), b"string");

    // Read fixed32
    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 4);
    assert_eq!(reader.read_fixed32().unwrap(), 0xDEADBEEF);

    assert!(!reader.has_remaining());
}

#[test]
fn test_field_reader_empty_length_delimited() {
    let mut buf = BytesMut::new();

    // Empty string
    encode_length_delimited(1, b"", &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (tag, wire_type) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(wire_type, WireType::LengthDelimited);

    let data = reader.read_length_delimited().unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_field_reader_zero_value_fields() {
    let mut buf = BytesMut::new();

    encode_varint_field(1, 0, &mut buf).unwrap();
    encode_fixed32_field(2, 0, &mut buf).unwrap();
    encode_fixed64_field(3, 0, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (_, _) = reader.read_field_key().unwrap();
    assert_eq!(reader.read_varint().unwrap(), 0);

    let (_, _) = reader.read_field_key().unwrap();
    assert_eq!(reader.read_fixed32().unwrap(), 0);

    let (_, _) = reader.read_field_key().unwrap();
    assert_eq!(reader.read_fixed64().unwrap(), 0);
}

#[test]
fn test_field_reader_max_value_varints() {
    let mut buf = BytesMut::new();

    encode_varint_field(1, u64::MAX, &mut buf).unwrap();

    let mut reader = FieldReader::new(&buf);

    let (tag, _) = reader.read_field_key().unwrap();
    assert_eq!(tag, 1);
    assert_eq!(reader.read_varint().unwrap(), u64::MAX);
}

#[test]
fn test_field_reader_sequential_processing() {
    let mut buf = BytesMut::new();

    // Simulate a typical message
    for i in 1..=10 {
        encode_varint_field(i, i as u64 * 100, &mut buf).unwrap();
    }

    let mut reader = FieldReader::new(&buf);
    let mut field_count = 0;

    while reader.has_remaining() {
        let (tag, _) = reader.read_field_key().unwrap();
        let value = reader.read_varint().unwrap();
        assert_eq!(tag as u64, value / 100);
        field_count += 1;
    }

    assert_eq!(field_count, 10);
}
