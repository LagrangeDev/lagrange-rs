
use lagrange_proto::*;
use lagrange_proto::helpers::*;
use lagrange_proto::wire::WireType;
use bytes::BytesMut;

#[test]
fn test_get_varint_length_u32_all_boundaries() {
    let test_cases = vec![
        (0u32, 1),
        (1, 1),
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

    for (value, expected) in test_cases {
        assert_eq!(get_varint_length_u32(value), expected,
                  "Incorrect length for u32: {}", value);
    }
}

#[test]
fn test_get_varint_length_u64_all_boundaries() {
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

    for (value, expected) in test_cases {
        assert_eq!(get_varint_length_u64(value), expected,
                  "Incorrect length for u64: {}", value);
    }
}

#[test]
fn test_count_string_empty() {
    let s = "";
    let size = count_string(s);

    assert_eq!(size, 1); // Just length prefix of 0
}

#[test]
fn test_count_string_various_lengths() {
    let s3 = "x".repeat(127);
    let s4 = "x".repeat(128);

    let test_cases = vec![
        ("a", 2),           // 1 byte length + 1 char
        ("hello", 6),       // 1 byte length + 5 chars
        (s3.as_str(), 128),   // 1 byte length + 127 chars
        (s4.as_str(), 130),   // 2 byte length + 128 chars
    ];

    for (s, expected) in test_cases {
        assert_eq!(count_string(s), expected);
    }
}

#[test]
fn test_count_string_unicode() {
    // Unicode characters take multiple bytes
    let s = "你好"; // 2 characters, 6 bytes in UTF-8
    let size = count_string(s);

    assert_eq!(size, 7); // 1 byte length + 6 bytes data
}

#[test]
fn test_count_bytes_empty() {
    let bytes: &[u8] = &[];
    let size = count_bytes(bytes);

    assert_eq!(size, 1); // Just length prefix of 0
}

#[test]
fn test_count_bytes_various_lengths() {
    let test_cases = vec![
        (1, 2),    // 1 byte length + 1 byte data
        (5, 6),    // 1 byte length + 5 bytes data
        (127, 128), // 1 byte length + 127 bytes data
        (128, 130), // 2 byte length + 128 bytes data
        (16383, 16385), // 2 byte length + 16383 bytes
        (16384, 16387), // 3 byte length + 16384 bytes
    ];

    for (len, expected) in test_cases {
        let bytes = vec![0u8; len];
        assert_eq!(count_bytes(&bytes), expected);
    }
}

#[test]
fn test_count_message() {
    // Test with a simple encodable type
    let value = 42u32;
    let size = count_message(&value);

    // Message size includes the value size + length prefix
    // 42 is 1 byte, so length prefix is also 1 byte
    assert_eq!(size, 2);
}

#[test]
fn test_count_message_large() {
    let value = u32::MAX;
    let size = count_message(&value);

    // u32::MAX is 5 bytes, so length prefix is 1 byte
    assert_eq!(size, 6);
}

#[test]
fn test_count_message_string() {
    let s = "hello".to_string();
    let size = count_message(&s);

    // String "hello" is 6 bytes (1 length + 5 data)
    // Message wrapper adds another length prefix
    assert_eq!(size, 7);
}

#[test]
fn test_field_tag_size_small_tags() {
    // Tag 1-15 with any wire type should be 1 byte
    for tag in 1..=15 {
        for wire_type in [
            WireType::Varint,
            WireType::Fixed64,
            WireType::LengthDelimited,
            WireType::Fixed32,
        ] {
            assert_eq!(field_tag_size(tag, wire_type), 1,
                      "Tag {} with {:?} should be 1 byte", tag, wire_type);
        }
    }
}

#[test]
fn test_field_tag_size_medium_tags() {
    // Tag 16-2047 should be 2 bytes
    let test_tags = [16, 100, 1000, 2047];

    for tag in test_tags {
        assert_eq!(field_tag_size(tag, WireType::Varint), 2,
                  "Tag {} should be 2 bytes", tag);
    }
}

#[test]
fn test_field_tag_size_large_tags() {
    // Tag 2048+ should be 3+ bytes
    let test_tags = [2048, 10000, 100000, 268435455]; // Max field number

    for tag in test_tags {
        let size = field_tag_size(tag, WireType::Varint);
        assert!(size >= 3, "Tag {} should be at least 3 bytes, got {}", tag, size);
    }
}

#[test]
fn test_count_repeated() {
    let items = vec![1u32, 2, 3, 4, 5];
    let tag_size = field_tag_size(1, WireType::Varint);

    let total = count_repeated(&items, tag_size);

    // Each item: tag_size + encoded_size
    // Items 1-5 are each 1 byte
    assert_eq!(total, 5 * (tag_size + 1));
}

#[test]
fn test_count_repeated_empty() {
    let items: Vec<u32> = vec![];
    let tag_size = field_tag_size(1, WireType::Varint);

    let total = count_repeated(&items, tag_size);

    assert_eq!(total, 0);
}

#[test]
fn test_count_repeated_large_values() {
    let items = vec![u32::MAX; 10];
    let tag_size = field_tag_size(1, WireType::Varint);

    let total = count_repeated(&items, tag_size);

    // Each u32::MAX is 5 bytes
    assert_eq!(total, 10 * (tag_size + 5));
}

#[test]
fn test_count_repeated_strings() {
    let strings = vec![
        "hello".to_string(),
        "world".to_string(),
        "test".to_string(),
    ];
    let tag_size = field_tag_size(1, WireType::LengthDelimited);

    let total = count_repeated_strings(&strings, tag_size);

    // Each string: tag + length + data
    // "hello" = 1 + 1 + 5 = 7
    // "world" = 1 + 1 + 5 = 7
    // "test" = 1 + 1 + 4 = 6
    // Total = 20
    assert_eq!(total, 20);
}

#[test]
fn test_count_repeated_strings_empty() {
    let strings: Vec<String> = vec![];
    let tag_size = field_tag_size(1, WireType::LengthDelimited);

    let total = count_repeated_strings(&strings, tag_size);

    assert_eq!(total, 0);
}

#[test]
fn test_count_repeated_strings_with_empty_strings() {
    let strings = vec![
        String::new(),
        String::new(),
        String::new(),
    ];
    let tag_size = field_tag_size(1, WireType::LengthDelimited);

    let total = count_repeated_strings(&strings, tag_size);

    // Each empty string: tag + length(0)
    assert_eq!(total, 3 * (tag_size + 1));
}

#[test]
fn test_count_repeated_bytes() {
    let bytes_list = vec![
        vec![1, 2, 3],
        vec![4, 5, 6, 7],
        vec![8],
    ];
    let tag_size = field_tag_size(1, WireType::LengthDelimited);

    let total = count_repeated_bytes(&bytes_list, tag_size);

    // [1,2,3]: tag + 1 + 3 = tag + 4
    // [4,5,6,7]: tag + 1 + 4 = tag + 5
    // [8]: tag + 1 + 1 = tag + 2
    // Total = 3*tag + 11
    assert_eq!(total, 3 * tag_size + 11);
}

#[test]
fn test_count_repeated_bytes_empty() {
    let bytes_list: Vec<Vec<u8>> = vec![];
    let tag_size = field_tag_size(1, WireType::LengthDelimited);

    let total = count_repeated_bytes(&bytes_list, tag_size);

    assert_eq!(total, 0);
}

#[test]
fn test_encoded_size_matches_actual_u32() {
    let test_values = [0u32, 1, 127, 128, u32::MAX];

    for value in test_values {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len(),
                  "Size mismatch for u32: {}", value);
    }
}

#[test]
fn test_encoded_size_matches_actual_u64() {
    let test_values = [0u64, 1, 127, 128, u64::MAX];

    for value in test_values {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len(),
                  "Size mismatch for u64: {}", value);
    }
}

#[test]
fn test_encoded_size_matches_actual_i32() {
    let test_values = [i32::MIN, -1, 0, 1, i32::MAX];

    for value in test_values {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len(),
                  "Size mismatch for i32: {}", value);
    }
}

#[test]
fn test_encoded_size_matches_actual_i64() {
    let test_values = [i64::MIN, -1, 0, 1, i64::MAX];

    for value in test_values {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len(),
                  "Size mismatch for i64: {}", value);
    }
}

#[test]
fn test_encoded_size_matches_actual_bool() {
    for value in [true, false] {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len());
        assert_eq!(buf.len(), 1);
    }
}

#[test]
fn test_encoded_size_matches_actual_f32() {
    let test_values = [0.0f32, -0.0, 1.0, -1.0, f32::INFINITY, f32::MAX];

    for value in test_values {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len());
        assert_eq!(buf.len(), 4);
    }
}

#[test]
fn test_encoded_size_matches_actual_f64() {
    let test_values = [0.0f64, -0.0, 1.0, -1.0, f64::INFINITY, f64::MAX];

    for value in test_values {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        assert_eq!(value.encoded_size(), buf.len());
        assert_eq!(buf.len(), 8);
    }
}

#[test]
fn test_encoded_size_matches_actual_string() {
    let test_strings = [
        "",
        "a",
        "hello",
        &"x".repeat(127),
        &"x".repeat(128),
        &"x".repeat(1000),
        "你好世界",
    ];

    for s in test_strings {
        let mut buf = BytesMut::new();
        s.encode(&mut buf).unwrap();

        assert_eq!(s.encoded_size(), buf.len(),
                  "Size mismatch for string of length {}", s.len());
    }
}

#[test]
fn test_encoded_size_matches_actual_bytes() {
    let test_sizes = [0, 1, 5, 127, 128, 1000];

    for size in test_sizes {
        let bytes = vec![0xAB; size];
        let mut buf = BytesMut::new();
        bytes.encode(&mut buf).unwrap();

        assert_eq!(bytes.encoded_size(), buf.len(),
                  "Size mismatch for bytes of length {}", size);
    }
}

#[test]
fn test_encoded_size_matches_actual_option() {
    let some_value: Option<u32> = Some(42);
    let mut buf = BytesMut::new();
    some_value.encode(&mut buf).unwrap();
    assert_eq!(some_value.encoded_size(), buf.len());

    let none_value: Option<u32> = None;
    buf.clear();
    none_value.encode(&mut buf).unwrap();
    assert_eq!(none_value.encoded_size(), buf.len());
    assert_eq!(buf.len(), 0);
}

#[test]
fn test_encoded_size_matches_actual_vec() {
    let vec = vec![1u32, 2, 3, 4, 5];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(vec.encoded_size(), buf.len());
}

#[test]
fn test_size_consistency_across_types() {
    // Verify that size calculations are consistent
    let value = 12345u32;

    let direct_size = value.encoded_size();

    let mut buf = BytesMut::new();
    value.encode(&mut buf).unwrap();
    let actual_size = buf.len();

    let length_calc = get_varint_length_u32(value);

    assert_eq!(direct_size, actual_size);
    assert_eq!(direct_size, length_calc);
}

#[test]
fn test_varint_length_power_of_two_boundaries() {
    // Test at powers of 2 - 1 (boundary values)
    let test_cases = vec![
        (127u32, 1),     // 2^7 - 1
        (128, 2),        // 2^7
        (16383, 2),      // 2^14 - 1
        (16384, 3),      // 2^14
        (2097151, 3),    // 2^21 - 1
        (2097152, 4),    // 2^21
        (268435455, 4),  // 2^28 - 1
        (268435456, 5),  // 2^28
    ];

    for (value, expected) in test_cases {
        assert_eq!(get_varint_length_u32(value), expected);
    }
}

#[test]
fn test_field_tag_size_max_field_number() {
    // Maximum valid field number is 2^29 - 1 = 536,870,911
    let max_field = 268435455u32;

    let size = field_tag_size(max_field, WireType::Varint);

    // Should be encodable
    assert!(size > 0);
    assert!(size <= 5);
}

#[test]
fn test_size_calculation_complex_message() {
    // Simulate calculating size for a complex message
    let mut total_size = 0;

    // Field 1: u32 value
    total_size += field_tag_size(1, WireType::Varint);
    total_size += 42u32.encoded_size();

    // Field 2: string
    total_size += field_tag_size(2, WireType::LengthDelimited);
    total_size += "hello".encoded_size();

    // Field 3: repeated u32
    let repeated = vec![1u32, 2, 3];
    total_size += count_repeated(&repeated, field_tag_size(3, WireType::Varint));

    assert!(total_size > 0);
}

#[test]
fn test_count_helpers_consistency() {
    let s = "test";
    let bytes = s.as_bytes();

    // These should be equivalent
    let string_size = count_string(s);
    let bytes_size = count_bytes(bytes);

    assert_eq!(string_size, bytes_size);
}
