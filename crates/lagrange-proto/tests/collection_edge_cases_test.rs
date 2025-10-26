use bytes::{Bytes, BytesMut};
use lagrange_proto::*;

#[test]
fn test_empty_vec_u32() {
    let vec: Vec<u32> = vec![];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 0);
    assert_eq!(vec.encoded_size(), 0);
}

#[test]
fn test_single_element_vec() {
    let vec = vec![42u32];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // Vec encoding just encodes each element
    assert_eq!(buf.len(), 1);
}

#[test]
fn test_large_vec() {
    let vec: Vec<u32> = (0..10000).collect();
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert!(!buf.is_empty());
}

#[test]
fn test_vec_of_strings() {
    let vec = vec!["hello".to_string(), "world".to_string(), "test".to_string()];

    let size = vec.encoded_size();
    assert!(size > 0);
}

#[test]
fn test_vec_alternating_small_large() {
    let vec = vec![1u32, u32::MAX, 2, u32::MAX - 1, 3];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(vec.encoded_size(), buf.len());
}

#[test]
fn test_option_none_u32() {
    let opt: Option<u32> = None;
    let mut buf = BytesMut::new();
    opt.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 0);
    assert_eq!(opt.encoded_size(), 0);
}

#[test]
fn test_option_some_u32() {
    let opt = Some(42u32);
    let mut buf = BytesMut::new();
    opt.encode(&mut buf).unwrap();

    assert_eq!(buf[0], 42);
    assert_eq!(opt.encoded_size(), 1);
}

#[test]
fn test_option_some_string() {
    let opt = Some("hello".to_string());
    let mut buf = BytesMut::new();
    opt.encode(&mut buf).unwrap();

    assert_eq!(opt.encoded_size(), buf.len());
    assert!(buf.len() > 5); // At least length prefix + data
}

#[test]
fn test_option_none_string() {
    let opt: Option<String> = None;
    let mut buf = BytesMut::new();
    opt.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 0);
}

#[test]
fn test_nested_option() {
    // Option<Option<T>> is valid
    let nested: Option<Option<u32>> = Some(Some(42));
    let size = nested.encoded_size();
    assert_eq!(size, 1); // Inner Some(42) encodes to 1 byte
}

#[test]
fn test_option_large_value() {
    let opt = Some(u64::MAX);
    let mut buf = BytesMut::new();
    opt.encode(&mut buf).unwrap();

    assert_eq!(opt.encoded_size(), 10); // Max varint length for u64
}

#[test]
fn test_bytes_empty() {
    let bytes = Bytes::new();
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1); // Just length prefix of 0
    assert_eq!(buf[0], 0);
}

#[test]
fn test_bytes_small() {
    let bytes = Bytes::from(vec![1, 2, 3, 4, 5]);
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 6); // 1 byte length + 5 bytes data
    assert_eq!(buf[0], 5);
    assert_eq!(&buf[1..], &[1, 2, 3, 4, 5]);
}

#[test]
fn test_bytes_large() {
    let data = vec![0xAB; 10000];
    let bytes = Bytes::from(data);
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    // Length is 10000, which is 0x2710, requiring 2 bytes in varint
    assert!(buf.len() > 10000);
    assert_eq!(bytes.encoded_size(), buf.len());
}

#[test]
fn test_bytes_roundtrip() {
    let original = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let mut buf = BytesMut::new();
    original.encode(&mut buf).unwrap();

    let decoded = Bytes::decode(&buf).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn test_bytesmut_empty() {
    let bytes = BytesMut::new();
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1);
    assert_eq!(buf[0], 0);
}

#[test]
fn test_bytesmut_with_data() {
    let mut bytes = BytesMut::new();
    bytes.extend_from_slice(&[1, 2, 3, 4, 5]);

    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 6);
    assert_eq!(buf[0], 5);
}

#[test]
fn test_vec_u8_empty() {
    let vec: Vec<u8> = vec![];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1);
    assert_eq!(buf[0], 0);
}

#[test]
fn test_vec_u8_with_data() {
    let vec = vec![1u8, 2, 3, 4, 5];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 6);
    assert_eq!(buf[0], 5);
    assert_eq!(&buf[1..], &[1, 2, 3, 4, 5]);
}

#[test]
fn test_vec_u8_large() {
    let vec = vec![0xFF; 20000];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert!(buf.len() > 20000);

    let decoded = Vec::<u8>::decode(&buf).unwrap();
    assert_eq!(decoded, vec);
}

#[test]
fn test_slice_u8_encoding() {
    let data: &[u8] = &[1, 2, 3, 4, 5];
    let mut buf = BytesMut::new();
    data.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 6);
    assert_eq!(data.encoded_size(), 6);
}

#[test]
fn test_string_empty() {
    let s = String::new();
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 1);
    assert_eq!(buf[0], 0);
    assert_eq!(s.encoded_size(), 1);
}

#[test]
fn test_string_single_char() {
    let s = "a".to_string();
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 2);
    assert_eq!(buf[0], 1);
    assert_eq!(buf[1], b'a');
}

#[test]
fn test_string_unicode() {
    let s = "你好世界".to_string(); // 4 Chinese characters
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_string_emoji() {
    let s = "😀😃😄😁".to_string();
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_string_mixed_unicode() {
    let s = "Hello 你好 🌍".to_string();
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_string_rtl_text() {
    let s = "مرحبا بالعالم".to_string(); // Arabic (RTL)
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_string_zero_width_joiner() {
    let s = "👨‍👩‍👧‍👦".to_string(); // Family emoji with zero-width joiners
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_string_length_boundary_127() {
    let s = "x".repeat(127);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    // 127 + 1 byte for length
    assert_eq!(buf.len(), 128);
    assert_eq!(buf[0], 127);

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 127);
}

#[test]
fn test_string_length_boundary_128() {
    let s = "x".repeat(128);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    // 128 + 2 bytes for length (varint encoding)
    assert_eq!(buf.len(), 130);

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 128);
}

#[test]
fn test_str_slice_encoding() {
    let s: &str = "hello world";
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    assert_eq!(s.encoded_size(), buf.len());
    assert_eq!(buf[0], 11); // Length
}

#[test]
fn test_vec_bool() {
    let vec = vec![true, false, true, true, false];
    let size = vec.encoded_size();

    // Each bool is 1 byte
    assert_eq!(size, 5);
}

#[test]
fn test_vec_i32() {
    let vec = vec![-100i32, -1, 0, 1, 100];
    let size = vec.encoded_size();

    // Each value uses zigzag encoding
    assert!(size > 0);
}

#[test]
fn test_vec_i64() {
    let vec = vec![i64::MIN, -1, 0, 1, i64::MAX];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(vec.encoded_size(), buf.len());
}

#[test]
fn test_vec_with_max_values() {
    let vec = vec![u64::MAX; 100];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // Each u64::MAX is 10 bytes
    assert_eq!(buf.len(), 1000);
}

#[test]
fn test_bytes_at_length_boundaries() {
    let test_sizes = [0, 1, 127, 128, 255, 256, 16383, 16384];

    for size in test_sizes {
        let data = vec![0xAB; size];
        let bytes = Bytes::from(data);
        let mut buf = BytesMut::new();
        bytes.encode(&mut buf).unwrap();

        assert_eq!(bytes.encoded_size(), buf.len());

        let decoded = Bytes::decode(&buf).unwrap();
        assert_eq!(decoded.len(), size);
    }
}

#[test]
fn test_string_at_length_boundaries() {
    let test_sizes = [0, 1, 127, 128, 255, 256, 16383, 16384];

    for size in test_sizes {
        let s = "x".repeat(size);
        let mut buf = BytesMut::new();
        s.encode(&mut buf).unwrap();

        assert_eq!(s.encoded_size(), buf.len());

        let decoded = String::decode(&buf).unwrap();
        assert_eq!(decoded.len(), size);
    }
}

#[test]
fn test_option_vec() {
    let opt: Option<Vec<u32>> = Some(vec![1, 2, 3]);
    let size = opt.encoded_size();

    // Should encode the vec
    assert!(size > 0);

    let opt_none: Option<Vec<u32>> = None;
    let size_none = opt_none.encoded_size();
    assert_eq!(size_none, 0);
}

#[test]
fn test_vec_of_options() {
    let vec = vec![Some(1u32), None, Some(3), Some(4), None];

    // Each Some encodes to value size, None encodes to 0
    let size = vec.encoded_size();
    assert_eq!(size, 3); // Three Some values, each 1 byte
}

#[test]
fn test_vec_of_vec() {
    let vec = vec![vec![1u32, 2, 3], vec![4, 5], vec![6, 7, 8, 9]];

    let size = vec.encoded_size();
    assert!(size > 0);
}

#[test]
fn test_bytes_all_byte_values() {
    // Test all possible byte values
    let data: Vec<u8> = (0..=255).collect();
    let bytes = Bytes::from(data);
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    let decoded = Bytes::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 256);

    for i in 0..=255u8 {
        assert_eq!(decoded[i as usize], i);
    }
}

#[test]
fn test_string_combining_characters() {
    let s = "e\u{0301}".to_string(); // e with combining acute accent
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_string_special_whitespace() {
    let s = "hello\t\n\r\x0Bworld".to_string();
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_vec_single_max_value() {
    let vec = vec![u64::MAX];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(buf.len(), 10); // u64::MAX is 10 bytes in varint
}

#[test]
fn test_collection_size_accuracy() {
    // Verify encoded_size matches actual encoding for all collection types
    let test_cases: Vec<Box<dyn Fn()>> = vec![
        Box::new(|| {
            let vec = vec![1u32, 2, 3];
            let mut buf = BytesMut::new();
            vec.encode(&mut buf).unwrap();
            assert_eq!(vec.encoded_size(), buf.len());
        }),
        Box::new(|| {
            let s = "test string".to_string();
            let mut buf = BytesMut::new();
            s.encode(&mut buf).unwrap();
            assert_eq!(s.encoded_size(), buf.len());
        }),
        Box::new(|| {
            let bytes = Bytes::from(vec![1, 2, 3, 4, 5]);
            let mut buf = BytesMut::new();
            bytes.encode(&mut buf).unwrap();
            assert_eq!(bytes.encoded_size(), buf.len());
        }),
    ];

    for test in test_cases {
        test();
    }
}
