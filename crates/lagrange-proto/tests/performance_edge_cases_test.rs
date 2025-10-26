use bytes::BytesMut;
use lagrange_proto::*;

#[test]
fn test_large_vec_u32() {
    // 100k elements
    let vec: Vec<u32> = (0..100_000).collect();
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert!(!buf.is_empty());
    assert_eq!(vec.encoded_size(), buf.len());
}

#[test]
fn test_large_vec_u64() {
    // 50k elements of u64
    let vec: Vec<u64> = (0..50_000).collect();
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert!(!buf.is_empty());
}

#[test]
fn test_very_large_string() {
    // 1 MB string
    let s = "x".repeat(1_000_000);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 1_000_000);
}

#[test]
fn test_very_large_bytes() {
    // 1 MB of bytes (single Vec<u8> encodes as length + data)
    let bytes = vec![0xAB; 1_000_000];
    let mut buf = BytesMut::new();
    bytes.encode(&mut buf).unwrap();

    let decoded = Vec::<u8>::decode(&buf).unwrap();
    assert_eq!(decoded, bytes);
    assert_eq!(decoded.len(), 1_000_000);
}

#[test]
fn test_many_small_strings() {
    // 10k small strings
    let strings: Vec<String> = (0..10_000).map(|i| format!("string_{}", i)).collect();

    let size = strings.encoded_size();
    assert!(size > 0);
}

#[test]
fn test_many_max_u64_values() {
    // Each u64::MAX is 10 bytes
    let vec = vec![u64::MAX; 10_000];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // 10k * 10 bytes = 100k bytes
    assert_eq!(buf.len(), 100_000);
}

#[test]
fn test_alternating_small_large_values() {
    // Alternate between small and large values
    let mut vec = Vec::new();
    for i in 0..10_000 {
        if i % 2 == 0 {
            vec.push(1u32);
        } else {
            vec.push(u32::MAX);
        }
    }

    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(vec.encoded_size(), buf.len());
}

#[test]
fn test_deep_option_nesting() {
    // Create deeply nested Options
    let opt = Some(Some(Some(Some(Some(42u32)))));

    let size = opt.encoded_size();
    assert_eq!(size, 1); // Innermost value is 1 byte
}

#[test]
fn test_many_empty_strings() {
    let strings = vec![String::new(); 10_000];
    let size = strings.encoded_size();

    // Each empty string still needs to be encoded (even if empty)
    // The encoding depends on how Vec<String> is implemented
    // Just verify the size calculation doesn't panic
    let _ = size;
}

#[test]
fn test_many_none_options() {
    let options: Vec<Option<u32>> = vec![None; 10_000];
    let size = options.encoded_size();

    // All None values encode to 0 bytes
    assert_eq!(size, 0);
}

#[test]
fn test_unicode_heavy_string() {
    // String with lots of multi-byte Unicode characters
    let s = "你好世界🌍".repeat(10_000);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_consecutive_varint_encoding_performance() {
    // Encode 100k consecutive integers
    let mut buf = BytesMut::new();

    for i in 0..100_000u32 {
        i.encode(&mut buf).unwrap();
    }

    assert!(buf.len() > 100_000);
}

#[test]
fn test_large_bytes_buffer_roundtrip() {
    // 10 MB buffer
    let original = bytes::Bytes::from(vec![0x42; 10_000_000]);
    let mut buf = BytesMut::new();
    original.encode(&mut buf).unwrap();

    let decoded = bytes::Bytes::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 10_000_000);
}

#[test]
fn test_varint_worst_case_all_max() {
    // All maximum values (worst case for varint)
    let vec = vec![u32::MAX; 20_000];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // Each u32::MAX is 5 bytes
    assert_eq!(buf.len(), 100_000);
}

#[test]
fn test_varint_best_case_all_zero() {
    // All zeros (best case for varint)
    let vec = vec![0u32; 20_000];
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // Each 0 is 1 byte
    assert_eq!(buf.len(), 20_000);
}

#[test]
fn test_mixed_size_strings() {
    let mut strings = Vec::new();

    // Mix of different sized strings
    for i in 0..1_000 {
        if i % 3 == 0 {
            strings.push(String::new());
        } else if i % 3 == 1 {
            strings.push("x".repeat(10));
        } else {
            strings.push("x".repeat(1000));
        }
    }

    let size = strings.encoded_size();
    assert!(size > 0);
}

#[test]
fn test_repeated_zigzag_encoding() {
    // Many negative values (uses zigzag)
    let vec: Vec<i32> = (-10_000..0).collect();
    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert!(!buf.is_empty());
}

#[test]
fn test_large_bool_array() {
    let bools = vec![true; 50_000];
    let mut buf = BytesMut::new();
    bools.encode(&mut buf).unwrap();

    // Each bool is 1 byte
    assert_eq!(buf.len(), 50_000);
}

#[test]
fn test_large_float_array() {
    let floats = vec![std::f32::consts::PI; 25_000];
    let mut buf = BytesMut::new();
    floats.encode(&mut buf).unwrap();

    // Each f32 is 4 bytes
    assert_eq!(buf.len(), 100_000);
}

#[test]
fn test_large_double_array() {
    let doubles = vec![std::f64::consts::PI; 12_500];
    let mut buf = BytesMut::new();
    doubles.encode(&mut buf).unwrap();

    // Each f64 is 8 bytes
    assert_eq!(buf.len(), 100_000);
}

#[test]
fn test_string_length_at_boundaries_bulk() {
    // Test many strings at various length boundaries
    let lengths = vec![0, 1, 127, 128, 255, 256, 16383, 16384];

    for len in lengths {
        let s = "x".repeat(len);
        let mut buf = BytesMut::new();
        s.encode(&mut buf).unwrap();

        let decoded = String::decode(&buf).unwrap();
        assert_eq!(decoded.len(), len);
    }
}

#[test]
fn test_bytes_length_at_boundaries_bulk() {
    let lengths = vec![0, 1, 127, 128, 255, 256, 16383, 16384];

    for len in lengths {
        let bytes = vec![0xAB; len];
        let mut buf = BytesMut::new();
        bytes.encode(&mut buf).unwrap();

        let decoded = Vec::<u8>::decode(&buf).unwrap();
        assert_eq!(decoded, bytes);
        assert_eq!(decoded.len(), len);
    }
}

#[test]
fn test_encode_decode_cycle_stability() {
    // Encode and decode many times, should remain stable
    let mut value = 12345u32;

    for _ in 0..1000 {
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();
        value = u32::decode(&buf).unwrap();
    }

    assert_eq!(value, 12345);
}

#[test]
fn test_size_calculation_performance() {
    // Calculate sizes for many values without encoding
    let vec: Vec<u32> = (0..100_000).collect();

    let size = vec.encoded_size();

    // Verify it's correct
    assert!(size > 0);
}

#[test]
fn test_buffer_reuse() {
    // Reuse same buffer for multiple encodings
    let mut buf = BytesMut::new();

    for i in 0..10_000u32 {
        buf.clear();
        i.encode(&mut buf).unwrap();

        let decoded = u32::decode(&buf).unwrap();
        assert_eq!(decoded, i);
    }
}

#[test]
fn test_large_option_vec() {
    // Large Vec of Options
    let vec: Vec<Option<u32>> = (0..50_000)
        .map(|i| if i % 2 == 0 { Some(i) } else { None })
        .collect();

    let size = vec.encoded_size();
    assert!(size > 0);
}

#[test]
fn test_no_panic_on_large_data() {
    // Ensure no panics with large data
    let s = "x".repeat(5_000_000); // 5MB string
    let mut buf = BytesMut::new();

    // Should not panic
    let result = s.encode(&mut buf);
    assert!(result.is_ok());
}

#[test]
fn test_varint_decode_performance_bulk() {
    // Decode many varints
    let mut buf = BytesMut::new();

    for i in 0..100_000u32 {
        i.encode(&mut buf).unwrap();
    }

    // Now decode them all
    let mut offset = 0;
    for i in 0..100_000u32 {
        let (value, len) = lagrange_proto::varint::decode::<u32>(&buf[offset..]).unwrap();
        assert_eq!(value, i);
        offset += len;
    }
}

#[test]
fn test_zigzag_performance_bulk() {
    // Encode and decode many zigzag values
    for i in -50_000..50_000i32 {
        let (buf, len) = lagrange_proto::varint::encode_zigzag::<u32>(i);
        let (decoded, _) = lagrange_proto::varint::decode_zigzag::<u32>(&buf[..len]).unwrap();
        assert_eq!(decoded, i);
    }
}

#[test]
fn test_many_small_messages() {
    // Simulate encoding many small messages
    for i in 0..10_000 {
        let value = i as u32;
        let mut buf = BytesMut::new();
        value.encode(&mut buf).unwrap();

        let decoded = u32::decode(&buf).unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn test_memory_efficiency_repeated_values() {
    // Same value repeated many times
    let vec = vec![42u32; 100_000];

    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    // All values are 1 byte each
    assert_eq!(buf.len(), 100_000);
}

#[test]
fn test_string_with_many_unicode_chars() {
    // Each emoji is 4 bytes
    let s = "😀".repeat(10_000);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn test_nested_vec_of_vec() {
    // Vec of Vec
    let outer: Vec<Vec<u32>> = (0..1_000).map(|i| vec![i, i + 1, i + 2]).collect();

    let size = outer.encoded_size();
    assert!(size > 0);
}

#[test]
fn test_alternating_types_encoded_size() {
    // Calculate sizes for different types quickly
    let count = 10_000;

    for i in 0..count {
        let _u32_size = (i as u32).encoded_size();
        let _u64_size = (i as u64).encoded_size();
        let _bool_size = (i % 2 == 0).encoded_size();
    }

    // Just ensure it completes without panic
}

#[test]
fn test_max_length_string_roundtrip() {
    // Test a very large string (10MB)
    let s = "a".repeat(10_000_000);
    let mut buf = BytesMut::new();
    s.encode(&mut buf).unwrap();

    let decoded = String::decode(&buf).unwrap();
    assert_eq!(decoded.len(), 10_000_000);
}

#[test]
fn test_sparse_large_values() {
    // Mostly small values with occasional large ones
    let mut vec = Vec::new();
    for i in 0..10_000 {
        if i % 1000 == 0 {
            vec.push(u64::MAX);
        } else {
            vec.push(i as u64);
        }
    }

    let mut buf = BytesMut::new();
    vec.encode(&mut buf).unwrap();

    assert_eq!(vec.encoded_size(), buf.len());
}
