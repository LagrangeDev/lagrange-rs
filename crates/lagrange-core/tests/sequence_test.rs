#[cfg(test)]
mod sequence_conversion_tests {
    /// Test that u32 -> i32 -> u32 conversion is reversible for all valid sequence values
    #[test]
    fn test_sequence_conversion_roundtrip() {
        // Test normal range (0 to i32::MAX)
        for seq in [0u32, 1, 100, 1000, i32::MAX as u32] {
            let as_i32 = seq as i32;
            let back_to_u32 = as_i32 as u32;
            assert_eq!(
                seq, back_to_u32,
                "Conversion failed for {}: {} -> {} -> {}",
                seq, seq, as_i32, back_to_u32
            );
        }
    }

    #[test]
    fn test_sequence_conversion_overflow_range() {
        // Test values that overflow i32 (i32::MAX + 1 to u32::MAX)
        let test_values = vec![
            (i32::MAX as u32) + 1,  // First overflow value
            (i32::MAX as u32) + 100,
            3_000_000_000u32,
            u32::MAX - 1,
            u32::MAX,
        ];

        for seq in test_values {
            let as_i32 = seq as i32;
            let back_to_u32 = as_i32 as u32;

            println!(
                "Testing overflow: {} (u32) -> {} (i32) -> {} (u32)",
                seq, as_i32, back_to_u32
            );

            assert_eq!(
                seq, back_to_u32,
                "Conversion failed for overflow value {}: {} -> {} -> {}",
                seq, seq, as_i32, back_to_u32
            );
        }
    }

    #[test]
    fn test_negative_i32_to_u32_conversion() {
        // Test that negative i32 values convert correctly to u32
        let test_cases = vec![
            (-1i32, 4294967295u32),
            (-2i32, 4294967294u32),
            (-100i32, 4294967196u32),
            (i32::MIN, 2147483648u32),
        ];

        for (i32_val, expected_u32) in test_cases {
            let result = i32_val as u32;
            assert_eq!(
                result, expected_u32,
                "Negative i32 {} should convert to u32 {}, got {}",
                i32_val, expected_u32, result
            );
        }
    }
}
