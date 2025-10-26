use crate::error::DecodeError;
use crate::varint::num::VarIntTarget;

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn decode_simd<T: VarIntTarget>(bytes: &[u8]) -> Result<(T, usize), DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }

    let result = if bytes.len() >= 16 {
        unsafe { decode_unsafe::<T>(bytes.as_ptr()) }
    } else {
        let mut data = [0u8; 16];
        let len = bytes.len().min(16);
        data[..len].copy_from_slice(&bytes[..len]);
        unsafe { decode_unsafe::<T>(data.as_ptr()) }
    };

    if result.1 > bytes.len() {
        return Err(DecodeError::UnexpectedEof);
    }

    if result.1 == T::MAX_VARINT_BYTES {
        let last_byte = bytes[T::MAX_VARINT_BYTES - 1];
        if last_byte > T::MAX_LAST_VARINT_BYTE {
            return Err(DecodeError::InvalidVarint);
        }
    } else if result.1 > T::MAX_VARINT_BYTES {
        return Err(DecodeError::InvalidVarint);
    }

    Ok(result)
}

/// Decodes a varint using SIMD instructions.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers without bounds checking
/// - Uses SIMD intrinsics and requires SSE2 support
/// - Assumes at least 16 bytes are accessible from the pointer (caller must ensure this)
///
/// The caller must ensure the pointer is valid and points to at least 16 readable bytes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[inline]
pub unsafe fn decode_unsafe<T: VarIntTarget>(bytes: *const u8) -> (T, usize) {
    if T::MAX_VARINT_BYTES <= 5 {
        let b = bytes.cast::<u64>().read_unaligned();
        let msbs = !b & 0x8080808080808080u64;
        let len = msbs.trailing_zeros() + 1;
        let varint_part = b & (msbs ^ msbs.wrapping_sub(1));

        let num = T::scalar_to_num(varint_part);
        (num, (len / 8) as usize)
    } else {
        let b0 = bytes.cast::<u64>().read_unaligned();
        let b1 = bytes.cast::<u64>().add(1).read_unaligned();

        let msbs0 = !b0 & 0x8080808080808080u64;
        let msbs1 = !b1 & 0x8080808080808080u64;

        let len0 = msbs0.trailing_zeros() + 1;
        let len1 = msbs1.trailing_zeros() + 1;

        let varint_part0 = b0 & (msbs0 ^ msbs0.wrapping_sub(1));

        let varint_part1 = (b1 & (msbs1 ^ msbs1.wrapping_sub(1))) * ((msbs0 == 0) as u64);

        let num = T::vector_to_num(core::mem::transmute::<[u64; 2], [u8; 16]>([
            varint_part0,
            varint_part1,
        ]));

        let len = if msbs0 == 0 { len1 + 64 } else { len0 };

        (num, (len / 8) as usize)
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn decode_len_simd<T: VarIntTarget>(bytes: &[u8]) -> Result<usize, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }

    let len = if bytes.len() >= 16 {
        unsafe { decode_len_unsafe::<T>(bytes.as_ptr()) }
    } else {
        let mut data = [0u8; 16];
        let copy_len = bytes.len().min(16);
        data[..copy_len].copy_from_slice(&bytes[..copy_len]);
        unsafe { decode_len_unsafe::<T>(data.as_ptr()) }
    };

    if len > bytes.len() {
        Err(DecodeError::UnexpectedEof)
    } else if len > T::MAX_VARINT_BYTES {
        Err(DecodeError::InvalidVarint)
    } else {
        Ok(len)
    }
}

/// Decodes the length of a varint using SIMD instructions.
///
/// # Safety
///
/// This function is unsafe because it:
/// - Dereferences raw pointers without bounds checking
/// - Uses SIMD intrinsics and requires SSE2 support
/// - Assumes at least 16 bytes are accessible from the pointer (caller must ensure this)
///
/// The caller must ensure the pointer is valid and points to at least 16 readable bytes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[inline]
pub unsafe fn decode_len_unsafe<T: VarIntTarget>(bytes: *const u8) -> usize {
    if T::MAX_VARINT_BYTES <= 5 {
        let b = bytes.cast::<u64>().read_unaligned();
        let msbs = !b & 0x8080808080808080u64;
        let len = msbs.trailing_zeros() + 1;
        (len / 8) as usize
    } else {
        let b0 = bytes.cast::<u64>().read_unaligned();
        let b1 = bytes.cast::<u64>().add(1).read_unaligned();

        let msbs0 = !b0 & 0x8080808080808080u64;
        let msbs1 = !b1 & 0x8080808080808080u64;

        let len0 = msbs0.trailing_zeros() + 1;
        let len1 = msbs1.trailing_zeros() + 1;

        let len = if msbs0 == 0 { len1 + 64 } else { len0 };
        (len / 8) as usize
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn decode_simd<T: VarIntTarget>(bytes: &[u8]) -> Result<(T, usize), DecodeError> {
    T::decode_varint(bytes)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn decode_len_simd<T: VarIntTarget>(bytes: &[u8]) -> Result<usize, DecodeError> {
    super::decode_len::<T>(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_simd_u32() {
        let test_cases = vec![
            (vec![0], 0u32, 1),
            (vec![1], 1u32, 1),
            (vec![127], 127u32, 1),
            (vec![0x80, 0x01], 128u32, 2),
            (vec![0xFF, 0x01], 255u32, 2),
            (vec![0x80, 0x02], 256u32, 2),
            (vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F], u32::MAX, 5),
        ];

        for (bytes, expected_val, expected_len) in test_cases {
            let mut padded = vec![0u8; 16];
            padded[..bytes.len()].copy_from_slice(&bytes);

            let result = decode_simd::<u32>(&padded).unwrap();
            assert_eq!(result.0, expected_val, "Value mismatch for {:?}", bytes);
            assert_eq!(result.1, expected_len, "Length mismatch for {:?}", bytes);
        }
    }

    #[test]
    fn test_decode_simd_u64() {
        let test_cases = vec![
            (vec![0], 0u64, 1),
            (vec![1], 1u64, 1),
            (vec![127], 127u64, 1),
            (vec![0x80, 0x01], 128u64, 2),
            (
                vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
                u64::MAX,
                10,
            ),
        ];

        for (bytes, expected_val, expected_len) in test_cases {
            let mut padded = vec![0u8; 16];
            padded[..bytes.len()].copy_from_slice(&bytes);

            let result = decode_simd::<u64>(&padded).unwrap();
            assert_eq!(result.0, expected_val, "Value mismatch for {:?}", bytes);
            assert_eq!(result.1, expected_len, "Length mismatch for {:?}", bytes);
        }
    }

    #[test]
    fn test_decode_len_simd() {
        let test_cases = vec![
            (vec![0], 1),
            (vec![0x80, 0x01], 2),
            (vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F], 5),
        ];

        for (bytes, expected_len) in test_cases {
            let mut padded = vec![0u8; 16];
            padded[..bytes.len()].copy_from_slice(&bytes);

            let result = decode_len_simd::<u32>(&padded).unwrap();
            assert_eq!(result, expected_len, "Length mismatch for {:?}", bytes);
        }
    }

    #[test]
    fn test_decode_simd_overflow() {
        let bytes = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x10];
        let mut padded = vec![0u8; 16];
        padded[..bytes.len()].copy_from_slice(&bytes);

        let result = decode_simd::<u32>(&padded);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_simd_roundtrip() {
        let test_values = [0u32, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX];

        for &val in &test_values {
            let (buf, len) = crate::varint::encode::simd::encode_simd(val);
            let (decoded, dec_len) = decode_simd::<u32>(&buf[..16]).unwrap();

            assert_eq!(decoded, val, "Roundtrip failed for {}", val);
            assert_eq!(dec_len, len, "Length mismatch in roundtrip for {}", val);
        }
    }
}
