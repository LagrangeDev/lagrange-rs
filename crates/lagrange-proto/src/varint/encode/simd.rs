#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::varint::num::VarIntTarget;

/// Encodes a varint using SIMD instructions.
///
/// # Safety
///
/// This function is unsafe because it uses SIMD intrinsics and requires SSE2 support.
/// The caller must ensure the target CPU supports SSE2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
#[inline]
pub unsafe fn encode_unsafe<T: VarIntTarget>(num: T) -> ([u8; 16], usize) {
    if T::MAX_VARINT_BYTES <= 5 {
        let stage1 = num.num_to_scalar_stage1();

        let leading = stage1.leading_zeros();
        let unused_bytes = (leading - 1) / 8;
        let bytes_needed = 8 - unused_bytes;

        let msbs = 0x8080808080808080u64;
        let msbmask = 0xFFFFFFFFFFFFFFFF >> ((8 - bytes_needed + 1) * 8 - 1);
        let merged = stage1 | (msbs & msbmask);

        (
            core::mem::transmute::<[u64; 2], [u8; 16]>([merged, 0]),
            bytes_needed as usize,
        )
    } else {
        let stage1: __m128i = core::mem::transmute(num.num_to_vector_stage1());

        let minimum = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xffu8 as i8);
        let exists = _mm_or_si128(_mm_cmpgt_epi8(stage1, _mm_setzero_si128()), minimum);
        let bits = _mm_movemask_epi8(exists);

        let bytes = 32 - bits.leading_zeros() as usize;

        let ascend = _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        let mask = _mm_cmplt_epi8(ascend, _mm_set1_epi8(bytes as i8));

        let shift = _mm_bsrli_si128(mask, 1);
        let msbmask = _mm_and_si128(shift, _mm_set1_epi8(0x80u8 as i8));

        let merged = _mm_or_si128(stage1, msbmask);

        (core::mem::transmute::<__m128i, [u8; 16]>(merged), bytes)
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn encode_simd<T: VarIntTarget>(num: T) -> ([u8; 16], usize) {
    unsafe { encode_unsafe(num) }
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn encode_to_slice_simd<T: VarIntTarget>(num: T, slice: &mut [u8]) -> usize {
    let (data, size) = encode_simd(num);
    slice[..size].copy_from_slice(&data[..size]);
    size
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn encode_zigzag_simd<T: VarIntTarget>(num: T::Signed) -> ([u8; 16], usize)
where
    T::Signed: crate::varint::num::SignedVarIntTarget<Unsigned = T>,
{
    let unsigned = T::zigzag(num);
    encode_simd(unsigned)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn encode_simd<T: VarIntTarget>(num: T) -> ([u8; 16], usize) {
    super::encode(num)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn encode_to_slice_simd<T: VarIntTarget>(num: T, slice: &mut [u8]) -> usize {
    super::encode_to_slice(num, slice)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn encode_zigzag_simd<T: VarIntTarget>(num: T::Signed) -> ([u8; 16], usize)
where
    T::Signed: crate::varint::num::SignedVarIntTarget<Unsigned = T>,
{
    let unsigned = T::zigzag(num);
    super::encode(unsigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simd_u32() {
        let test_values = [0u32, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX];

        for &val in &test_values {
            let (simd_buf, simd_len) = encode_simd(val);
            let (scalar_buf, scalar_len) = crate::varint::encode::encode(val);

            assert_eq!(simd_len, scalar_len, "Length mismatch for {}", val);
            assert_eq!(
                &simd_buf[..simd_len],
                &scalar_buf[..scalar_len],
                "Encoding mismatch for {}",
                val
            );
        }
    }

    #[test]
    fn test_encode_simd_u64() {
        let test_values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX];

        for &val in &test_values {
            let (simd_buf, simd_len) = encode_simd(val);
            let (scalar_buf, scalar_len) = crate::varint::encode::encode(val);

            assert_eq!(simd_len, scalar_len, "Length mismatch for {}", val);
            assert_eq!(
                &simd_buf[..simd_len],
                &scalar_buf[..scalar_len],
                "Encoding mismatch for {}",
                val
            );
        }
    }

    #[test]
    fn test_encode_zigzag_simd() {
        let test_values = [0i32, 1, -1, 127, -127, 128, -128, i32::MIN, i32::MAX];

        for &val in &test_values {
            let (simd_buf, simd_len) = encode_zigzag_simd::<u32>(val);

            let unsigned = crate::varint::zigzag_encode_i32(val);
            let (scalar_buf, scalar_len) = crate::varint::encode::encode(unsigned);

            assert_eq!(simd_len, scalar_len, "Length mismatch for {}", val);
            assert_eq!(
                &simd_buf[..simd_len],
                &scalar_buf[..scalar_len],
                "ZigZag encoding mismatch for {}",
                val
            );
        }
    }

    #[test]
    fn test_roundtrip_simd() {
        let test_values = [0u32, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX];

        for &val in &test_values {
            let (buf, len) = encode_simd(val);
            let (decoded, dec_len) = crate::varint::decode::decode::<u32>(&buf[..len]).unwrap();

            assert_eq!(decoded, val, "Roundtrip failed for {}", val);
            assert_eq!(dec_len, len, "Length mismatch in roundtrip for {}", val);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_stage1_and_msb_application() {
        let val = 300u32;

        let _stage1 = val.num_to_scalar_stage1();

        let (buf, len) = encode_simd(val);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0xAC);
        assert_eq!(buf[1], 0x02);
    }
}
