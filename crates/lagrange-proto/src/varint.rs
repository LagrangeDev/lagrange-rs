
pub mod num;
pub mod encode;
pub mod decode;

pub const MAX_VARINT_LEN_U8: usize = 2;
pub const MAX_VARINT_LEN_U16: usize = 3;
pub const MAX_VARINT_LEN_U32: usize = 5;
pub const MAX_VARINT_LEN_U64: usize = 10;

pub use encode::{encode, encode_to_slice, encode_zigzag};
pub use decode::{decode, decode_len, decode_zigzag};

#[inline(always)]
pub const fn zigzag_encode_i32(value: i32) -> u32 {
    ((value << 1) ^ (value >> 31)) as u32
}

#[inline(always)]
pub const fn zigzag_decode_i32(value: u32) -> i32 {
    ((value >> 1) as i32) ^ (-((value & 1) as i32))
}

#[inline(always)]
pub const fn zigzag_encode_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

#[inline(always)]
pub const fn zigzag_decode_i64(value: u64) -> i64 {
    ((value >> 1) as i64) ^ (-((value & 1) as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zigzag_encoding() {
        assert_eq!(zigzag_encode_i32(0), 0);
        assert_eq!(zigzag_encode_i32(-1), 1);
        assert_eq!(zigzag_encode_i32(1), 2);
        assert_eq!(zigzag_encode_i32(-2), 3);
        assert_eq!(zigzag_encode_i32(2), 4);

        assert_eq!(zigzag_decode_i32(0), 0);
        assert_eq!(zigzag_decode_i32(1), -1);
        assert_eq!(zigzag_decode_i32(2), 1);
        assert_eq!(zigzag_decode_i32(3), -2);
        assert_eq!(zigzag_decode_i32(4), 2);
    }

    #[test]
    fn test_encoded_len() {
        use crate::helpers::{get_varint_length_u32, get_varint_length_u64};

        assert_eq!(get_varint_length_u32(0), 1);
        assert_eq!(get_varint_length_u32(127), 1);
        assert_eq!(get_varint_length_u32(128), 2);
        assert_eq!(get_varint_length_u32(16383), 2);
        assert_eq!(get_varint_length_u32(16384), 3);
        assert_eq!(get_varint_length_u32(u32::MAX), 5);

        assert_eq!(get_varint_length_u64(0), 1);
        assert_eq!(get_varint_length_u64(127), 1);
        assert_eq!(get_varint_length_u64(128), 2);
        assert_eq!(get_varint_length_u64(u64::MAX), 10);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let test_values = [0u32, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX];

        for &value in &test_values {
            let (buf, len) = encode(value);
            let (decoded, dec_len) = decode::<u32>(&buf[..len]).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(dec_len, len);
        }
    }

    #[test]
    fn test_zigzag_roundtrip() {
        let test_values = [0i32, 1, -1, 127, -127, 128, -128, i32::MIN, i32::MAX];

        for &value in &test_values {
            let (buf, len) = encode_zigzag::<u32>(value);
            let (decoded, dec_len) = decode_zigzag::<u32>(&buf[..len]).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(dec_len, len);
        }
    }

}
