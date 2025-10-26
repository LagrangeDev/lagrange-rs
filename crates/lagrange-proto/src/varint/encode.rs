
use crate::varint::num::{VarIntTarget, SignedVarIntTarget};

pub mod simd;

#[inline(always)]
pub fn encode<T: VarIntTarget>(value: T) -> ([u8; 16], usize) {
    let mut buf = [0u8; 16];
    let len = value.encode_varint(&mut buf);
    (buf, len)
}

#[inline(always)]
pub fn encode_to_slice<T: VarIntTarget>(value: T, slice: &mut [u8]) -> usize {
    value.encode_varint(slice)
}

#[inline]
pub fn encode_zigzag<T: VarIntTarget>(value: T::Signed) -> ([u8; 16], usize)
where
    T::Signed: SignedVarIntTarget<Unsigned = T>,
{
    let unsigned = T::zigzag(value);
    encode(unsigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let (buf, len) = encode(0u32);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0);

        let (buf, len) = encode(127u32);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 127);

        let (buf, len) = encode(128u32);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x01);
    }

    #[test]
    fn test_encode_to_slice() {
        let mut buf = [0u8; 10];
        let len = encode_to_slice(255u32, &mut buf);
        assert_eq!(len, 2);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf[1], 0x01);
    }

    #[test]
    fn test_encode_zigzag() {
        let (buf, len) = encode_zigzag::<u32>(0i32);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 0);

        let (buf, len) = encode_zigzag::<u32>(-1i32);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 1);

        let (buf, len) = encode_zigzag::<u32>(1i32);
        assert_eq!(len, 1);
        assert_eq!(buf[0], 2);
    }
}
