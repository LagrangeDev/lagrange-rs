
use crate::varint::num::{VarIntTarget, SignedVarIntTarget};

pub mod simd;

use crate::error::DecodeError;

#[inline]
pub fn decode<T: VarIntTarget + 'static>(buf: &[u8]) -> Result<(T, usize), DecodeError> {
    T::decode_varint(buf)
}

/// Decode only the length of a varint without fully decoding it.
///
/// This is faster than full decoding when only the length is needed.
#[inline]
pub fn decode_len<T: VarIntTarget>(buf: &[u8]) -> Result<usize, DecodeError> {
    if buf.is_empty() {
        return Err(DecodeError::UnexpectedEof);
    }

    // Count bytes with MSB set (continuation bit)
    for (i, &byte) in buf.iter().enumerate().take(T::MAX_VARINT_BYTES) {
        if byte < 0x80 {
            return Ok(i + 1);
        }
    }

    if buf.len() < T::MAX_VARINT_BYTES {
        Err(DecodeError::UnexpectedEof)
    } else {
        Err(DecodeError::InvalidVarint)
    }
}

/// Decode a varint with ZigZag decoding (for signed integers).
#[inline]
pub fn decode_zigzag<T: VarIntTarget + 'static>(buf: &[u8]) -> Result<(T::Signed, usize), DecodeError>
where
    T::Signed: SignedVarIntTarget<Unsigned = T>,
{
    let (unsigned, len) = decode::<T>(buf)?;
    Ok((unsigned.unzigzag(), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        assert_eq!(decode::<u32>(&[0]).unwrap(), (0, 1));
        assert_eq!(decode::<u32>(&[127]).unwrap(), (127, 1));
        assert_eq!(decode::<u32>(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode::<u32>(&[0xFF, 0x01]).unwrap(), (255, 2));
    }

    #[test]
    fn test_decode_len() {
        assert_eq!(decode_len::<u32>(&[0]).unwrap(), 1);
        assert_eq!(decode_len::<u32>(&[0x80, 0x01]).unwrap(), 2);
        assert_eq!(decode_len::<u32>(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]).unwrap(), 5);
    }

    #[test]
    fn test_decode_zigzag() {
        assert_eq!(decode_zigzag::<u32>(&[0]).unwrap(), (0i32, 1));
        assert_eq!(decode_zigzag::<u32>(&[1]).unwrap(), (-1i32, 1));
        assert_eq!(decode_zigzag::<u32>(&[2]).unwrap(), (1i32, 1));
    }
}
