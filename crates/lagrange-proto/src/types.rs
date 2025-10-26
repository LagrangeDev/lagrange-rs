use crate::decoding::ProtoDecode;
use crate::encoding::ProtoEncode;
use crate::error::{DecodeError, EncodeError};
use crate::varint;
use bytes::BufMut;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SInt32(pub i32);

impl From<i32> for SInt32 {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<SInt32> for i32 {
    fn from(value: SInt32) -> Self {
        value.0
    }
}

impl ProtoEncode for SInt32 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode_zigzag::<u32>(self.0);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        let unsigned = varint::zigzag_encode_i32(self.0);
        crate::helpers::get_varint_length_u32(unsigned)
    }
}

impl ProtoDecode for SInt32 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode_zigzag::<u32>(buf)?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SInt64(pub i64);

impl From<i64> for SInt64 {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<SInt64> for i64 {
    fn from(value: SInt64) -> Self {
        value.0
    }
}

impl ProtoEncode for SInt64 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode_zigzag::<u64>(self.0);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        let unsigned = varint::zigzag_encode_i64(self.0);
        crate::helpers::get_varint_length_u64(unsigned)
    }
}

impl ProtoDecode for SInt64 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode_zigzag::<u64>(buf)?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fixed32(pub u32);

impl From<u32> for Fixed32 {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Fixed32> for u32 {
    fn from(value: Fixed32) -> Self {
        value.0
    }
}

impl ProtoEncode for Fixed32 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        buf.put_u32_le(self.0);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        4
    }
}

impl ProtoDecode for Fixed32 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = [buf[0], buf[1], buf[2], buf[3]];
        Ok(Self(u32::from_le_bytes(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fixed64(pub u64);

impl From<u64> for Fixed64 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Fixed64> for u64 {
    fn from(value: Fixed64) -> Self {
        value.0
    }
}

impl ProtoEncode for Fixed64 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        buf.put_u64_le(self.0);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        8
    }
}

impl ProtoDecode for Fixed64 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 8 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];
        Ok(Self(u64::from_le_bytes(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SFixed32(pub i32);

impl From<i32> for SFixed32 {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<SFixed32> for i32 {
    fn from(value: SFixed32) -> Self {
        value.0
    }
}

impl ProtoEncode for SFixed32 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        buf.put_i32_le(self.0);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        4
    }
}

impl ProtoDecode for SFixed32 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = [buf[0], buf[1], buf[2], buf[3]];
        Ok(Self(i32::from_le_bytes(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SFixed64(pub i64);

impl From<i64> for SFixed64 {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<SFixed64> for i64 {
    fn from(value: SFixed64) -> Self {
        value.0
    }
}

impl ProtoEncode for SFixed64 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        buf.put_i64_le(self.0);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        8
    }
}

impl ProtoDecode for SFixed64 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 8 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ];
        Ok(Self(i64::from_le_bytes(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_sint32_roundtrip() {
        let values = [i32::MIN, -1000, -1, 0, 1, 1000, i32::MAX];
        for &val in &values {
            let sint = SInt32(val);
            let mut buf = BytesMut::new();
            sint.encode(&mut buf).unwrap();
            let decoded = SInt32::decode(&buf).unwrap();
            assert_eq!(sint, decoded);
        }
    }

    #[test]
    fn test_sint64_roundtrip() {
        let values = [i64::MIN, -1000, -1, 0, 1, 1000, i64::MAX];
        for &val in &values {
            let sint = SInt64(val);
            let mut buf = BytesMut::new();
            sint.encode(&mut buf).unwrap();
            let decoded = SInt64::decode(&buf).unwrap();
            assert_eq!(sint, decoded);
        }
    }

    #[test]
    fn test_fixed32_roundtrip() {
        let values = [0u32, 1, 1000, u32::MAX];
        for &val in &values {
            let fixed = Fixed32(val);
            let mut buf = BytesMut::new();
            fixed.encode(&mut buf).unwrap();
            assert_eq!(buf.len(), 4);
            let decoded = Fixed32::decode(&buf).unwrap();
            assert_eq!(fixed, decoded);
        }
    }

    #[test]
    fn test_fixed64_roundtrip() {
        let values = [0u64, 1, 1000, u64::MAX];
        for &val in &values {
            let fixed = Fixed64(val);
            let mut buf = BytesMut::new();
            fixed.encode(&mut buf).unwrap();
            assert_eq!(buf.len(), 8);
            let decoded = Fixed64::decode(&buf).unwrap();
            assert_eq!(fixed, decoded);
        }
    }

    #[test]
    fn test_sfixed32_roundtrip() {
        let values = [i32::MIN, -1000, -1, 0, 1, 1000, i32::MAX];
        for &val in &values {
            let sfixed = SFixed32(val);
            let mut buf = BytesMut::new();
            sfixed.encode(&mut buf).unwrap();
            assert_eq!(buf.len(), 4);
            let decoded = SFixed32::decode(&buf).unwrap();
            assert_eq!(sfixed, decoded);
        }
    }

    #[test]
    fn test_sfixed64_roundtrip() {
        let values = [i64::MIN, -1000, -1, 0, 1, 1000, i64::MAX];
        for &val in &values {
            let sfixed = SFixed64(val);
            let mut buf = BytesMut::new();
            sfixed.encode(&mut buf).unwrap();
            assert_eq!(buf.len(), 8);
            let decoded = SFixed64::decode(&buf).unwrap();
            assert_eq!(sfixed, decoded);
        }
    }

    #[test]
    fn test_size_calculations() {
        assert!(SInt32(0).encoded_size() < Fixed32(0).encoded_size());
        assert!(SInt32(100).encoded_size() < Fixed32(100).encoded_size());

        assert_eq!(Fixed32(0).encoded_size(), 4);
        assert_eq!(Fixed64(0).encoded_size(), 8);
        assert_eq!(SFixed32(0).encoded_size(), 4);
        assert_eq!(SFixed64(0).encoded_size(), 8);
    }
}
