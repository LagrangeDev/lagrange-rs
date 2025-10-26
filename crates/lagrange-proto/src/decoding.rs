
use crate::error::DecodeError;
use crate::varint;
use crate::wire::{decode_key, WireType};
use bytes::Bytes;

pub trait ProtoDecode: Sized {
    
    fn decode(buf: &[u8]) -> Result<Self, DecodeError>;

    fn merge(&mut self, buf: &[u8]) -> Result<(), DecodeError> {
        let decoded = Self::decode(buf)?;
        *self = decoded;
        Ok(())
    }
}

#[inline]
pub fn decode_field_key(buf: &[u8]) -> Result<(u32, WireType, usize), DecodeError> {
    let (key, len) = varint::decode::<u32>(buf)?;
    let (tag, wire_type) = decode_key(key)?;
    Ok((tag, wire_type, len))
}

#[inline]
pub fn skip_field(wire_type: WireType, buf: &[u8]) -> Result<usize, DecodeError> {
    match wire_type {
        WireType::Varint => {
            let (_, len) = varint::decode::<u64>(buf)?;
            Ok(len)
        }
        WireType::Fixed64 => {
            if buf.len() < 8 {
                Err(DecodeError::UnexpectedEof)
            } else {
                Ok(8)
            }
        }
        WireType::Fixed32 => {
            if buf.len() < 4 {
                Err(DecodeError::UnexpectedEof)
            } else {
                Ok(4)
            }
        }
        WireType::LengthDelimited => {
            let (len, varint_len) = varint::decode::<u32>(buf)?;
            let total_len = varint_len + len as usize;
            if buf.len() < total_len {
                Err(DecodeError::UnexpectedEof)
            } else {
                Ok(total_len)
            }
        }
        WireType::StartGroup | WireType::EndGroup => {
            
            Err(DecodeError::Custom("Groups are not supported".to_string()))
        }
    }
}

impl ProtoDecode for u32 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode::<u32>(buf)?;
        Ok(value)
    }
}

impl ProtoDecode for u64 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode::<u64>(buf)?;
        Ok(value)
    }
}

impl ProtoDecode for i32 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode_zigzag::<u32>(buf)?;
        Ok(value)
    }
}

impl ProtoDecode for i64 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode_zigzag::<u64>(buf)?;
        Ok(value)
    }
}

impl ProtoDecode for bool {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (value, _) = varint::decode::<u64>(buf)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidBool(value)),
        }
    }
}

impl ProtoDecode for f32 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = [buf[0], buf[1], buf[2], buf[3]];
        Ok(f32::from_le_bytes(bytes))
    }
}

impl ProtoDecode for f64 {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < 8 {
            return Err(DecodeError::UnexpectedEof);
        }
        let bytes = [buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
        Ok(f64::from_le_bytes(bytes))
    }
}

impl ProtoDecode for String {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (len, varint_len) = varint::decode::<u32>(buf)?;
        let len = len as usize;

        if buf.len() < varint_len + len {
            return Err(DecodeError::UnexpectedEof);
        }

        let bytes = &buf[varint_len..varint_len + len];
        String::from_utf8(bytes.to_vec()).map_err(DecodeError::InvalidUtf8)
    }
}

impl ProtoDecode for Vec<u8> {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (len, varint_len) = varint::decode::<u32>(buf)?;
        let len = len as usize;

        if buf.len() < varint_len + len {
            return Err(DecodeError::UnexpectedEof);
        }

        let bytes = &buf[varint_len..varint_len + len];
        Ok(bytes.to_vec())
    }
}

impl ProtoDecode for Bytes {
    #[inline]
    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let (len, varint_len) = varint::decode::<u32>(buf)?;
        let len = len as usize;

        if buf.len() < varint_len + len {
            return Err(DecodeError::UnexpectedEof);
        }

        let bytes = &buf[varint_len..varint_len + len];
        Ok(Bytes::copy_from_slice(bytes))
    }
}

#[inline]
pub fn decode_length_delimited(buf: &[u8]) -> Result<(&[u8], usize), DecodeError> {
    let (len, varint_len) = varint::decode::<u32>(buf)?;
    let len = len as usize;

    if buf.len() < varint_len + len {
        return Err(DecodeError::UnexpectedEof);
    }

    let data = &buf[varint_len..varint_len + len];
    Ok((data, varint_len + len))
}

#[inline]
pub fn decode_varint_field(buf: &[u8]) -> Result<(u64, usize), DecodeError> {
    varint::decode::<u64>(buf)
}

#[inline]
pub fn decode_fixed32_field(buf: &[u8]) -> Result<(u32, usize), DecodeError> {
    if buf.len() < 4 {
        return Err(DecodeError::UnexpectedEof);
    }
    let bytes = [buf[0], buf[1], buf[2], buf[3]];
    Ok((u32::from_le_bytes(bytes), 4))
}

#[inline]
pub fn decode_fixed64_field(buf: &[u8]) -> Result<(u64, usize), DecodeError> {
    if buf.len() < 8 {
        return Err(DecodeError::UnexpectedEof);
    }
    let bytes = [buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]];
    Ok((u64::from_le_bytes(bytes), 8))
}

pub struct FieldReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FieldReader<'a> {
    
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Check if there's more data to read.
    #[inline]
    pub fn has_remaining(&self) -> bool {
        self.pos < self.buf.len()
    }

    #[inline]
    pub fn remaining(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    #[inline]
    pub fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    #[inline]
    pub fn read_field_key(&mut self) -> Result<(u32, WireType), DecodeError> {
        let (tag, wire_type, len) = decode_field_key(self.remaining())?;
        self.advance(len);
        Ok((tag, wire_type))
    }

    #[inline]
    pub fn skip_field(&mut self, wire_type: WireType) -> Result<(), DecodeError> {
        let len = skip_field(wire_type, self.remaining())?;
        self.advance(len);
        Ok(())
    }

    #[inline]
    pub fn read_field_data(&mut self, wire_type: WireType) -> Result<Vec<u8>, DecodeError> {
        let data = match wire_type {
            WireType::Varint => {
                let (_value, len) = varint::decode::<u64>(self.remaining())?;
                let data = self.remaining()[..len].to_vec();
                self.advance(len);
                data
            }
            WireType::Fixed64 => {
                if self.remaining().len() < 8 {
                    return Err(DecodeError::UnexpectedEof);
                }
                let data = self.remaining()[..8].to_vec();
                self.advance(8);
                data
            }
            WireType::Fixed32 => {
                if self.remaining().len() < 4 {
                    return Err(DecodeError::UnexpectedEof);
                }
                let data = self.remaining()[..4].to_vec();
                self.advance(4);
                data
            }
            WireType::LengthDelimited => {
                
                let (len, varint_len) = varint::decode::<u32>(self.remaining())?;
                let total_len = varint_len + len as usize;
                if self.remaining().len() < total_len {
                    return Err(DecodeError::UnexpectedEof);
                }
                let data = self.remaining()[..total_len].to_vec();
                self.advance(total_len);
                data
            }
            WireType::StartGroup | WireType::EndGroup => {
                return Err(DecodeError::Custom(
                    "Groups are not supported".to_string(),
                ))
            }
        };
        Ok(data)
    }

    #[inline]
    pub fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let (value, len) = varint::decode::<u64>(self.remaining())?;
        self.advance(len);
        Ok(value)
    }

    #[inline]
    pub fn read_length_delimited(&mut self) -> Result<Vec<u8>, DecodeError> {
        let (data, len) = decode_length_delimited(self.remaining())?;
        let result = data.to_vec();
        self.advance(len);
        Ok(result)
    }

    #[inline]
    pub fn read_length_delimited_slice(&mut self) -> Result<(usize, usize), DecodeError> {
        let start = self.pos;
        let (_, len) = decode_length_delimited(self.remaining())?;
        self.advance(len);
        Ok((start, len))
    }

    #[inline]
    pub fn read_fixed32(&mut self) -> Result<u32, DecodeError> {
        let (value, len) = decode_fixed32_field(self.remaining())?;
        self.advance(len);
        Ok(value)
    }

    #[inline]
    pub fn read_fixed64(&mut self) -> Result<u64, DecodeError> {
        let (value, len) = decode_fixed64_field(self.remaining())?;
        self.advance(len);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::ProtoEncode;
    use bytes::BytesMut;

    #[test]
    fn test_decode_primitives() {
        
        let mut buf = BytesMut::new();
        42u32.encode(&mut buf).unwrap();
        let value = u32::decode(&buf).unwrap();
        assert_eq!(value, 42);

        let mut buf = BytesMut::new();
        "hello".encode(&mut buf).unwrap();
        let value = String::decode(&buf).unwrap();
        assert_eq!(value, "hello");

        let mut buf = BytesMut::new();
        true.encode(&mut buf).unwrap();
        let value = bool::decode(&buf).unwrap();
        assert!(value);
    }

    #[test]
    fn test_field_reader() {
        use crate::encoding::encode_varint_field;

        let mut buf = BytesMut::new();
        encode_varint_field(1, 42, &mut buf).unwrap();
        encode_varint_field(2, 100, &mut buf).unwrap();

        let mut reader = FieldReader::new(&buf);

        let (tag, wire_type) = reader.read_field_key().unwrap();
        assert_eq!(tag, 1);
        assert_eq!(wire_type, WireType::Varint);
        let value = reader.read_varint().unwrap();
        assert_eq!(value, 42);

        let (tag, wire_type) = reader.read_field_key().unwrap();
        assert_eq!(tag, 2);
        assert_eq!(wire_type, WireType::Varint);
        let value = reader.read_varint().unwrap();
        assert_eq!(value, 100);

        assert!(!reader.has_remaining());
    }

    #[test]
    fn test_skip_field() {
        use crate::encoding::encode_varint_field;

        let mut buf = BytesMut::new();
        encode_varint_field(1, 42, &mut buf).unwrap();

        let mut reader = FieldReader::new(&buf);
        let (_, wire_type) = reader.read_field_key().unwrap();
        reader.skip_field(wire_type).unwrap();

        assert!(!reader.has_remaining());
    }
}
