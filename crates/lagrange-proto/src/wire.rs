
use crate::error::DecodeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    
    Varint = 0,
    
    Fixed64 = 1,
    
    LengthDelimited = 2,
    
    StartGroup = 3,
    
    EndGroup = 4,
    
    Fixed32 = 5,
}

impl WireType {
    
    #[inline]
    pub fn from_u8(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::Fixed64),
            2 => Ok(WireType::LengthDelimited),
            3 => Ok(WireType::StartGroup),
            4 => Ok(WireType::EndGroup),
            5 => Ok(WireType::Fixed32),
            _ => Err(DecodeError::InvalidWireType(value)),
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    
    pub tag: u32,
    
    pub wire_type: WireType,
}

impl Key {
    
    #[inline]
    pub const fn new(tag: u32, wire_type: WireType) -> Self {
        Self { tag, wire_type }
    }

    #[inline]
    pub const fn encode(self) -> u32 {
        (self.tag << 3) | (self.wire_type.as_u8() as u32)
    }

    #[inline]
    pub fn decode(value: u32) -> Result<Self, DecodeError> {
        let tag = value >> 3;
        let wire_type = WireType::from_u8((value & 0x7) as u8)?;

        if tag == 0 {
            return Err(DecodeError::InvalidTag(tag));
        }

        Ok(Self { tag, wire_type })
    }
}

#[inline]
pub const fn encode_key(tag: u32, wire_type: WireType) -> u32 {
    Key::new(tag, wire_type).encode()
}

#[inline]
pub fn decode_key(value: u32) -> Result<(u32, WireType), DecodeError> {
    let key = Key::decode(value)?;
    Ok((key.tag, key.wire_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_type_conversion() {
        assert_eq!(WireType::from_u8(0).unwrap(), WireType::Varint);
        assert_eq!(WireType::from_u8(1).unwrap(), WireType::Fixed64);
        assert_eq!(WireType::from_u8(2).unwrap(), WireType::LengthDelimited);
        assert_eq!(WireType::from_u8(5).unwrap(), WireType::Fixed32);
        assert!(WireType::from_u8(6).is_err());
    }

    #[test]
    fn test_key_encoding() {
        let key = Key::new(1, WireType::Varint);
        assert_eq!(key.encode(), 8); 

        let key = Key::new(2, WireType::LengthDelimited);
        assert_eq!(key.encode(), 18); 
    }

    #[test]
    fn test_key_decoding() {
        let key = Key::decode(8).unwrap();
        assert_eq!(key.tag, 1);
        assert_eq!(key.wire_type, WireType::Varint);

        let key = Key::decode(18).unwrap();
        assert_eq!(key.tag, 2);
        assert_eq!(key.wire_type, WireType::LengthDelimited);

        assert!(Key::decode(0).is_err());
    }

    #[test]
    fn test_encode_decode_key() {
        assert_eq!(encode_key(1, WireType::Varint), 8);

        let (tag, wire_type) = decode_key(8).unwrap();
        assert_eq!(tag, 1);
        assert_eq!(wire_type, WireType::Varint);
    }
}
