
use crate::decoding::ProtoDecode;
use crate::encoding::ProtoEncode;
use crate::error::{DecodeError, EncodeError};
use bytes::{Bytes, BytesMut};

pub trait ProtoMessage: ProtoEncode + ProtoDecode {
    fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = BytesMut::with_capacity(self.encoded_size());
        self.encode(&mut buf)?;
        Ok(buf.to_vec())
    }

    fn encode_to_bytes(&self) -> Result<Bytes, EncodeError> {
        let mut buf = BytesMut::with_capacity(self.encoded_size());
        self.encode(&mut buf)?;
        Ok(buf.freeze())
    }

    fn decode_from_slice(buf: &[u8]) -> Result<Self, DecodeError>
    where Self: Sized,
    {
        Self::decode(buf)
    }

    fn decode_from_bytes(buf: &Bytes) -> Result<Self, DecodeError>
    where Self: Sized,
    {
        Self::decode(buf)
    }
}

impl<T> ProtoMessage for T where T: ProtoEncode + ProtoDecode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encode_decode() {
        
        let original = "hello world".to_string();
        let bytes = original.encode_to_vec().unwrap();
        let decoded = String::decode_from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);

        let original = 12345u32;
        let bytes = original.encode_to_vec().unwrap();
        let decoded = u32::decode_from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}
