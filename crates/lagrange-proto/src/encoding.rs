use crate::error::EncodeError;
use crate::varint;
use crate::wire::{encode_key, WireType};
use bytes::{BufMut, Bytes, BytesMut};

pub trait ProtoEncode {
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError>;

    fn encoded_size(&self) -> usize;
}

#[inline]
pub fn encode_field<B: BufMut, T: ProtoEncode>(
    tag: u32,
    wire_type: WireType,
    value: &T,
    buf: &mut B,
) -> Result<(), EncodeError> {
    let key = encode_key(tag, wire_type);
    let (arr, len) = varint::encode(key);
    buf.put_slice(&arr[..len]);
    value.encode(buf)
}

impl ProtoEncode for u32 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(*self);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        crate::helpers::get_varint_length_u32(*self)
    }
}

impl ProtoEncode for u64 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(*self);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        crate::helpers::get_varint_length_u64(*self)
    }
}

impl ProtoEncode for i32 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode_zigzag::<u32>(*self);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        let unsigned = varint::zigzag_encode_i32(*self);
        crate::helpers::get_varint_length_u32(unsigned)
    }
}

impl ProtoEncode for i64 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode_zigzag::<u64>(*self);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        let unsigned = varint::zigzag_encode_i64(*self);
        crate::helpers::get_varint_length_u64(unsigned)
    }
}

impl ProtoEncode for bool {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(*self as u32);
        buf.put_slice(&arr[..len]);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        1
    }
}

impl ProtoEncode for f32 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        buf.put_f32_le(*self);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        4
    }
}

impl ProtoEncode for f64 {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        buf.put_f64_le(*self);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        8
    }
}

impl ProtoEncode for String {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let bytes = self.as_bytes();
        let (arr, len) = varint::encode(bytes.len() as u32);
        buf.put_slice(&arr[..len]);
        buf.put_slice(bytes);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        let len = self.len();
        crate::helpers::get_varint_length_u32(len as u32) + len
    }
}

impl ProtoEncode for str {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let bytes = self.as_bytes();
        let (arr, len) = varint::encode(bytes.len() as u32);
        buf.put_slice(&arr[..len]);
        buf.put_slice(bytes);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        let len = self.len();
        crate::helpers::get_varint_length_u32(len as u32) + len
    }
}

impl ProtoEncode for Vec<u8> {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(self.len() as u32);
        buf.put_slice(&arr[..len]);
        buf.put_slice(self);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        crate::helpers::get_varint_length_u32(self.len() as u32) + self.len()
    }
}

impl ProtoEncode for [u8] {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(self.len() as u32);
        buf.put_slice(&arr[..len]);
        buf.put_slice(self);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        crate::helpers::get_varint_length_u32(self.len() as u32) + self.len()
    }
}

impl ProtoEncode for Bytes {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(self.len() as u32);
        buf.put_slice(&arr[..len]);
        buf.put_slice(self);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        crate::helpers::get_varint_length_u32(self.len() as u32) + self.len()
    }
}

impl ProtoEncode for BytesMut {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        let (arr, len) = varint::encode(self.len() as u32);
        buf.put_slice(&arr[..len]);
        buf.put_slice(self);
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        crate::helpers::get_varint_length_u32(self.len() as u32) + self.len()
    }
}

impl<T: ProtoEncode> ProtoEncode for Option<T> {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        match self {
            Some(value) => value.encode(buf),
            None => Ok(()),
        }
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        match self {
            Some(value) => value.encoded_size(),
            None => 0,
        }
    }
}

impl<T: ProtoEncode> ProtoEncode for Vec<T> {
    #[inline]
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        for item in self {
            item.encode(buf)?;
        }
        Ok(())
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        self.iter().map(|item| item.encoded_size()).sum()
    }
}

#[inline]
pub fn encode_length_delimited<B: BufMut>(
    tag: u32,
    data: &[u8],
    buf: &mut B,
) -> Result<(), EncodeError> {
    let key = encode_key(tag, WireType::LengthDelimited);
    let (arr_key, len_key) = varint::encode(key);
    buf.put_slice(&arr_key[..len_key]);
    let (arr_len, len_len) = varint::encode(data.len() as u32);
    buf.put_slice(&arr_len[..len_len]);
    buf.put_slice(data);
    Ok(())
}

#[inline]
pub fn encode_varint_field<B: BufMut>(
    tag: u32,
    value: u64,
    buf: &mut B,
) -> Result<(), EncodeError> {
    let key = encode_key(tag, WireType::Varint);
    let (arr_key, len_key) = varint::encode(key);
    buf.put_slice(&arr_key[..len_key]);
    let (arr_val, len_val) = varint::encode(value);
    buf.put_slice(&arr_val[..len_val]);
    Ok(())
}

#[inline]
pub fn encode_fixed32_field<B: BufMut>(
    tag: u32,
    value: u32,
    buf: &mut B,
) -> Result<(), EncodeError> {
    let key = encode_key(tag, WireType::Fixed32);
    let (arr, len) = varint::encode(key);
    buf.put_slice(&arr[..len]);
    buf.put_u32_le(value);
    Ok(())
}

#[inline]
pub fn encode_fixed64_field<B: BufMut>(
    tag: u32,
    value: u64,
    buf: &mut B,
) -> Result<(), EncodeError> {
    let key = encode_key(tag, WireType::Fixed64);
    let (arr, len) = varint::encode(key);
    buf.put_slice(&arr[..len]);
    buf.put_u64_le(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_primitives() {
        let mut buf = BytesMut::new();

        42u32.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 42);

        buf.clear();
        "hello".encode(&mut buf).unwrap();
        assert_eq!(buf[0], 5);
        assert_eq!(&buf[1..], b"hello");

        buf.clear();
        true.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 1);

        buf.clear();
        false.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_encode_option() {
        let mut buf = BytesMut::new();

        let some_value: Option<u32> = Some(42);
        some_value.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1);

        buf.clear();
        let none_value: Option<u32> = None;
        none_value.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_encoded_size() {
        assert_eq!(42u32.encoded_size(), 1);
        assert_eq!(128u32.encoded_size(), 2);
        assert_eq!("hello".encoded_size(), 6);
        assert_eq!(true.encoded_size(), 1);
    }
}
