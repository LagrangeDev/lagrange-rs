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

    #[test]
    fn test_bytes_types_encoding() {
        // Test Vec<u8>
        let data_vec = vec![1u8, 2, 3, 4, 5];
        let mut buf = BytesMut::new();
        data_vec.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1 + data_vec.len()); // varint length + data
        assert_eq!(data_vec.encoded_size(), 1 + data_vec.len());

        // Test Bytes
        let data_bytes = Bytes::from_static(&[10, 20, 30, 40, 50]);
        let mut buf = BytesMut::new();
        data_bytes.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1 + data_bytes.len());
        assert_eq!(data_bytes.encoded_size(), 1 + data_bytes.len());

        // Test BytesMut
        let data_bytes_mut = BytesMut::from(&[100, 200, 255][..]);
        let mut buf = BytesMut::new();
        data_bytes_mut.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1 + data_bytes_mut.len());
        assert_eq!(data_bytes_mut.encoded_size(), 1 + data_bytes_mut.len());

        // Test slice
        let data_slice = &[1u8, 2, 3][..];
        let mut buf = BytesMut::new();
        data_slice.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1 + data_slice.len());
        assert_eq!(data_slice.encoded_size(), 1 + data_slice.len());

        // Test empty bytes
        let empty: Vec<u8> = vec![];
        let mut buf = BytesMut::new();
        empty.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 1); // Just the zero-length varint
        assert_eq!(empty.encoded_size(), 1);
    }

    #[test]
    fn test_bytes_types_consistency() {
        // All bytes types should produce identical encoded output
        let data = vec![1u8, 2, 3, 4, 5];

        let mut buf1 = BytesMut::new();
        data.encode(&mut buf1).unwrap();

        let mut buf2 = BytesMut::new();
        Bytes::from(data.clone()).encode(&mut buf2).unwrap();

        let mut buf3 = BytesMut::new();
        BytesMut::from(&data[..]).encode(&mut buf3).unwrap();

        let mut buf4 = BytesMut::new();
        data.as_slice().encode(&mut buf4).unwrap();

        assert_eq!(buf1, buf2);
        assert_eq!(buf2, buf3);
        assert_eq!(buf3, buf4);
    }
}
