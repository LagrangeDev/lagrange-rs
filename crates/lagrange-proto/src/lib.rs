
pub mod decoding;
pub mod encoding;
pub mod error;
pub mod helpers;
pub mod message;
pub mod types;
pub mod unknown_fields;
pub mod varint;
pub mod wire;

pub use decoding::ProtoDecode;
pub use encoding::ProtoEncode;
pub use error::{DecodeError, EncodeError, ProtoError};
pub use message::ProtoMessage;

pub use types::{Fixed32, Fixed64, SFixed32, SFixed64, SInt32, SInt64};

pub use unknown_fields::{UnknownField, UnknownFields};

#[cfg(feature = "derive")]
pub use lagrange_proto_derive::{ProtoBuilder, ProtoEnum, ProtoMessage, ProtoOneof};

use bytes::{Bytes, BytesMut};

pub fn to_bytes<T: ProtoEncode>(value: &T) -> Result<Bytes, EncodeError> {
    let mut buf = BytesMut::new();
    value.encode(&mut buf)?;
    Ok(buf.freeze())
}

pub fn from_bytes<T: ProtoDecode>(bytes: &[u8]) -> Result<T, DecodeError> {
    T::decode(bytes)
}
