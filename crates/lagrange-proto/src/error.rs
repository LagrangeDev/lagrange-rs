
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncodeError {
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid field tag: {0}")]
    InvalidTag(u32),

    #[error("Buffer too small")]
    BufferTooSmall,

    #[error("{0}")]
    Custom(String),
}

#[derive(Debug, Error)]
pub enum DecodeError {
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unexpected end of input")]
    UnexpectedEof,

    #[error("Invalid wire type: {0}")]
    InvalidWireType(u8),

    #[error("Invalid field tag: {0}")]
    InvalidTag(u32),

    #[error("Invalid varint encoding")]
    InvalidVarint,

    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("Invalid boolean value: {0}")]
    InvalidBool(u64),

    #[error("Invalid enum value: {0}")]
    InvalidEnumValue(i32),

    #[error("Required field missing: {0}")]
    MissingField(&'static str),

    /// Unknown field encountered
    #[error("Unknown field: {0}")]
    UnknownField(u32),

    /// Custom error message
    #[error("{0}")]
    Custom(String),
}

/// General protobuf error type.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Encoding error
    #[error("Encode error: {0}")]
    Encode(#[from] EncodeError),

    /// Decoding error
    #[error("Decode error: {0}")]
    Decode(#[from] DecodeError),
}

impl From<std::io::Error> for ProtoError {
    fn from(err: std::io::Error) -> Self {
        ProtoError::Decode(DecodeError::Io(err))
    }
}
