use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct SsoPacket {
    pub command: String,
    pub data: Bytes,
    pub sequence: i32,
    pub ret_code: i32,
    pub extra: String,
}

impl SsoPacket {
    /// Create a new successful SSO packet with data
    pub fn new(command: String, data: Bytes, sequence: i32) -> Self {
        Self {
            command,
            data,
            sequence,
            ret_code: 0,
            extra: String::new(),
        }
    }

    /// Create a new error SSO packet
    pub fn new_error(command: String, sequence: i32, ret_code: i32, extra: String) -> Self {
        Self {
            command,
            data: Bytes::new(),
            sequence,
            ret_code,
            extra,
        }
    }

    /// Check if this packet represents a successful response
    pub fn is_success(&self) -> bool {
        self.ret_code == 0
    }
}
