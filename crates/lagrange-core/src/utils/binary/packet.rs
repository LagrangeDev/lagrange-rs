use super::helper::{from_be, to_be, EndianSwap};
use super::prefix::Prefix;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    InsufficientData { requested: usize, available: usize },
    InvalidUtf8(std::str::Utf8Error),
    InvalidPrefix,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientData {
                requested,
                available,
            } => write!(
                f,
                "Insufficient data: requested {} bytes, but only {} available",
                requested, available
            ),
            Self::InvalidUtf8(e) => write!(f, "Invalid UTF-8: {}", e),
            Self::InvalidPrefix => write!(f, "Invalid prefix flag"),
        }
    }
}

impl std::error::Error for PacketError {}

impl From<std::str::Utf8Error> for PacketError {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8(e)
    }
}

pub type Result<T> = std::result::Result<T, PacketError>;

/// A binary packet reader/writer with support for method chaining.
///
/// # Examples
///
/// ## Method Chaining with Write Operations
///
/// ```
/// use lagrange_core::utils::binary::packet::BinaryPacket;
/// use lagrange_core::utils::binary::prefix::Prefix;
///
/// let mut packet = BinaryPacket::with_capacity(128);
///
/// // Chain write operations fluently
/// packet
///     .write(0x01u8)
///     .write_bytes(&[0xAA, 0xBB, 0xCC])
///     .write(0x1234u16)
///     .write_str("Hello", Prefix::INT16)
///     .write(0xDEADBEEFu32);
///
/// let data = packet.to_vec();
/// ```
///
/// ## Using Length Prefixes
///
/// ```
/// use lagrange_core::utils::binary::packet::BinaryPacket;
///
/// let mut packet = BinaryPacket::with_capacity(64);
///
/// packet.with_length_prefix::<u32, _, _>(false, 0, |w| {
///     w.write(0xABu8)
///      .write(0x1234u16)
///      .write(0x5678u16);
/// }).unwrap();
/// ```
#[derive(Debug)]
pub struct BinaryPacket {
    buffer: Vec<u8>,
    offset: usize,
}

impl BinaryPacket {
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            offset: 0,
        }
    }

    #[inline]
    pub fn from_vec(buffer: Vec<u8>) -> Self {
        Self { buffer, offset: 0 }
    }

    #[inline]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            buffer: slice.to_vec(),
            offset: 0,
        }
    }

    #[inline]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    #[inline]
    fn ensure_capacity(&mut self, additional: usize) {
        let required = self.offset + additional;
        if required > self.buffer.len() {
            if required > self.buffer.capacity() {
                self.buffer.reserve(required - self.buffer.len());
            }
            self.buffer.resize(required, 0);
        }
    }

    #[inline]
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.ensure_capacity(data.len());
        self.buffer[self.offset..self.offset + data.len()].copy_from_slice(data);
        self.offset += data.len();
        self
    }

    #[inline]
    pub fn write<T: EndianSwap + Copy>(&mut self, value: T) -> &mut Self {
        let swapped = to_be(value);
        let size = std::mem::size_of::<T>();
        self.ensure_capacity(size);

        unsafe {
            let ptr = self.buffer.as_mut_ptr().add(self.offset) as *mut T;
            ptr.write_unaligned(swapped);
        }

        self.offset += size;
        self
    }

    #[inline]
    pub fn write_at<T: EndianSwap + Copy>(&mut self, offset: usize, value: T) -> Result<()> {
        let swapped = to_be(value);
        let size = std::mem::size_of::<T>();

        if offset + size > self.buffer.len() {
            return Err(PacketError::InsufficientData {
                requested: size,
                available: self.buffer.len().saturating_sub(offset),
            });
        }

        unsafe {
            let ptr = self.buffer.as_mut_ptr().add(offset) as *mut T;
            ptr.write_unaligned(swapped);
        }

        Ok(())
    }

    #[inline]
    fn calculate_length(&self, length: usize, prefix: Prefix, addition: i32) -> usize {
        let mut len = length as i32 + addition;
        if prefix.is_length_counted() {
            len += prefix.prefix_length() as i32;
        }
        len as usize
    }

    #[inline]
    fn write_length(&mut self, length: usize, prefix: Prefix, addition: i32) -> &mut Self {
        let len = self.calculate_length(length, prefix, addition);
        let prefix_len = prefix.prefix_length();

        match prefix_len {
            1 => {
                self.write(len as u8);
            }
            2 => {
                self.write(len as u16);
            }
            4 => {
                self.write(len as u32);
            }
            0 => {}
            _ => panic!("Invalid prefix length: {}", prefix_len),
        }

        self
    }

    #[inline]
    pub fn write_bytes_with_prefix(&mut self, data: &[u8], prefix: Prefix) -> &mut Self {
        self.write_length(data.len(), prefix, 0);
        self.write_bytes(data);
        self
    }

    #[inline]
    pub fn write_str(&mut self, s: &str, prefix: Prefix) -> &mut Self {
        let bytes = s.as_bytes();
        if prefix.prefix_length() > 0 {
            self.write_bytes_with_prefix(bytes, prefix);
        } else {
            self.write_bytes(bytes);
        }
        self
    }

    #[inline]
    pub fn read_bytes(&mut self, length: usize) -> Result<&[u8]> {
        if self.offset + length > self.buffer.len() {
            return Err(PacketError::InsufficientData {
                requested: length,
                available: self.remaining(),
            });
        }

        let slice = &self.buffer[self.offset..self.offset + length];
        self.offset += length;
        Ok(slice)
    }

    #[inline]
    pub fn read_remaining(&mut self) -> &[u8] {
        let slice = &self.buffer[self.offset..];
        self.offset = self.buffer.len();
        slice
    }

    #[inline]
    pub fn read<T: EndianSwap + Copy>(&mut self) -> Result<T> {
        let size = std::mem::size_of::<T>();

        if self.offset + size > self.buffer.len() {
            return Err(PacketError::InsufficientData {
                requested: size,
                available: self.remaining(),
            });
        }

        let value = unsafe {
            let ptr = self.buffer.as_ptr().add(self.offset) as *const T;
            ptr.read_unaligned()
        };

        self.offset += size;
        Ok(from_be(value))
    }

    #[inline]
    fn read_length(&mut self, prefix: Prefix) -> Result<usize> {
        let prefix_len = prefix.prefix_length();
        let length = match prefix_len {
            1 => self.read::<u8>()? as usize,
            2 => self.read::<u16>()? as usize,
            4 => self.read::<u32>()? as usize,
            0 => return Err(PacketError::InvalidPrefix),
            _ => return Err(PacketError::InvalidPrefix),
        };

        let mut len = length;
        if prefix.is_length_counted() {
            len = len.saturating_sub(prefix_len);
        }

        Ok(len)
    }

    #[inline]
    pub fn read_bytes_with_prefix(&mut self, prefix: Prefix) -> Result<&[u8]> {
        let length = self.read_length(prefix)?;
        self.read_bytes(length)
    }

    #[inline]
    pub fn read_string(&mut self, prefix: Prefix) -> Result<String> {
        let bytes = self.read_bytes_with_prefix(prefix)?;
        let s = std::str::from_utf8(bytes)?;
        Ok(s.to_string())
    }

    #[inline]
    pub fn peek<T: EndianSwap + Copy>(&self) -> Result<T> {
        let size = std::mem::size_of::<T>();

        if self.offset + size > self.buffer.len() {
            return Err(PacketError::InsufficientData {
                requested: size,
                available: self.remaining(),
            });
        }

        let value = unsafe {
            let ptr = self.buffer.as_ptr().add(self.offset) as *const T;
            ptr.read_unaligned()
        };

        Ok(from_be(value))
    }

    #[inline]
    pub fn skip(&mut self, count: usize) -> &mut Self {
        self.ensure_capacity(count);
        self.offset += count;
        self
    }

    /// Writes a length-prefixed section using a closure-based approach.
    ///
    /// This method provides a functional, RAII-compliant way to write length-prefixed data.
    /// It automatically reserves space for the length prefix, executes the provided closure
    /// to write data, calculates the written length, and writes it back to the reserved space.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of the length prefix (e.g., `u16`, `u32`)
    /// * `F` - The closure type that performs the write operations
    /// * `R` - The return type of the closure (optional, defaults to `()`)
    ///
    /// # Parameters
    ///
    /// * `include_prefix` - Whether to include the prefix size in the length calculation
    /// * `addition` - Additional offset to add to the calculated length
    /// * `f` - Closure that receives `&mut Self` and performs write operations
    ///
    /// # Returns
    ///
    /// Returns `Ok(R)` containing the closure's return value, or `Err` if writing the length fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lagrange_core::utils::binary::packet::BinaryPacket;
    ///
    /// let mut packet = BinaryPacket::with_capacity(64);
    ///
    /// packet.with_length_prefix::<u32, _, _>(true, 0, |w| {
    ///     w.write(0x12i32)
    ///      .write(0x34u16)
    ///      .write_bytes(&[0xAA, 0xBB, 0xCC]);
    /// }).unwrap();
    /// ```
    #[inline]
    pub fn with_length_prefix<T, F, R>(
        &mut self,
        include_prefix: bool,
        addition: i32,
        f: F,
    ) -> Result<R>
    where
        T: EndianSwap + Copy,
        F: FnOnce(&mut Self) -> R,
    {
        let barrier = self.offset;
        let size = std::mem::size_of::<T>();
        self.ensure_capacity(size);
        self.offset += size;

        let result = f(self);

        let mut written = (self.offset - barrier) as i32 + addition;
        if !include_prefix {
            written -= size as i32;
        }

        match size {
            1 => self.write_at(barrier, written as u8)?,
            2 => self.write_at(barrier, written as u16)?,
            4 => self.write_at(barrier, written as u32)?,
            8 => self.write_at(barrier, written as u64)?,
            _ => panic!("Unsupported size for length prefix: {}", size),
        }

        Ok(result)
    }

    #[inline]
    pub fn to_vec(mut self) -> Vec<u8> {
        self.buffer.truncate(self.offset);
        self.buffer
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let offset = self.offset;
        &mut self.buffer[..offset]
    }
}

impl From<Vec<u8>> for BinaryPacket {
    fn from(buffer: Vec<u8>) -> Self {
        Self::from_vec(buffer)
    }
}

impl From<&[u8]> for BinaryPacket {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

impl AsRef<[u8]> for BinaryPacket {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for BinaryPacket {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_read_integers() {
        let mut packet = BinaryPacket::with_capacity(64);

        // Test method chaining
        packet
            .write(0x12u8)
            .write(0x1234u16)
            .write(0x12345678u32)
            .write(0x123456789ABCDEFu64);

        let mut read_packet = BinaryPacket::from(packet.to_vec());

        assert_eq!(read_packet.read::<u8>().unwrap(), 0x12u8);
        assert_eq!(read_packet.read::<u16>().unwrap(), 0x1234u16);
        assert_eq!(read_packet.read::<u32>().unwrap(), 0x12345678u32);
        assert_eq!(read_packet.read::<u64>().unwrap(), 0x123456789ABCDEFu64);
    }

    #[test]
    fn test_write_read_bytes() {
        let mut packet = BinaryPacket::with_capacity(64);

        packet.write_bytes(b"hello");
        packet.write_bytes(&[1, 2, 3, 4, 5]);

        let mut read_packet = BinaryPacket::from(packet.to_vec());

        assert_eq!(read_packet.read_bytes(5).unwrap(), b"hello");
        assert_eq!(read_packet.read_bytes(5).unwrap(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_write_read_strings() {
        let mut packet = BinaryPacket::with_capacity(64);

        // Test method chaining
        packet
            .write_str("hello", Prefix::INT16)
            .write_str("world", Prefix::INT32);

        let mut read_packet = BinaryPacket::from(packet.to_vec());

        assert_eq!(read_packet.read_string(Prefix::INT16).unwrap(), "hello");
        assert_eq!(read_packet.read_string(Prefix::INT32).unwrap(), "world");
    }

    #[test]
    fn test_length_prefix() {
        let mut packet = BinaryPacket::with_capacity(64);

        // Test method chaining with length prefix
        packet
            .with_length_prefix::<u32, _, _>(false, 0, |w| {
                w.write(0x1234u16);
                w.write(0x5678u16);
            })
            .unwrap();

        let mut read_packet = BinaryPacket::from(packet.to_vec());

        let len: u32 = read_packet.read().unwrap();
        assert_eq!(len, 4);

        assert_eq!(read_packet.read::<u16>().unwrap(), 0x1234);
        assert_eq!(read_packet.read::<u16>().unwrap(), 0x5678);
    }

    #[test]
    fn test_peek() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let mut packet = BinaryPacket::from(data);

        let value: u16 = packet.peek().unwrap();
        assert_eq!(value, 0x1234);
        assert_eq!(packet.offset(), 0);

        let value: u16 = packet.read().unwrap();
        assert_eq!(value, 0x1234);
        assert_eq!(packet.offset(), 2);
    }

    #[test]
    fn test_skip() {
        let data = vec![1, 2, 3, 4, 5];
        let mut packet = BinaryPacket::from(data);

        // Test chaining skip
        packet.skip(2);
        assert_eq!(packet.read::<u8>().unwrap(), 3);
        assert_eq!(packet.read::<u8>().unwrap(), 4);
    }

    #[test]
    fn test_remaining() {
        let data = vec![1, 2, 3, 4, 5];
        let mut packet = BinaryPacket::from(data);

        assert_eq!(packet.remaining(), 5);
        packet.skip(2);
        assert_eq!(packet.remaining(), 3);
    }

    #[test]
    fn test_method_chaining() {
        let mut packet = BinaryPacket::with_capacity(128);

        // Demonstrate fluent API with mixed operations
        packet
            .write(0xAAu8)
            .write_bytes(&[1, 2, 3, 4])
            .write(0xBBCCu16)
            .write_str("test", Prefix::INT16)
            .write(0xDDEEFFu32);

        let vec = packet.to_vec();
        assert!(!vec.is_empty());
    }

    #[test]
    fn test_prefix_with_length_counted() {
        let mut packet = BinaryPacket::with_capacity(64);

        let prefix = Prefix::INT16 | Prefix::WITH_PREFIX;
        packet.write_str("hello", prefix);

        let mut read_packet = BinaryPacket::from(packet.to_vec());

        let len: u16 = read_packet.read().unwrap();
        assert_eq!(len, 5 + 2);

        assert_eq!(read_packet.read_bytes(5).unwrap(), b"hello");
    }

    #[test]
    fn test_insufficient_data_error() {
        let data = vec![1, 2];
        let mut packet = BinaryPacket::from(data);

        let result: Result<u32> = packet.read();
        assert!(matches!(result, Err(PacketError::InsufficientData { .. })));
    }

    #[test]
    fn test_length_prefix_with_different_types() {
        // Test u8 prefix
        let mut packet = BinaryPacket::with_capacity(64);
        packet
            .with_length_prefix::<u8, _, _>(false, 0, |w| {
                w.write(0x1234u16);
            })
            .unwrap();
        let mut read_packet = BinaryPacket::from(packet.to_vec());
        let len: u8 = read_packet.read().unwrap();
        assert_eq!(len, 2);
        assert_eq!(read_packet.read::<u16>().unwrap(), 0x1234);

        // Test u16 prefix
        let mut packet = BinaryPacket::with_capacity(64);
        packet
            .with_length_prefix::<u16, _, _>(false, 0, |w| {
                w.write(0x12345678u32);
            })
            .unwrap();
        let mut read_packet = BinaryPacket::from(packet.to_vec());
        let len: u16 = read_packet.read().unwrap();
        assert_eq!(len, 4);
        assert_eq!(read_packet.read::<u32>().unwrap(), 0x12345678);

        // Test u32 prefix
        let mut packet = BinaryPacket::with_capacity(64);
        packet
            .with_length_prefix::<u32, _, _>(false, 0, |w| {
                w.write(0x123456789ABCDEFu64);
            })
            .unwrap();
        let mut read_packet = BinaryPacket::from(packet.to_vec());
        let len: u32 = read_packet.read().unwrap();
        assert_eq!(len, 8);
        assert_eq!(read_packet.read::<u64>().unwrap(), 0x123456789ABCDEFu64);

        // Test u64 prefix with include_prefix=true
        let mut packet = BinaryPacket::with_capacity(64);
        packet
            .with_length_prefix::<u64, _, _>(true, 0, |w| {
                w.write(0x1234u16);
            })
            .unwrap();
        let mut read_packet = BinaryPacket::from(packet.to_vec());
        let len: u64 = read_packet.read().unwrap();
        assert_eq!(len, 2 + 8); // data length + prefix size
        assert_eq!(read_packet.read::<u16>().unwrap(), 0x1234);
    }
}
