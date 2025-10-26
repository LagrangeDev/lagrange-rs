
use crate::encoding::ProtoEncode;

const VARINT_LENGTHS_32: [u8; 32] = {
    let mut arr = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        arr[i] = ((((38 - i) * 0x12493) >> 19) + (i >> 5)) as u8;
        i += 1;
    }
    arr
};

const VARINT_LENGTHS_64: [u8; 64] = {
    let mut arr = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        arr[i] = ((((70 - i) * 0x12493) >> 19) + (i >> 6)) as u8;
        i += 1;
    }
    arr
};

#[inline(always)]
pub fn get_varint_length_u32(value: u32) -> usize {
    if value == 0 {
        return 1;
    }
    let lz = value.leading_zeros();
    VARINT_LENGTHS_32[lz as usize] as usize
}

#[inline(always)]
pub fn get_varint_length_u64(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let lz = value.leading_zeros();
    VARINT_LENGTHS_64[lz as usize] as usize
}

#[inline(always)]
pub fn count_string(s: &str) -> usize {
    let byte_len = s.len();
    get_varint_length_u32(byte_len as u32) + byte_len
}

#[inline(always)]
pub fn count_bytes(bytes: &[u8]) -> usize {
    let byte_len = bytes.len();
    get_varint_length_u32(byte_len as u32) + byte_len
}

#[inline(always)]
pub fn count_message<T: ProtoEncode>(message: &T) -> usize {
    let message_size = message.encoded_size();
    get_varint_length_u32(message_size as u32) + message_size
}

#[inline(always)]
pub fn count_repeated<T: ProtoEncode>(items: &[T], tag_size: usize) -> usize {
    items
        .iter()
        .map(|item| tag_size + item.encoded_size())
        .sum()
}

#[inline(always)]
pub fn count_repeated_strings(strings: &[String], tag_size: usize) -> usize {
    strings
        .iter()
        .map(|s| tag_size + count_string(s))
        .sum()
}

#[inline(always)]
pub fn count_repeated_bytes(bytes_list: &[Vec<u8>], tag_size: usize) -> usize {
    bytes_list
        .iter()
        .map(|b| tag_size + count_bytes(b))
        .sum()
}

#[inline(always)]
pub fn field_tag_size(tag: u32, wire_type: crate::wire::WireType) -> usize {
    let key = crate::wire::encode_key(tag, wire_type);
    get_varint_length_u32(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WireType;

    #[test]
    fn test_count_string() {
        assert_eq!(count_string(""), 1); 
        assert_eq!(count_string("hello"), 6); 
        assert_eq!(count_string(&"a".repeat(127)), 128); 
        assert_eq!(count_string(&"a".repeat(128)), 130); 
    }

    #[test]
    fn test_count_bytes() {
        assert_eq!(count_bytes(&[]), 1);
        assert_eq!(count_bytes(&[1, 2, 3, 4, 5]), 6);
        assert_eq!(count_bytes(&vec![0u8; 127]), 128);
        assert_eq!(count_bytes(&vec![0u8; 128]), 130);
    }

    #[test]
    fn test_field_tag_size() {
        assert_eq!(field_tag_size(1, WireType::Varint), 1); 
        assert_eq!(field_tag_size(2, WireType::LengthDelimited), 1); 
        assert_eq!(field_tag_size(15, WireType::Varint), 1); 
        assert_eq!(field_tag_size(16, WireType::Varint), 2); 
    }

    #[test]
    fn test_count_repeated_strings() {
        let strings = vec![
            "hello".to_string(),
            "world".to_string(),
            "test".to_string(),
        ];
        let tag_size = field_tag_size(1, WireType::LengthDelimited);

        let total = count_repeated_strings(&strings, tag_size);

        assert_eq!(total, 20);
    }

    #[test]
    fn test_count_repeated_bytes() {
        let bytes_list = vec![
            vec![1, 2, 3],
            vec![4, 5, 6, 7],
            vec![8],
        ];
        let tag_size = field_tag_size(1, WireType::LengthDelimited);

        let total = count_repeated_bytes(&bytes_list, tag_size);

        assert_eq!(total, 14);
    }
}
