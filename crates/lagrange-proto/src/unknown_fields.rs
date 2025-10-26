
use crate::wire::WireType;
use crate::{EncodeError, ProtoEncode};
use bytes::BufMut;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownField {
    
    pub tag: u32,
    
    pub wire_type: WireType,
    
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnknownFields {
    fields: Vec<UnknownField>,
}

impl UnknownFields {
    
    pub fn new() -> Self {
        UnknownFields {
            fields: Vec::new(),
        }
    }

    pub fn add(&mut self, tag: u32, wire_type: WireType, data: Vec<u8>) {
        self.fields.push(UnknownField {
            tag,
            wire_type,
            data,
        });
    }

    pub fn get(&self, tag: u32) -> Vec<&UnknownField> {
        self.fields.iter().filter(|f| f.tag == tag).collect()
    }

    pub fn has(&self, tag: u32) -> bool {
        self.fields.iter().any(|f| f.tag == tag)
    }

    pub fn clear(&mut self) {
        self.fields.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &UnknownField> {
        self.fields.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut UnknownField> {
        self.fields.iter_mut()
    }

    pub fn remove(&mut self, tag: u32) {
        self.fields.retain(|f| f.tag != tag);
    }
}

impl ProtoEncode for UnknownFields {
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        
        for field in &self.fields {
            
            let key = crate::wire::encode_key(field.tag, field.wire_type);
            let (arr, len) = crate::varint::encode(key as u64);
            buf.put_slice(&arr[..len]);

            buf.put_slice(&field.data);
        }
        Ok(())
    }

    fn encoded_size(&self) -> usize {
        let mut size = 0;
        for field in &self.fields {
            
            let key = crate::wire::encode_key(field.tag, field.wire_type);
            size += crate::helpers::get_varint_length_u32(key);
            
            size += field.data.len();
        }
        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_fields_new() {
        let fields = UnknownFields::new();
        assert!(fields.is_empty());
        assert_eq!(fields.len(), 0);
    }

    #[test]
    fn test_unknown_fields_add() {
        let mut fields = UnknownFields::new();
        fields.add(1, WireType::Varint, vec![0x0A]);
        assert_eq!(fields.len(), 1);
        assert!(!fields.is_empty());
    }

    #[test]
    fn test_unknown_fields_get() {
        let mut fields = UnknownFields::new();
        fields.add(1, WireType::Varint, vec![0x0A]);
        fields.add(2, WireType::Varint, vec![0x14]);
        fields.add(1, WireType::Varint, vec![0x1E]);

        let tag1_fields = fields.get(1);
        assert_eq!(tag1_fields.len(), 2);
        assert_eq!(tag1_fields[0].data, vec![0x0A]);
        assert_eq!(tag1_fields[1].data, vec![0x1E]);

        let tag2_fields = fields.get(2);
        assert_eq!(tag2_fields.len(), 1);
        assert_eq!(tag2_fields[0].data, vec![0x14]);
    }

    #[test]
    fn test_unknown_fields_has() {
        let mut fields = UnknownFields::new();
        fields.add(1, WireType::Varint, vec![0x0A]);

        assert!(fields.has(1));
        assert!(!fields.has(2));
    }

    #[test]
    fn test_unknown_fields_remove() {
        let mut fields = UnknownFields::new();
        fields.add(1, WireType::Varint, vec![0x0A]);
        fields.add(2, WireType::Varint, vec![0x14]);
        fields.add(1, WireType::Varint, vec![0x1E]);

        fields.remove(1);
        assert_eq!(fields.len(), 1);
        assert!(!fields.has(1));
        assert!(fields.has(2));
    }

    #[test]
    fn test_unknown_fields_clear() {
        let mut fields = UnknownFields::new();
        fields.add(1, WireType::Varint, vec![0x0A]);
        fields.add(2, WireType::Varint, vec![0x14]);

        fields.clear();
        assert!(fields.is_empty());
        assert_eq!(fields.len(), 0);
    }

    #[test]
    fn test_unknown_fields_iter() {
        let mut fields = UnknownFields::new();
        fields.add(1, WireType::Varint, vec![0x0A]);
        fields.add(2, WireType::Varint, vec![0x14]);

        let collected: Vec<_> = fields.iter().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].tag, 1);
        assert_eq!(collected[1].tag, 2);
    }

    #[test]
    fn test_unknown_fields_encode() {
        use bytes::BytesMut;

        let mut fields = UnknownFields::new();
        
        fields.add(1, WireType::Varint, vec![0x2A]);

        let mut buf = BytesMut::new();
        fields.encode(&mut buf).unwrap();

        assert_eq!(buf.as_ref(), &[0x08, 0x2A]);
    }

    #[test]
    fn test_unknown_fields_encoded_size() {
        let mut fields = UnknownFields::new();
        
        fields.add(1, WireType::Varint, vec![0x2A]);

        let size = fields.encoded_size();
        
        assert_eq!(size, 2);
    }
}
