
use lagrange_proto::{ProtoMessage, ProtoEncode};

#[derive(Debug, PartialEq, ProtoMessage)]
struct SimpleMessage {
    #[proto(tag = 1)]
    id: u32,
    #[proto(tag = 2)]
    name: String,
    #[proto(tag = 3)]
    active: bool,
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithOptional {
    #[proto(tag = 1)]
    id: u64,
    #[proto(tag = 2)]
    name: Option<String>,
    #[proto(tag = 3)]
    value: Option<i32>,
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithRepeated {
    #[proto(tag = 1)]
    id: u32,
    #[proto(tag = 2)]
    tags: Vec<String>,
    #[proto(tag = 3)]
    numbers: Vec<u32>,
}

#[test]
fn test_simple_message_roundtrip() {
    let msg = SimpleMessage {
        id: 42,
        name: "test".to_string(),
        active: true,
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = SimpleMessage::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_message_with_optional() {
    
    let msg = MessageWithOptional {
        id: 12345,
        name: Some("optional".to_string()),
        value: Some(-42),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOptional::decode_from_slice(&encoded).unwrap();
    assert_eq!(msg, decoded);

    let msg = MessageWithOptional {
        id: 12345,
        name: None,
        value: None,
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOptional::decode_from_slice(&encoded).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn test_message_with_repeated() {
    let msg = MessageWithRepeated {
        id: 1,
        tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
        numbers: vec![1, 2, 3, 4, 5],
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithRepeated::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_empty_repeated_fields() {
    let msg = MessageWithRepeated {
        id: 100,
        tags: vec![],
        numbers: vec![],
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithRepeated::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_encoded_size() {
    let msg = SimpleMessage {
        id: 42,
        name: "hello".to_string(),
        active: true,
    };

    let encoded = msg.encode_to_vec().unwrap();
    assert_eq!(msg.encoded_size(), encoded.len());
}

#[test]
fn test_large_values() {
    let msg = SimpleMessage {
        id: u32::MAX,
        name: "a".repeat(1000),
        active: false,
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = SimpleMessage::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_zigzag_encoding() {
    let msg = MessageWithOptional {
        id: 0,
        name: None,
        value: Some(i32::MIN),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOptional::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);

    let msg = MessageWithOptional {
        id: 0,
        name: None,
        value: Some(i32::MAX),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOptional::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}
