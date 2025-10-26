use bytes::BytesMut;
use lagrange_proto::{ProtoDecode, ProtoEncode, ProtoMessage, UnknownFields};

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
#[proto(preserve_unknown)]
struct MessageV1 {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2)]
    name: String,

    pub _unknown_fields: UnknownFields,
}

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
struct MessageV2 {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2)]
    name: String,

    #[proto(tag = 3)]
    email: String,

    #[proto(tag = 4)]
    age: u32,
}

#[test]
fn test_preserve_unknown_fields() {
    let msg_v2 = MessageV2 {
        id: 42,
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
        age: 25,
    };

    let mut buf = BytesMut::new();
    msg_v2.encode(&mut buf).unwrap();
    let encoded_v2 = buf.freeze();

    let msg_v1 = MessageV1::decode(&encoded_v2).unwrap();

    assert_eq!(msg_v1.id, 42);
    assert_eq!(msg_v1.name, "Alice");

    assert!(!msg_v1._unknown_fields.is_empty());
    assert_eq!(msg_v1._unknown_fields.len(), 2);

    let mut buf = BytesMut::new();
    msg_v1.encode(&mut buf).unwrap();
    let re_encoded = buf.freeze();

    let msg_v2_restored = MessageV2::decode(&re_encoded).unwrap();
    assert_eq!(msg_v2_restored, msg_v2);
}

#[test]
fn test_unknown_fields_api() {
    let mut unknown = UnknownFields::new();
    assert!(unknown.is_empty());
    assert_eq!(unknown.len(), 0);

    unknown.add(3, lagrange_proto::wire::WireType::Varint, vec![0x19]);
    unknown.add(4, lagrange_proto::wire::WireType::Varint, vec![0x2A]);

    assert!(!unknown.is_empty());
    assert_eq!(unknown.len(), 2);

    assert!(unknown.has(3));
    assert!(unknown.has(4));
    assert!(!unknown.has(5));

    let tag3_fields = unknown.get(3);
    assert_eq!(tag3_fields.len(), 1);
    assert_eq!(tag3_fields[0].tag, 3);

    unknown.remove(3);
    assert!(!unknown.has(3));
    assert_eq!(unknown.len(), 1);

    unknown.clear();
    assert!(unknown.is_empty());
}

#[test]
fn test_round_trip_fidelity() {
    let original = MessageV2 {
        id: 123,
        name: "Bob".to_string(),
        email: "bob@test.com".to_string(),
        age: 30,
    };

    let mut buf = BytesMut::new();
    original.encode(&mut buf).unwrap();
    let encoded = buf.freeze();

    let v1 = MessageV1::decode(&encoded).unwrap();

    let mut buf = BytesMut::new();
    v1.encode(&mut buf).unwrap();
    let re_encoded = buf.freeze();

    let restored = MessageV2::decode(&re_encoded).unwrap();

    assert_eq!(restored, original);
}

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
#[proto(preserve_unknown)]
struct MessageV1Optional {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2, optional)]
    name: Option<String>,

    pub _unknown_fields: UnknownFields,
}

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
struct MessageV2Extended {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2, optional)]
    name: Option<String>,

    #[proto(tag = 3)]
    count: u32,

    #[proto(tag = 4, optional)]
    description: Option<String>,
}

#[test]
fn test_preserve_with_optional_fields() {
    let msg_v2 = MessageV2Extended {
        id: 999,
        name: Some("Test".to_string()),
        count: 42,
        description: Some("A test message".to_string()),
    };

    let mut buf = BytesMut::new();
    msg_v2.encode(&mut buf).unwrap();
    let encoded = buf.freeze();

    let msg_v1 = MessageV1Optional::decode(&encoded).unwrap();
    assert_eq!(msg_v1.id, 999);
    assert_eq!(msg_v1.name, Some("Test".to_string()));
    assert_eq!(msg_v1._unknown_fields.len(), 2);

    let mut buf = BytesMut::new();
    msg_v1.encode(&mut buf).unwrap();
    let re_encoded = buf.freeze();

    let restored = MessageV2Extended::decode(&re_encoded).unwrap();
    assert_eq!(restored, msg_v2);
}

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
#[proto(preserve_unknown)]
struct MessageV1WithRepeated {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2)]
    tags: Vec<String>,

    pub _unknown_fields: UnknownFields,
}

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
struct MessageV2WithRepeated {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2)]
    tags: Vec<String>,

    #[proto(tag = 3)]
    scores: Vec<u32>,
}

#[test]
fn test_preserve_with_repeated_fields() {
    let msg_v2 = MessageV2WithRepeated {
        id: 1,
        tags: vec!["rust".to_string(), "protobuf".to_string()],
        scores: vec![100, 200, 300],
    };

    let mut buf = BytesMut::new();
    msg_v2.encode(&mut buf).unwrap();
    let encoded = buf.freeze();

    let msg_v1 = MessageV1WithRepeated::decode(&encoded).unwrap();
    assert_eq!(msg_v1.id, 1);
    assert_eq!(
        msg_v1.tags,
        vec!["rust".to_string(), "protobuf".to_string()]
    );

    assert!(!msg_v1._unknown_fields.is_empty());

    let mut buf = BytesMut::new();
    msg_v1.encode(&mut buf).unwrap();
    let re_encoded = buf.freeze();

    let restored = MessageV2WithRepeated::decode(&re_encoded).unwrap();
    assert_eq!(restored, msg_v2);
}

#[test]
fn test_encoded_size_includes_unknown_fields() {
    let msg_v2 = MessageV2 {
        id: 42,
        name: "Test".to_string(),
        email: "test@example.com".to_string(),
        age: 25,
    };

    let v2_size = msg_v2.encoded_size();

    let mut buf = BytesMut::new();
    msg_v2.encode(&mut buf).unwrap();
    let msg_v1 = MessageV1::decode(&buf.freeze()).unwrap();

    let v1_size = msg_v1.encoded_size();
    assert_eq!(v1_size, v2_size);
}

#[derive(ProtoMessage, Debug, Clone, PartialEq)]
struct MessageWithoutPreserve {
    #[proto(tag = 1)]
    id: u32,

    #[proto(tag = 2)]
    name: String,
}

#[test]
fn test_message_without_preserve() {
    let _msg = MessageWithoutPreserve {
        id: 42,
        name: "Test".to_string(),
    };

    let msg_v2 = MessageV2 {
        id: 42,
        name: "Test".to_string(),
        email: "test@example.com".to_string(),
        age: 25,
    };

    let mut buf = BytesMut::new();
    msg_v2.encode(&mut buf).unwrap();
    let encoded = buf.freeze();

    let decoded = MessageWithoutPreserve::decode(&encoded).unwrap();
    assert_eq!(decoded.id, 42);
    assert_eq!(decoded.name, "Test");

    let mut buf = BytesMut::new();
    decoded.encode(&mut buf).unwrap();
    let re_encoded = buf.freeze();

    assert!(re_encoded.len() < encoded.len());
}
