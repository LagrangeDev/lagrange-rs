use lagrange_proto::{
    Fixed32, Fixed64, ProtoEncode, ProtoEnum, ProtoMessage, ProtoOneof, SFixed32, SFixed64, SInt32,
    SInt64,
};
use std::collections::HashMap;

#[derive(Debug, PartialEq, ProtoEnum, Clone, Copy, Default)]
enum Status {
    #[default]
    #[proto(value = 0)]
    Unknown,
    #[proto(value = 1)]
    Active,
    #[proto(value = 2)]
    Inactive,
    #[proto(value = 3)]
    Deleted,
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithProtoTypes {
    #[proto(tag = 1)]
    sint32_value: SInt32,
    #[proto(tag = 2)]
    sint64_value: SInt64,
    #[proto(tag = 3)]
    fixed32_value: Fixed32,
    #[proto(tag = 4)]
    fixed64_value: Fixed64,
    #[proto(tag = 5)]
    sfixed32_value: SFixed32,
    #[proto(tag = 6)]
    sfixed64_value: SFixed64,
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithEnum {
    #[proto(tag = 1)]
    id: u32,
    #[proto(tag = 2)]
    status: Status,
    #[proto(tag = 3)]
    name: String,
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithPackedFields {
    #[proto(tag = 1)]
    id: u64,
    #[proto(tag = 2, packed)]
    numbers: Vec<u32>,
    #[proto(tag = 3, packed)]
    flags: Vec<bool>,
    #[proto(tag = 4, packed)]
    scores: Vec<i32>,
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithUnpackedFields {
    #[proto(tag = 1)]
    id: u64,
    #[proto(tag = 2)]
    numbers: Vec<u32>,
    #[proto(tag = 3)]
    names: Vec<String>,
}

#[test]
fn test_proto_types_roundtrip() {
    let msg = MessageWithProtoTypes {
        sint32_value: SInt32(-42),
        sint64_value: SInt64(-123456789),
        fixed32_value: Fixed32(0xDEADBEEF),
        fixed64_value: Fixed64(0xCAFEBABEDEADBEEF),
        sfixed32_value: SFixed32(-100),
        sfixed64_value: SFixed64(-99999),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithProtoTypes::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_proto_types_with_extreme_values() {
    let msg = MessageWithProtoTypes {
        sint32_value: SInt32(i32::MIN),
        sint64_value: SInt64(i64::MAX),
        fixed32_value: Fixed32(u32::MAX),
        fixed64_value: Fixed64(u64::MAX),
        sfixed32_value: SFixed32(i32::MAX),
        sfixed64_value: SFixed64(i64::MIN),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithProtoTypes::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_enum_roundtrip() {
    let msg = MessageWithEnum {
        id: 12345,
        status: Status::Active,
        name: "test_user".to_string(),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithEnum::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_enum_all_values() {
    for status in [
        Status::Unknown,
        Status::Active,
        Status::Inactive,
        Status::Deleted,
    ] {
        let msg = MessageWithEnum {
            id: 1,
            status,
            name: "test".to_string(),
        };

        let encoded = msg.encode_to_vec().unwrap();
        let decoded = MessageWithEnum::decode_from_slice(&encoded).unwrap();

        assert_eq!(msg, decoded);
        assert_eq!(msg.status, decoded.status);
    }
}

#[test]
fn test_enum_conversion_methods() {
    assert_eq!(Status::Unknown.to_i32(), 0);
    assert_eq!(Status::Active.to_i32(), 1);
    assert_eq!(Status::Inactive.to_i32(), 2);
    assert_eq!(Status::Deleted.to_i32(), 3);

    assert_eq!(Status::from_i32(0), Ok(Status::Unknown));
    assert_eq!(Status::from_i32(1), Ok(Status::Active));
    assert_eq!(Status::from_i32(2), Ok(Status::Inactive));
    assert_eq!(Status::from_i32(3), Ok(Status::Deleted));
    assert_eq!(Status::from_i32(99), Err(99));
}

#[test]
fn test_packed_fields_roundtrip() {
    let msg = MessageWithPackedFields {
        id: 999,
        numbers: vec![1, 2, 3, 4, 5, 100, 1000, 10000],
        flags: vec![true, false, true, true, false],
        scores: vec![-100, -50, 0, 50, 100, 999, -999],
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithPackedFields::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_packed_fields_empty() {
    let msg = MessageWithPackedFields {
        id: 123,
        numbers: vec![],
        flags: vec![],
        scores: vec![],
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithPackedFields::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_packed_vs_unpacked_size() {
    let packed = MessageWithPackedFields {
        id: 1,
        numbers: (0..100).collect(),
        flags: vec![true; 50],
        scores: (0..50).collect(),
    };

    let unpacked = MessageWithUnpackedFields {
        id: 1,
        numbers: (0..100).collect(),
        names: vec![],
    };

    let packed_encoded = packed.encode_to_vec().unwrap();
    let unpacked_encoded = unpacked.encode_to_vec().unwrap();

    println!("Packed size: {}", packed_encoded.len());
    println!("Unpacked size: {}", unpacked_encoded.len());

    let packed_decoded = MessageWithPackedFields::decode_from_slice(&packed_encoded).unwrap();
    let unpacked_decoded = MessageWithUnpackedFields::decode_from_slice(&unpacked_encoded).unwrap();

    assert_eq!(packed, packed_decoded);
    assert_eq!(unpacked, unpacked_decoded);
}

#[test]
fn test_unpacked_fields_roundtrip() {
    let msg = MessageWithUnpackedFields {
        id: 777,
        numbers: vec![1, 2, 3],
        names: vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ],
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithUnpackedFields::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_large_packed_array() {
    let msg = MessageWithPackedFields {
        id: 1,
        numbers: (0..1000).collect(),
        flags: vec![true; 500],
        scores: (-500..500).collect(),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithPackedFields::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_encoded_size_accuracy() {
    let msg = MessageWithProtoTypes {
        sint32_value: SInt32(-42),
        sint64_value: SInt64(-123456),
        fixed32_value: Fixed32(12345),
        fixed64_value: Fixed64(98765),
        sfixed32_value: SFixed32(-99),
        sfixed64_value: SFixed64(-88888),
    };

    let encoded = msg.encode_to_vec().unwrap();
    assert_eq!(msg.encoded_size(), encoded.len());
}

#[test]
fn test_mixed_types_message() {
    #[derive(Debug, PartialEq, ProtoMessage)]
    struct ComplexMessage {
        #[proto(tag = 1)]
        regular_int: u32,
        #[proto(tag = 2)]
        sint_value: SInt32,
        #[proto(tag = 3)]
        fixed_value: Fixed32,
        #[proto(tag = 4)]
        status: Status,
        #[proto(tag = 5, packed)]
        packed_ints: Vec<i32>,
        #[proto(tag = 6)]
        name: String,
        #[proto(tag = 7)]
        optional_value: Option<u64>,
    }

    let msg = ComplexMessage {
        regular_int: 42,
        sint_value: SInt32(-100),
        fixed_value: Fixed32(0x12345678),
        status: Status::Active,
        packed_ints: vec![1, -2, 3, -4, 5],
        name: "complex".to_string(),
        optional_value: Some(999),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = ComplexMessage::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithMaps {
    #[proto(tag = 1)]
    id: u64,
    #[proto(tag = 2)]
    string_map: HashMap<String, String>,
    #[proto(tag = 3)]
    int_map: HashMap<u32, u64>,
    #[proto(tag = 4)]
    name: String,
}

#[test]
fn test_map_fields_roundtrip() {
    let mut msg = MessageWithMaps {
        id: 123,
        string_map: HashMap::new(),
        int_map: HashMap::new(),
        name: "test".to_string(),
    };

    msg.string_map
        .insert("key1".to_string(), "value1".to_string());
    msg.string_map
        .insert("key2".to_string(), "value2".to_string());
    msg.string_map
        .insert("key3".to_string(), "value3".to_string());

    msg.int_map.insert(1, 100);
    msg.int_map.insert(2, 200);
    msg.int_map.insert(3, 300);

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithMaps::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_map_fields_empty() {
    let msg = MessageWithMaps {
        id: 456,
        string_map: HashMap::new(),
        int_map: HashMap::new(),
        name: "empty_maps".to_string(),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithMaps::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_map_with_many_entries() {
    let mut msg = MessageWithMaps {
        id: 999,
        string_map: HashMap::new(),
        int_map: HashMap::new(),
        name: "large".to_string(),
    };

    for i in 0..100 {
        msg.string_map
            .insert(format!("key{}", i), format!("value{}", i));
        msg.int_map.insert(i, i as u64 * 10);
    }

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithMaps::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
    assert_eq!(msg.string_map.len(), 100);
    assert_eq!(msg.int_map.len(), 100);
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithDefaults {
    #[proto(tag = 1, default = "42")]
    number: i32,

    #[proto(tag = 2, default = "Hello")]
    greeting: String,

    #[proto(tag = 3, default = "true")]
    flag: bool,

    #[proto(tag = 4, default = "Active")]
    status: Status,

    #[proto(tag = 5)]
    optional_field: Option<String>,
}

#[test]
fn test_default_values() {
    let empty_bytes: &[u8] = &[];
    let msg = MessageWithDefaults::decode_from_slice(empty_bytes).unwrap();

    assert_eq!(msg.number, 42);
    assert_eq!(msg.greeting, "Hello");
    assert!(msg.flag);
    assert_eq!(msg.status, Status::Active);
    assert_eq!(msg.optional_field, None);
}

#[test]
fn test_defaults_overridden() {
    let msg = MessageWithDefaults {
        number: 100,
        greeting: "World".to_string(),
        flag: false,
        status: Status::Inactive,
        optional_field: Some("test".to_string()),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithDefaults::decode_from_slice(&encoded).unwrap();

    assert_eq!(decoded.number, 100);
    assert_eq!(decoded.greeting, "World");
    assert!(!decoded.flag);
    assert_eq!(decoded.status, Status::Inactive);
    assert_eq!(decoded.optional_field, Some("test".to_string()));
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct Proto3Message {
    #[proto(tag = 1)]
    implicit_int: i32,

    #[proto(tag = 2)]
    explicit_int: Option<i32>,

    #[proto(tag = 3)]
    implicit_flag: bool,

    #[proto(tag = 4)]
    explicit_flag: Option<bool>,

    #[proto(tag = 5)]
    name: String,
}

#[test]
fn test_proto3_implicit_presence() {
    let msg = Proto3Message {
        implicit_int: 0,
        explicit_int: None,
        implicit_flag: false,
        explicit_flag: None,
        name: String::new(),
    };

    let encoded = msg.encode_to_vec().unwrap();

    let decoded = Proto3Message::decode_from_slice(&encoded).unwrap();

    assert_eq!(decoded.implicit_int, 0);
    assert_eq!(decoded.explicit_int, None);
    assert!(!decoded.implicit_flag);
    assert_eq!(decoded.explicit_flag, None);
}

#[test]
fn test_proto3_explicit_presence() {
    let msg = Proto3Message {
        implicit_int: 0,
        explicit_int: Some(0),
        implicit_flag: false,
        explicit_flag: Some(false),
        name: "test".to_string(),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = Proto3Message::decode_from_slice(&encoded).unwrap();

    assert_eq!(decoded.explicit_int, Some(0));
    assert_eq!(decoded.explicit_flag, Some(false));
}

#[test]
fn test_proto3_presence_distinction() {
    let msg1 = Proto3Message {
        implicit_int: 0,
        explicit_int: None,
        implicit_flag: false,
        explicit_flag: None,
        name: String::new(),
    };

    let msg2 = Proto3Message {
        implicit_int: 0,
        explicit_int: Some(0),
        implicit_flag: false,
        explicit_flag: Some(false),
        name: String::new(),
    };

    let encoded1 = msg1.encode_to_vec().unwrap();
    let encoded2 = msg2.encode_to_vec().unwrap();

    let decoded1 = Proto3Message::decode_from_slice(&encoded1).unwrap();
    let decoded2 = Proto3Message::decode_from_slice(&encoded2).unwrap();

    assert_eq!(decoded1.explicit_int, None);
    assert_eq!(decoded2.explicit_int, Some(0));

    assert_eq!(decoded1.explicit_flag, None);
    assert_eq!(decoded2.explicit_flag, Some(false));
}

#[derive(Debug, PartialEq, Clone, ProtoOneof)]
enum TestOneof {
    #[proto(tag = 4)]
    Name(String),
    #[proto(tag = 5)]
    Id(u32),
    #[proto(tag = 6)]
    Score(i32),
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithOneof {
    #[proto(tag = 1)]
    version: u32,
    #[proto(oneof)]
    data: Option<TestOneof>,
}

#[test]
fn test_oneof_roundtrip_name() {
    let msg = MessageWithOneof {
        version: 1,
        data: Some(TestOneof::Name("alice".to_string())),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
    assert_eq!(decoded.data, Some(TestOneof::Name("alice".to_string())));
}

#[test]
fn test_oneof_roundtrip_id() {
    let msg = MessageWithOneof {
        version: 2,
        data: Some(TestOneof::Id(12345)),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
    assert_eq!(decoded.data, Some(TestOneof::Id(12345)));
}

#[test]
fn test_oneof_roundtrip_score() {
    let msg = MessageWithOneof {
        version: 3,
        data: Some(TestOneof::Score(-999)),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
    assert_eq!(decoded.data, Some(TestOneof::Score(-999)));
}

#[test]
fn test_oneof_none() {
    let msg = MessageWithOneof {
        version: 4,
        data: None,
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
    assert_eq!(decoded.data, None);
}

#[test]
fn test_oneof_last_wins() {
    let msg1 = MessageWithOneof {
        version: 1,
        data: Some(TestOneof::Name("first".to_string())),
    };
    let bytes1 = msg1.encode_to_vec().unwrap();

    let msg2 = MessageWithOneof {
        version: 1,
        data: Some(TestOneof::Id(999)),
    };
    let bytes2 = msg2.encode_to_vec().unwrap();

    let mut combined = bytes1.clone();

    let mut i = 0;
    while i < bytes2.len() {
        if bytes2[i] == 40 {
            combined.extend_from_slice(&bytes2[i..]);
            break;
        }
        i += 1;
    }

    let decoded = MessageWithOneof::decode_from_slice(&combined).unwrap();
    assert_eq!(decoded.data, Some(TestOneof::Id(999)));
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Clone, ProtoOneof)]
enum ComplexOneof {
    #[proto(tag = 10)]
    SintValue(SInt32),
    #[proto(tag = 11)]
    FixedValue(Fixed64),
    #[proto(tag = 12)]
    EnumValue(Status),
}

#[derive(Debug, PartialEq, ProtoMessage)]
struct MessageWithComplexOneof {
    #[proto(tag = 1)]
    id: u64,
    #[proto(oneof)]
    data: Option<ComplexOneof>,
}

#[test]
fn test_complex_oneof_sint() {
    let msg = MessageWithComplexOneof {
        id: 123,
        data: Some(ComplexOneof::SintValue(SInt32(-42))),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithComplexOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_complex_oneof_fixed() {
    let msg = MessageWithComplexOneof {
        id: 456,
        data: Some(ComplexOneof::FixedValue(Fixed64(0xDEADBEEFCAFEBABE))),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithComplexOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}

#[test]
fn test_complex_oneof_enum() {
    let msg = MessageWithComplexOneof {
        id: 789,
        data: Some(ComplexOneof::EnumValue(Status::Active)),
    };

    let encoded = msg.encode_to_vec().unwrap();
    let decoded = MessageWithComplexOneof::decode_from_slice(&encoded).unwrap();

    assert_eq!(msg, decoded);
}
