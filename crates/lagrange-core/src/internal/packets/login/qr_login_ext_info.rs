use bytes::Bytes;
use lagrange_proto::{ProtoEncode, ProtoMessage};

#[derive(Debug, Clone, Default, PartialEq, ProtoMessage)]
pub struct DevInfo {
    #[proto(tag = 1)]
    pub dev_type: String,
    #[proto(tag = 2)]
    pub dev_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, ProtoMessage)]
pub struct GenInfo {
    #[proto(tag = 1)]
    pub client_type: Option<u32>,
    #[proto(tag = 2)]
    pub client_ver: Option<u32>,
    #[proto(tag = 3)]
    pub client_appid: Option<u32>,
    #[proto(tag = 6)]
    pub field6: u32,
}

#[derive(Debug, Clone, Default, PartialEq, ProtoMessage)]
pub struct QrExtInfo {
    #[proto(tag = 1)]
    pub dev_info: Option<DevInfo>,
    #[proto(tag = 2)]
    pub qr_url: Option<String>,
    #[proto(tag = 3)]
    pub qr_sig: Option<String>,
    #[proto(tag = 4)]
    pub gen_info: Option<GenInfo>,
}

#[derive(Debug, Clone, Default, PartialEq, ProtoMessage)]
pub struct ScanExtInfo {
    #[proto(tag = 1)]
    pub guid: Bytes,
    #[proto(tag = 2)]
    pub imei: String,
    #[proto(tag = 3)]
    pub scan_scene: u32,
    #[proto(tag = 4)]
    pub allow_auto_renew_ticket: bool,
    #[proto(tag = 5)]
    pub invalid_gen_ticket: Option<bool>,
}
