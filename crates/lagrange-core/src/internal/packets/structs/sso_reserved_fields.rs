use lagrange_proto::{ProtoBuilder, ProtoEncode, ProtoMessage};

use super::SsoSecureInfo;

/// SSO reserved fields for packet metadata
#[derive(Debug, Clone, Default, PartialEq, ProtoMessage, ProtoBuilder)]
pub struct SsoReservedFields {
    #[proto(tag = 15)]
    pub trace_parent: Option<String>,
    #[proto(tag = 16)]
    pub uid: Option<String>,
    #[proto(tag = 21)]
    pub msg_type: Option<u32>,
    #[proto(tag = 24)]
    pub sec_info: Option<SsoSecureInfo>,
    #[proto(tag = 26)]
    pub nt_core_version: Option<u32>,
}
