use lagrange_proto::{ProtoBuilder, ProtoMessage};

/// SSO security information for secure packet transmission
#[derive(Debug, Clone, Default, PartialEq, ProtoMessage, ProtoBuilder)]
pub struct SsoSecureInfo {
    #[proto(tag = 1)]
    pub sec_sign: Option<Vec<u8>>,
    #[proto(tag = 2)]
    pub sec_token: Option<Vec<u8>>,
    #[proto(tag = 3)]
    pub sec_extra: Option<Vec<u8>>,
}
