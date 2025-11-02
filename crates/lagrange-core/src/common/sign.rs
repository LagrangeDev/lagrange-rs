use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

#[cfg(feature = "sign-provider")]
use std::collections::HashSet;

#[async_trait]
pub trait SignProvider: Send + Sync + std::fmt::Debug {
    async fn sign(&self, cmd: &str, seq: u32, data: &[u8]) -> Option<SignResult>;

    fn platform(&self) -> &str {
        "unknown"
    }
}

#[derive(Debug, Clone)]
pub struct SignResult {
    pub sign: Bytes,
    pub token: Bytes,
    pub extra: Bytes,
}

#[derive(Debug)]
pub struct NoOpSignProvider;

#[async_trait]
impl SignProvider for NoOpSignProvider {
    async fn sign(&self, _cmd: &str, _seq: u32, _data: &[u8]) -> Option<SignResult> {
        None
    }

    fn platform(&self) -> &str {
        "noop"
    }
}

impl Default for NoOpSignProvider {
    fn default() -> Self {
        Self
    }
}

#[derive(Debug)]
pub struct AndroidSignProvider {
    platform: String,
}

impl AndroidSignProvider {
    pub fn new() -> Self {
        Self {
            platform: "android".to_string(),
        }
    }
}

#[async_trait]
impl SignProvider for AndroidSignProvider {
    async fn sign(&self, cmd: &str, seq: u32, data: &[u8]) -> Option<SignResult> {
        tracing::debug!(
            "Android sign request: cmd={}, seq={}, len={}",
            cmd,
            seq,
            data.len()
        );
        None
    }

    fn platform(&self) -> &str {
        &self.platform
    }
}

impl Default for AndroidSignProvider {
    fn default() -> Self {
        Self::new()
    }
}

pub type BoxedSignProvider = Arc<dyn SignProvider>;

#[cfg(feature = "sign-provider")]
mod default {
    use super::*;
    use serde::{Deserialize, Serialize};

    const SIGN_API_URL: &str = "";

    #[derive(Debug, Serialize)]
    struct SignRequest {
        cmd: String,
        seq: u32,
        src: String,
    }

    #[derive(Debug, Deserialize)]
    struct SignResponse {
        value: SignResponseValue,
    }

    #[derive(Debug, Deserialize)]
    struct SignResponseValue {
        sign: String,
        token: String,
        extra: String,
    }

    #[derive(Debug)]
    pub struct DefaultSignProvider {
        client: reqwest::Client,
        whitelist: HashSet<String>,
    }

    impl DefaultSignProvider {
        pub fn new() -> Self {
            let whitelist = Self::build_whitelist();
            Self {
                client: reqwest::Client::new(),
                whitelist,
            }
        }

        fn build_whitelist() -> HashSet<String> {
            let mut set = HashSet::new();

            set.insert("trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey".to_string());
            set.insert("trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess".to_string());
            set.insert("trpc.o3.report.Report.SsoReport".to_string());
            set.insert("MessageSvc.PbSendMsg".to_string());
            set.insert("wtlogin.trans_emp".to_string());
            set.insert("wtlogin.login".to_string());
            set.insert("wtlogin.exchange_emp".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoKeyExchange".to_string());

            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginRefreshTicket".to_string());
            set.insert("trpc.login.ecdh.EcdhService.SsoNTLoginRefreshA2".to_string());

            set.insert("OidbSvcTrpcTcp.0x11ec_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x758_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x7c1_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x7c2_5".to_string());
            set.insert("OidbSvcTrpcTcp.0x10db_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x8a1_7".to_string());
            set.insert("OidbSvcTrpcTcp.0x89a_0".to_string());
            set.insert("OidbSvcTrpcTcp.0x89a_15".to_string());
            set.insert("OidbSvcTrpcTcp.0x88d_0".to_string());
            set.insert("OidbSvcTrpcTcp.0x88d_14".to_string());
            set.insert("OidbSvcTrpcTcp.0x112a_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x587_74".to_string());
            set.insert("OidbSvcTrpcTcp.0x587_103".to_string());
            set.insert("OidbSvcTrpcTcp.0x1100_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x1102_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x1103_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x1107_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x1105_1".to_string());
            set.insert("OidbSvcTrpcTcp.0xf88_1".to_string());
            set.insert("OidbSvcTrpcTcp.0xf89_1".to_string());
            set.insert("OidbSvcTrpcTcp.0xf57_1".to_string());
            set.insert("OidbSvcTrpcTcp.0xf57_106".to_string());
            set.insert("OidbSvcTrpcTcp.0xf57_9".to_string());
            set.insert("OidbSvcTrpcTcp.0xf55_1".to_string());
            set.insert("OidbSvcTrpcTcp.0xf67_1".to_string());
            set.insert("OidbSvcTrpcTcp.0xf67_5".to_string());
            set.insert("OidbSvcTrpcTcp.0x10c0_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x10c3_1".to_string());
            set.insert("OidbSvcTrpcTcp.0x1ba9".to_string());
            set.insert("OidbSvcTrpcTcp.0x6d9_4".to_string());

            set
        }

        pub fn is_whitelisted(&self, cmd: &str) -> bool {
            self.whitelist.contains(cmd)
        }

        async fn decode_hex_field(hex_str: &str) -> Result<Bytes, String> {
            hex::decode(hex_str)
                .map(Bytes::from)
                .map_err(|e| format!("Failed to decode hex string: {}", e))
        }
    }

    impl Default for DefaultSignProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl SignProvider for DefaultSignProvider {
        async fn sign(&self, cmd: &str, seq: u32, data: &[u8]) -> Option<SignResult> {
            if !self.is_whitelisted(cmd) {
                tracing::debug!(cmd = cmd,"Command not in whitelist, skipping sign");
                return None;
            }

            let request = SignRequest {
                cmd: cmd.to_string(),
                seq,
                src: hex::encode(data),
            };

            let response = match self.client
                .post(SIGN_API_URL)
                .json(&request)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!(error = %e, cmd = cmd, seq = seq, "Failed to send sign request");
                    return None;
                }
            };

            let sign_response: SignResponse = match response.json().await {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!(error = %e, cmd = cmd, seq = seq, "Failed to parse sign response");
                    return None;
                }
            };

            let sign = match Self::decode_hex_field(&sign_response.value.sign).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(error = e, field = "sign", "Failed to decode hex");
                    return None;
                }
            };

            let token = match Self::decode_hex_field(&sign_response.value.token).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(error = e, field = "token", "Failed to decode hex");
                    return None;
                }
            };

            let extra = match Self::decode_hex_field(&sign_response.value.extra).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(error = e, field = "extra", "Failed to decode hex");
                    return None;
                }
            };

            Some(SignResult {
                sign,
                token,
                extra,
            })
        }

        fn platform(&self) -> &str {
            "default"
        }
    }
}

#[cfg(feature = "sign-provider")]
pub use default::DefaultSignProvider;
