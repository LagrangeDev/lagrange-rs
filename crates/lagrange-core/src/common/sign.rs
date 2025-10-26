use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

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
pub struct DefaultSignProvider;

#[async_trait]
impl SignProvider for DefaultSignProvider {
    async fn sign(&self, _cmd: &str, _seq: u32, _data: &[u8]) -> Option<SignResult> {
        None
    }

    fn platform(&self) -> &str {
        "default"
    }
}

impl Default for DefaultSignProvider {
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
