use crate::{
    common::{sign::BoxedSignProvider, sign::DefaultSignProvider},
    protocol::Protocols,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotConfig {
    pub protocol: Protocols,

    #[serde(default)]
    pub use_ipv6_network: bool,

    #[serde(default = "default_true")]
    pub auto_reconnect: bool,

    #[serde(default = "default_true")]
    pub auto_re_login: bool,

    #[serde(default = "default_true")]
    pub get_optimum_server: bool,

    #[serde(default)]
    pub log_level: LogLevel,

    #[serde(default = "default_highway_chunk_size")]
    pub highway_chunk_size: usize,

    #[serde(default = "default_highway_concurrent")]
    pub highway_concurrent: usize,

    #[serde(skip)]
    pub sign_provider: Option<BoxedSignProvider>,

    #[serde(default)]
    pub verbose: bool,

    #[serde(default)]
    pub custom: std::collections::HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

fn default_highway_chunk_size() -> usize {
    1024 * 1024
}

fn default_highway_concurrent() -> usize {
    4
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            protocol: Protocols::Linux,
            use_ipv6_network: false,
            auto_reconnect: true,
            auto_re_login: true,
            get_optimum_server: true,
            log_level: LogLevel::Info,
            highway_chunk_size: 1024 * 1024,
            highway_concurrent: 4,
            sign_provider: None,
            verbose: false,
            custom: Default::default(),
        }
    }
}

impl BotConfig {
    pub fn builder() -> BotConfigBuilder {
        BotConfigBuilder::default()
    }

    pub fn get_sign_provider(&self) -> BoxedSignProvider {
        self.sign_provider
            .clone()
            .unwrap_or_else(|| Arc::new(DefaultSignProvider))
    }
}

#[derive(Default)]
pub struct BotConfigBuilder {
    protocol: Option<Protocols>,
    use_ipv6_network: Option<bool>,
    auto_reconnect: Option<bool>,
    auto_re_login: Option<bool>,
    get_optimum_server: Option<bool>,
    log_level: Option<LogLevel>,
    highway_chunk_size: Option<usize>,
    highway_concurrent: Option<usize>,
    sign_provider: Option<BoxedSignProvider>,
    verbose: Option<bool>,
}

impl BotConfigBuilder {
    pub fn protocol(mut self, protocol: Protocols) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn use_ipv6(mut self, enabled: bool) -> Self {
        self.use_ipv6_network = Some(enabled);
        self
    }

    pub fn auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = Some(enabled);
        self
    }

    pub fn auto_re_login(mut self, enabled: bool) -> Self {
        self.auto_re_login = Some(enabled);
        self
    }

    pub fn get_optimum_server(mut self, enabled: bool) -> Self {
        self.get_optimum_server = Some(enabled);
        self
    }

    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    pub fn highway_chunk_size(mut self, size: usize) -> Self {
        self.highway_chunk_size = Some(size.min(1024 * 1024));
        self
    }

    pub fn highway_concurrent(mut self, concurrent: usize) -> Self {
        self.highway_concurrent = Some(concurrent);
        self
    }

    pub fn sign_provider(mut self, provider: BoxedSignProvider) -> Self {
        self.sign_provider = Some(provider);
        self
    }

    pub fn verbose(mut self, enabled: bool) -> Self {
        self.verbose = Some(enabled);
        self
    }

    pub fn build(self) -> BotConfig {
        BotConfig {
            protocol: self.protocol.unwrap_or(Protocols::Linux),
            use_ipv6_network: self.use_ipv6_network.unwrap_or(false),
            auto_reconnect: self.auto_reconnect.unwrap_or(true),
            auto_re_login: self.auto_re_login.unwrap_or(true),
            get_optimum_server: self.get_optimum_server.unwrap_or(true),
            log_level: self.log_level.unwrap_or(LogLevel::Info),
            highway_chunk_size: self.highway_chunk_size.unwrap_or(1024 * 1024),
            highway_concurrent: self.highway_concurrent.unwrap_or(4),
            sign_provider: self.sign_provider,
            verbose: self.verbose.unwrap_or(false),
            custom: Default::default(),
        }
    }
}
