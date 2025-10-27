use crate::{
    common::BotAppInfo,
    config::BotConfig,
    internal::context::{CacheContext, EventContext, PacketContext, ServiceContext, SocketContext},
    keystore::BotKeystore,
    protocol::{EventMessage, ProtocolEvent},
};
use std::sync::Arc;

pub struct BotContext {
    pub config: BotConfig,

    pub app_info: BotAppInfo,

    pub keystore: std::sync::RwLock<BotKeystore>,

    pub cache: Arc<CacheContext>,

    pub packet: Arc<PacketContext>,

    pub service: Arc<ServiceContext>,

    pub socket: Arc<SocketContext>,

    pub event: Arc<EventContext>,

    is_online: std::sync::RwLock<bool>,
}

impl BotContext {
    pub fn builder() -> BotContextBuilder {
        BotContextBuilder::default()
    }

    pub fn bot_uin(&self) -> Option<u64> {
        self.keystore.read().expect("RwLock poisoned").uin
    }

    pub fn bot_uid(&self) -> Option<String> {
        self.keystore.read().expect("RwLock poisoned").uid.clone()
    }

    pub fn is_online(&self) -> bool {
        *self.is_online.read().expect("RwLock poisoned")
    }

    pub fn set_online(&self, online: bool) {
        *self.is_online.write().expect("RwLock poisoned") = online;
    }

    pub fn post_event(&self, event: EventMessage) {
        self.event.post_event(event);
    }

    pub fn post<T: ProtocolEvent>(&self, event: T) {
        self.event.post(event);
    }

    /// Creates a tracing span with bot context (uin, uid, online status)
    ///
    /// # Example
    /// ```no_run
    /// let _span = context.span().entered();
    /// tracing::info!("Processing message"); // Will include bot context
    /// ```
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!(
            "bot",
            uin = ?self.bot_uin(),
            uid = ?self.bot_uid(),
            online = self.is_online()
        )
    }
}

pub struct BotContextBuilder {
    config: Option<BotConfig>,
    app_info: Option<BotAppInfo>,
    keystore: Option<BotKeystore>,
}

impl Default for BotContextBuilder {
    fn default() -> Self {
        Self {
            config: Some(BotConfig::default()),
            app_info: Some(BotAppInfo::default()),
            keystore: Some(BotKeystore::default()),
        }
    }
}

impl BotContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn config(mut self, config: BotConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn app_info(mut self, app_info: BotAppInfo) -> Self {
        self.app_info = Some(app_info);
        self
    }

    pub fn keystore(mut self, keystore: BotKeystore) -> Self {
        self.keystore = Some(keystore);
        self
    }

    pub fn build(self) -> Arc<BotContext> {
        let config = self.config.expect("Config is required");
        let app_info = self.app_info.expect("AppInfo is required");
        let keystore = self.keystore.expect("Keystore is required");

        let cache = CacheContext::new();
        let socket = SocketContext::new();
        let event = EventContext::new();

        let keystore_arc = Arc::new(std::sync::RwLock::new(keystore.clone()));
        let app_info_arc = Arc::new(app_info.clone());

        // PacketContext needs keystore, app_info, and config
        let packet = PacketContext::new(keystore_arc, app_info_arc, &config);

        let service = ServiceContext::new(&config);

        Arc::new(BotContext {
            config,
            app_info,
            keystore: std::sync::RwLock::new(keystore),
            cache,
            packet,
            service,
            socket,
            event,
            is_online: std::sync::RwLock::new(false),
        })
    }
}

impl Drop for BotContext {
    fn drop(&mut self) {
        tracing::debug!(
            uin = ?self.bot_uin(),
            uid = ?self.bot_uid(),
            "BotContext dropping - cleaning up resources"
        );
    }
}
