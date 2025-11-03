use crate::{
    config::BotConfig,
    internal::services::registry,
    protocol::Protocols,
};
use std::sync::Arc;

pub struct ServiceContext {
    disabled_log: std::collections::HashSet<String>,
    #[allow(dead_code)]
    protocol: Protocols,
}

impl ServiceContext {
    pub fn new(config: &BotConfig) -> Arc<Self> {
        let mut disabled_log = std::collections::HashSet::new();

        let reg = registry();

        for (command, service_entry) in reg.typed_services() {
            if service_entry.metadata.disable_log {
                disabled_log.insert(command.clone());
            }
        }

        Arc::new(Self {
            disabled_log,
            protocol: config.protocol,
        })
    }

    pub fn is_log_disabled(&self, command: &str) -> bool {
        self.disabled_log.contains(command)
    }
}
