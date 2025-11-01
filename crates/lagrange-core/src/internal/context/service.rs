use crate::{
    config::BotConfig,
    error::{Error, Result},
    internal::services::{registry, SsoPacket},
    protocol::{EventMessage, Protocols},
};
use bytes::Bytes;
use std::sync::Arc;

pub struct ServiceContext {
    disabled_log: std::collections::HashSet<String>,
    protocol: Protocols,
}

impl ServiceContext {
    pub fn new(config: &BotConfig) -> Arc<Self> {
        let mut disabled_log = std::collections::HashSet::new();

        // Get services from global registry
        let reg = registry();
        for (command, service) in reg.services() {
            if service.metadata().disable_log {
                disabled_log.insert(command.clone());
            }
        }

        Arc::new(Self {
            disabled_log,
            protocol: config.protocol,
        })
    }

    pub async fn resolve_incoming(
        &self,
        packet: &SsoPacket,
        context: Arc<crate::context::BotContext>,
    ) -> Result<EventMessage> {
        let reg = registry();
        let service = reg
            .get_service(&packet.command)
            .ok_or_else(|| Error::ServiceNotFound(packet.command.clone()))?;

        if !self.disabled_log.contains(&packet.command) {
            tracing::debug!(
                command = %packet.command,
                data_len = packet.data.len(),
                "Parsing incoming packet"
            );
        }

        service.parse(packet.data.clone(), context).await
    }

    pub async fn resolve_outgoing(
        &self,
        event: EventMessage,
        context: Arc<crate::context::BotContext>,
    ) -> Result<Bytes> {
        let event_type = event.type_id();
        let reg = registry();

        let mappings = reg
            .get_event_mappings(event_type)
            .ok_or_else(|| Error::ServiceNotFound(format!("event type {:?}", event_type)))?;

        // Filter by protocol - find first matching service
        for mapping in mappings {
            // Check if this service's protocol mask matches our configured protocol
            if self.protocol_matches(mapping.protocol) {
                return mapping.service.build(event, context).await;
            }
        }

        Err(Error::ServiceNotFound(format!(
            "No service for event type {:?} matching protocol {:?}",
            event_type, self.protocol
        )))
    }

    /// Check if the service's protocol filter matches the configured protocol
    fn protocol_matches(&self, service_protocol_mask: u8) -> bool {
        // Check if the service's protocol mask includes our configured protocol
        // This uses bitwise AND to check if our protocol bit is set in the mask
        (self.protocol as u8) & service_protocol_mask != 0
    }

    pub fn is_log_disabled(&self, command: &str) -> bool {
        self.disabled_log.contains(command)
    }
}
