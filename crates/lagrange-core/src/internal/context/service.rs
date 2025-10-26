use crate::{
    config::BotConfig,
    error::{Error, Result},
    internal::service::{Service, ServiceRegistration, SsoPacket},
    protocol::{EventMessage, Protocols},
};
use bytes::Bytes;
use dashmap::DashMap;
use std::{any::TypeId, collections::HashMap, sync::Arc};

pub struct ServiceContext {
    services: HashMap<String, Box<dyn Service>>,

    services_by_event: DashMap<TypeId, Box<dyn Service>>,

    disabled_log: std::collections::HashSet<String>,

    #[allow(dead_code)]
    protocol: Protocols,
}

impl ServiceContext {
    pub fn new(config: &BotConfig) -> Arc<Self> {
        let mut services = HashMap::new();
        let mut disabled_log = std::collections::HashSet::new();

        for registration in inventory::iter::<ServiceRegistration> {
            let service = (registration.factory)();
            let command = service.metadata().command.to_string();
            let disable_log = service.metadata().disable_log;

            services.insert(command.clone(), service);

            if disable_log {
                disabled_log.insert(command);
            }
        }

        Arc::new(Self {
            services,
            services_by_event: DashMap::new(),
            disabled_log,
            protocol: config.protocol,
        })
    }

    pub async fn resolve_incoming(
        &self,
        packet: &SsoPacket,
        context: Arc<crate::context::BotContext>,
    ) -> Result<EventMessage> {
        let service = self
            .services
            .get(&packet.command)
            .ok_or_else(|| Error::ServiceNotFound(packet.command.clone()))?;

        if !self.disabled_log.contains(&packet.command) {
            tracing::debug!("Parsing packet: {}", packet.command);
        }

        service.parse(packet.data.clone(), context).await
    }

    pub async fn resolve_outgoing(
        &self,
        event: EventMessage,
        context: Arc<crate::context::BotContext>,
    ) -> Result<Bytes> {
        let event_type = event.type_id();
        let service = self
            .services_by_event
            .get(&event_type)
            .ok_or_else(|| Error::ServiceNotFound(format!("event type {:?}", event_type)))?;

        service.build(event, context).await
    }

    pub fn register_event_handler(&self, event_type: TypeId, service: Box<dyn Service>) {
        self.services_by_event.insert(event_type, service);
    }

    pub fn is_log_disabled(&self, command: &str) -> bool {
        self.disabled_log.contains(command)
    }
}
