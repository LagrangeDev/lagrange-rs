use crate::{
    context::BotContext,
    error::Result,
    protocol::{EventMessage, ServiceMetadata},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    any::TypeId,
    collections::HashMap,
    sync::{Arc, OnceLock},
};

/// Core service trait that all services must implement.
///
/// Services handle protocol commands by:
/// - `parse`: Converting incoming bytes to typed events
/// - `build`: Converting typed events to outgoing bytes
///
/// Unlike the previous `BaseService` design, this trait works with
/// untyped `EventMessage` to support multiple event types per service.
#[async_trait]
pub trait Service: Send + Sync {
    /// Parse incoming packet bytes into an event.
    async fn parse(&self, input: Bytes, context: Arc<BotContext>) -> Result<EventMessage>;

    /// Build outgoing packet bytes from an event.
    async fn build(&self, input: EventMessage, context: Arc<BotContext>) -> Result<Bytes>;

    /// Get service metadata (command, encryption, etc.)
    fn metadata(&self) -> &ServiceMetadata;
}

/// Mapping from an event type to a service with protocol filtering.
#[derive(Clone)]
pub struct EventMapping {
    /// The service instance that handles this event
    pub service: Arc<dyn Service>,
    /// Protocol bitmask - only handle this event on matching protocols
    pub protocol: u8,
}

/// Global service registry - singleton instance.
///
/// This replaces the inventory-based registration system with a manual
/// registration approach similar to C#'s reflection-based discovery.
pub struct ServiceRegistry {
    /// Maps command strings to service instances
    services: HashMap<String, Arc<dyn Service>>,
    /// Maps event TypeId to service instances with protocol filters
    services_by_event: HashMap<TypeId, Vec<EventMapping>>,
}

impl ServiceRegistry {
    /// Create a new empty registry
    fn new() -> Self {
        Self {
            services: HashMap::new(),
            services_by_event: HashMap::new(),
        }
    }

    /// Register a service with a command
    pub fn register_service(&mut self, command: String, service: Arc<dyn Service>) {
        self.services.insert(command, service);
    }

    /// Register an event subscription for a service
    pub fn register_event(&mut self, event_type: TypeId, service: Arc<dyn Service>, protocol: u8) {
        self.services_by_event
            .entry(event_type)
            .or_default()
            .push(EventMapping { service, protocol });
    }

    /// Get service by command
    pub fn get_service(&self, command: &str) -> Option<&Arc<dyn Service>> {
        self.services.get(command)
    }

    /// Get service mappings by event type
    pub fn get_event_mappings(&self, event_type: TypeId) -> Option<&Vec<EventMapping>> {
        self.services_by_event.get(&event_type)
    }

    /// Get all services
    pub fn services(&self) -> &HashMap<String, Arc<dyn Service>> {
        &self.services
    }
}

/// Global registry instance
static REGISTRY: OnceLock<ServiceRegistry> = OnceLock::new();

/// Get or initialize the global service registry
pub fn registry() -> &'static ServiceRegistry {
    REGISTRY.get_or_init(|| {
        let mut registry = ServiceRegistry::new();
        // Call all registration functions
        __register_all_services(&mut registry);
        registry
    })
}

/// Called by generated code to register all services
///
/// This function is implemented by the macro system - each `define_service!`
/// invocation adds its registration to this function via linkme or similar.
#[linkme::distributed_slice]
pub static SERVICE_INITIALIZERS: [fn(&mut ServiceRegistry)];

fn __register_all_services(registry: &mut ServiceRegistry) {
    for initializer in SERVICE_INITIALIZERS {
        initializer(registry);
    }
}

pub use crate::internal::packets::SsoPacket;

use lagrange_macros::auto_reexport;

auto_reexport! {
    pub mod login;
    pub mod system;
}

// Re-export renamed types for backward compatibility
pub use login::{LoginCommand, LoginStates};
