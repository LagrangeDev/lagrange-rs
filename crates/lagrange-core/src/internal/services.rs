use crate::{
    context::BotContext,
    error::Result,
    protocol::{ServiceMetadata, TypedService},
};
use bytes::Bytes;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
};

/// Type alias for boxed futures to simplify type signatures
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Entry for a typed service in the registry.
///
/// This stores type-erased dispatch functions that maintain type safety through
/// the registration process. Each ServiceEntry represents a single request→response
/// mapping for a specific service implementation.
pub struct TypedServiceEntry {
    /// The command name for this service
    pub command: String,

    /// Service metadata (encryption, request type, etc.)
    pub metadata: ServiceMetadata,

    /// TypeId of the request type
    pub request_type_id: TypeId,

    /// TypeId of the response type
    pub response_type_id: TypeId,

    /// Protocol bitmask for filtering (e.g., PC | Android)
    pub protocol_mask: u8,

    /// Type-erased build function: Request -> Bytes
    ///
    /// The Box<dyn Any + Send> must contain the concrete Request type.
    /// This is guaranteed safe by the registration process.
    build_fn: Arc<
        dyn Fn(Box<dyn Any + Send>, Arc<BotContext>) -> BoxFuture<'static, Result<Bytes>> + Send + Sync,
    >,

    /// Type-erased parse function: Bytes -> Response
    ///
    /// Returns Box<dyn Any> containing the concrete Response type.
    /// This is guaranteed safe by the registration process.
    parse_fn: Arc<
        dyn Fn(Bytes, Arc<BotContext>) -> BoxFuture<'static, Result<Box<dyn Any + Send>>>
            + Send
            + Sync,
    >,
}

impl TypedServiceEntry {
    /// Execute the build function with a type-erased request.
    ///
    /// # Safety
    ///
    /// The caller must ensure the `request` contains the correct request type
    /// (matching `request_type_id`). This is enforced by the type system at
    /// the call sites.
    pub async fn build(&self, request: Box<dyn Any + Send>, context: Arc<BotContext>) -> Result<Bytes> {
        (self.build_fn)(request, context).await
    }

    /// Execute the parse function to produce a type-erased response.
    ///
    /// The returned `Box<dyn Any>` contains the response type matching `response_type_id`.
    pub async fn parse(&self, bytes: Bytes, context: Arc<BotContext>) -> Result<Box<dyn Any + Send>> {
        (self.parse_fn)(bytes, context).await
    }
}

/// Global service registry - singleton instance.
///
/// This registry maintains typed services that provide compile-time type safety.
pub struct ServiceRegistry {
    /// Typed services: Maps command strings to typed service entries
    typed_services_by_command: HashMap<String, Arc<TypedServiceEntry>>,

    /// Typed services: Maps (request TypeId, protocol) to typed service entries
    /// This allows looking up services by the request type they handle
    typed_services_by_request: HashMap<TypeId, Vec<Arc<TypedServiceEntry>>>,
}

impl ServiceRegistry {
    /// Create a new empty registry
    fn new() -> Self {
        Self {
            typed_services_by_command: HashMap::new(),
            typed_services_by_request: HashMap::new(),
        }
    }

    /// Register a typed service.
    ///
    /// This creates type-erased dispatch functions while maintaining type safety
    /// through the generic parameters. The service can later be looked up by
    /// either its command string or its request type.
    ///
    /// # Type Parameters
    ///
    /// * `S` - The service type implementing `TypedService`
    ///
    /// # Arguments
    ///
    /// * `service` - The service instance to register
    /// * `protocol_mask` - Protocol bitmask for filtering (e.g., `Protocols::PC`)
    pub fn register_typed_service<S>(&mut self, service: S, protocol_mask: u8)
    where
        S: TypedService + 'static,
    {
        let metadata = service.metadata().clone();
        let service = Arc::new(service);

        // Create type-erased build function
        let build_fn = {
            let service = Arc::clone(&service);
            Arc::new(
                move |request_any: Box<dyn Any + Send>, context: Arc<BotContext>| -> BoxFuture<'static, Result<Bytes>> {
                    let service = Arc::clone(&service);
                    let future = async move {
                        // Downcast the type-erased request to the concrete type
                        let request = request_any
                            .downcast::<S::Request>()
                            .expect("Type safety violated in build_fn");
                        service.build(&*request, context).await
                    };
                    Box::pin(future)
                },
            )
                as Arc<
                    dyn Fn(Box<dyn Any + Send>, Arc<BotContext>) -> BoxFuture<'static, Result<Bytes>>
                        + Send
                        + Sync,
                >
        };

        // Create type-erased parse function
        let parse_fn = {
            let service = Arc::clone(&service);
            Arc::new(
                move |bytes: Bytes, context: Arc<BotContext>| -> BoxFuture<'static, Result<Box<dyn Any + Send>>> {
                    let service = Arc::clone(&service);
                    let future = async move {
                        let response = service.parse(bytes, context).await?;
                        Ok(Box::new(response) as Box<dyn Any + Send>)
                    };
                    Box::pin(future)
                },
            )
                as Arc<
                    dyn Fn(Bytes, Arc<BotContext>) -> BoxFuture<'static, Result<Box<dyn Any + Send>>>
                        + Send
                        + Sync,
                >
        };

        // Create the service entry
        let entry = Arc::new(TypedServiceEntry {
            command: metadata.command.to_string(),
            metadata,
            request_type_id: TypeId::of::<S::Request>(),
            response_type_id: TypeId::of::<S::Response>(),
            protocol_mask,
            build_fn,
            parse_fn,
        });

        // Register by command
        self.typed_services_by_command
            .insert(entry.command.clone(), Arc::clone(&entry));

        // Register by request type
        self.typed_services_by_request
            .entry(entry.request_type_id)
            .or_default()
            .push(entry);
    }

    /// Get typed service by command name.
    pub fn get_typed_service_by_command(&self, command: &str) -> Option<&Arc<TypedServiceEntry>> {
        self.typed_services_by_command.get(command)
    }

    /// Get all typed services by command.
    ///
    /// Returns an iterator over all (command, service_entry) pairs.
    pub fn typed_services(&self) -> impl Iterator<Item = (&String, &Arc<TypedServiceEntry>)> {
        self.typed_services_by_command.iter()
    }

    /// Get all typed services that handle a specific request type.
    ///
    /// Returns a list of service entries, which may have different protocol masks.
    pub fn get_typed_services_by_request(&self, request_type: TypeId) -> Option<&Vec<Arc<TypedServiceEntry>>> {
        self.typed_services_by_request.get(&request_type)
    }

    /// Get typed service by request type and protocol.
    ///
    /// Returns the first service that handles the given request type and matches
    /// the protocol filter.
    ///
    /// # Arguments
    ///
    /// * `request_type` - The TypeId of the request type
    /// * `protocol` - The protocol value to match against service protocol masks
    pub fn get_typed_service_by_request_and_protocol(
        &self,
        request_type: TypeId,
        protocol: u8,
    ) -> Option<&Arc<TypedServiceEntry>> {
        self.typed_services_by_request
            .get(&request_type)?
            .iter()
            .find(|entry| entry.protocol_mask & protocol != 0)
            .map(|arc| arc)
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
/// invocation adds its registration to this function via linkme.
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
