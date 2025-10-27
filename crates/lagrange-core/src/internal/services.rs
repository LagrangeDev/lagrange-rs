use crate::{
    context::BotContext,
    error::Result,
    protocol::{EventMessage, ProtocolEvent, ServiceMetadata},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::{any::TypeId, sync::Arc};

#[async_trait]
pub trait Service: Send + Sync {
    async fn parse(&self, input: Bytes, context: Arc<BotContext>) -> Result<EventMessage>;

    async fn build(&self, input: EventMessage, context: Arc<BotContext>) -> Result<Bytes>;

    fn metadata(&self) -> &ServiceMetadata;
}

#[async_trait]
pub trait BaseService: Send + Sync + Sized {
    type Request: ProtocolEvent + Clone;

    type Response: ProtocolEvent;

    async fn parse_impl(&self, _input: Bytes, _context: Arc<BotContext>) -> Result<Self::Response> {
        Err(crate::error::Error::ParseError(
            "parse not implemented".to_string(),
        ))
    }

    async fn build_impl(&self, _input: Self::Request, _context: Arc<BotContext>) -> Result<Bytes> {
        Err(crate::error::Error::BuildError(
            "build not implemented".to_string(),
        ))
    }

    fn metadata(&self) -> &ServiceMetadata;
}

/// Type alias for parse function results.
///
/// Use this in your service implementations for consistent, IDE-friendly type hints.
///
/// # Example
/// ```ignore
/// async fn parse(...) -> ParseResult<MyResponse> { ... }
/// ```
pub type ParseResult<T> = Result<T>;

/// Type alias for build function results.
///
/// Use this in your service implementations for consistent, IDE-friendly type hints.
///
/// # Example
/// ```ignore
/// async fn build(...) -> BuildResult { ... }
/// ```
pub type BuildResult = Result<Bytes>;

/// Helper trait for service function signatures.
///
/// This trait is NOT meant to be implemented directly. It exists solely to provide
/// IDE auto-completion hints for the expected function signatures in `define_service!`.
///
/// # Usage Hint
///
/// When writing functions inside `define_service!`, use these signatures:
///
/// ```ignore
/// async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<YourResponse> {
///     // Parse implementation
/// }
///
/// async fn build(request: YourRequest, context: Arc<BotContext>) -> Result<Bytes> {
///     // Build implementation
/// }
/// ```
///
/// You can also use the type aliases for cleaner code:
/// ```ignore
/// async fn parse(input: Bytes, context: Arc<BotContext>) -> ParseResult<YourResponse> { ... }
/// async fn build(request: YourRequest, context: Arc<BotContext>) -> BuildResult { ... }
/// ```
#[allow(unused)]
pub trait ServiceSignatures {
    /// Request event type
    type Request: ProtocolEvent;

    /// Response event type
    type Response: ProtocolEvent;

    /// Expected signature for parse function in `define_service!` macro.
    ///
    /// # Parameters
    /// - `input: Bytes` - The incoming packet data to parse
    /// - `context: Arc<BotContext>` - The bot context with configuration and state
    ///
    /// # Returns
    /// `Result<Self::Response>` - The parsed response event or an error
    async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<Self::Response>;

    /// Expected signature for build function in `define_service!` macro.
    ///
    /// # Parameters
    /// - `request: Self::Request` - The request event to serialize
    /// - `context: Arc<BotContext>` - The bot context with configuration and state
    ///
    /// # Returns
    /// `Result<Bytes>` - The serialized packet data or an error
    async fn build(request: Self::Request, context: Arc<BotContext>) -> Result<Bytes>;
}

// Blanket implementation: automatically implements Service for any BaseService
#[async_trait]
impl<T: BaseService> Service for T {
    async fn parse(&self, input: Bytes, context: Arc<BotContext>) -> Result<EventMessage> {
        let response = BaseService::parse_impl(self, input, context).await?;
        Ok(EventMessage::new(response))
    }

    async fn build(&self, input: EventMessage, context: Arc<BotContext>) -> Result<Bytes> {
        let event = input
            .downcast_ref::<T::Request>()
            .ok_or_else(|| crate::error::Error::ParseError("Invalid event type".to_string()))?
            .clone();

        BaseService::build_impl(self, event, context).await
    }

    fn metadata(&self) -> &ServiceMetadata {
        BaseService::metadata(self)
    }
}

pub struct ServiceRegistration {
    pub command: &'static str,
    pub factory: fn() -> Box<dyn Service>,
}

inventory::collect!(ServiceRegistration);

pub struct EventSubscription {
    pub event_type: TypeId,
    pub protocol_mask: u8,
    pub handler: fn(
        Arc<BotContext>,
        EventMessage,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Bytes>> + Send + 'static>,
    >,
}

inventory::collect!(EventSubscription);

#[derive(Debug, Clone)]
pub struct SsoPacket {
    pub sequence: u32,
    pub command: String,
    pub data: Bytes,
}

impl SsoPacket {
    pub fn new(sequence: u32, command: String, data: Bytes) -> Self {
        Self {
            sequence,
            command,
            data,
        }
    }
}

// Service modules
pub mod exchange_emp;
pub mod login;
pub mod message;
pub mod qrlogin;
pub mod trans_emp;
pub mod uin_resolve;

pub use exchange_emp::{ExchangeEmpCommand, ExchangeEmpServiceANDROID};
pub use login::{
    Command as LoginCommand, LoginEventReq, LoginEventResp, LoginServiceANDROID, LoginServicePC,
    States as LoginStates,
};
pub use message::{SendMessageEvent, SendMessageResponse, SendMessageService};
pub use qrlogin::{QrLoginCloseServiceANDROID, QrLoginVerifyServiceANDROID};
pub use trans_emp::{TransEmp12ServiceANDROID, TransEmp31ServiceANDROID};
pub use uin_resolve::UinResolveServiceANDROID;
