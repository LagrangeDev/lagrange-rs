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
pub mod login;
pub mod message;

pub use login::{LoginEvent, LoginResponse, LoginService};
pub use message::{SendMessageEvent, SendMessageResponse, SendMessageService};
