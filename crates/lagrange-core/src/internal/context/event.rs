use crate::protocol::{EventMessage, ProtocolEvent};
use crate::config::BotConfig;
use super::{PacketContext, ServiceContext, SocketContext};
use std::{any::TypeId, sync::Arc};
use tokio::sync::broadcast;

pub struct EventContext {
    sender: broadcast::Sender<EventMessage>,
    service: Arc<ServiceContext>,
    packet: Arc<PacketContext>,
    socket: Arc<SocketContext>,
    config: Arc<BotConfig>,
}

impl EventContext {
    pub fn new(
        service: Arc<ServiceContext>,
        packet: Arc<PacketContext>,
        socket: Arc<SocketContext>,
        config: Arc<BotConfig>,
    ) -> Arc<Self> {
        let (sender, _) = broadcast::channel(1024);
        Arc::new(Self {
            sender,
            service,
            packet,
            socket,
            config,
        })
    }

    pub fn post_event(&self, event: EventMessage) {
        let _ = self.sender.send(event);
    }

    pub fn post<T: ProtocolEvent>(&self, event: T) {
        self.post_event(EventMessage::new(event));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventMessage> {
        self.sender.subscribe()
    }

    pub fn subscribe_to<T: 'static>(&self) -> TypedEventReceiver<T> {
        TypedEventReceiver {
            receiver: self.sender.subscribe(),
            type_id: TypeId::of::<T>(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Send a protocol event as a packet through the network and wait for response
    pub async fn send_event<T>(
        self: &Arc<Self>,
        context: Arc<crate::context::BotContext>,
        event: T,
    ) -> Result<(), crate::Error>
    where
        T: ProtocolEvent,
    {
        use crate::internal::context::packet::ServiceAttribute;

        let event_msg = EventMessage::new(event);
        let bytes = self.service.resolve_outgoing(event_msg.clone(), context.clone()).await?;

        let event_type = event_msg.type_id();
        let mappings = crate::internal::services::registry()
            .get_event_mappings(event_type)
            .ok_or_else(|| crate::Error::ServiceNotFound(format!("event type {:?}", event_type)))?;

        let service = mappings
            .iter()
            .find(|m| (self.config.protocol as u8) & m.protocol != 0)
            .ok_or_else(|| crate::Error::ServiceNotFound(format!("No service for protocol {:?}", self.config.protocol)))?;

        let metadata = service.service.metadata();

        let attributes = Some(ServiceAttribute::new()
            .with_request_type(metadata.request_type)
            .with_encrypt_type(metadata.encrypt_type));

        let response = self.packet.send_packet(
            metadata.command.to_string(),
            bytes,
            self.socket.clone(),
            attributes,
        ).await?;

        let response_event = self.service.resolve_incoming(&response, context).await?;
        self.post_event(response_event);

        Ok(())
    }
}

pub struct TypedEventReceiver<T> {
    receiver: broadcast::Receiver<EventMessage>,
    type_id: TypeId,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: 'static> TypedEventReceiver<T> {
    pub async fn recv(&mut self) -> Result<Arc<T>, broadcast::error::RecvError> {
        loop {
            let event = self.receiver.recv().await?;
            if event.type_id() == self.type_id {
                if let Some(typed) = event.downcast::<T>() {
                    return Ok(typed);
                }
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<Arc<T>, broadcast::error::TryRecvError> {
        loop {
            let event = self.receiver.try_recv()?;
            if event.type_id() == self.type_id {
                if let Some(typed) = event.downcast::<T>() {
                    return Ok(typed);
                }
            }
        }
    }
}


impl<T> Clone for TypedEventReceiver<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.resubscribe(),
            type_id: self.type_id,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl Drop for EventContext {
    fn drop(&mut self) {}
}
