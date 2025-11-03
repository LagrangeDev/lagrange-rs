use crate::protocol::{EventMessage, ProtocolEvent};
use crate::config::BotConfig;
use super::{PacketContext, SocketContext};
use std::{any::TypeId, sync::Arc};
use tokio::sync::broadcast;

pub struct EventContext {
    sender: broadcast::Sender<EventMessage>,
    packet: Arc<PacketContext>,
    socket: Arc<SocketContext>,
    config: Arc<BotConfig>,
}

impl EventContext {
    pub fn new(
        packet: Arc<PacketContext>,
        socket: Arc<SocketContext>,
        config: Arc<BotConfig>,
    ) -> Arc<Self> {
        let (sender, _) = broadcast::channel(1024);
        Arc::new(Self {
            sender,
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

    /// Send a protocol event as a packet through the network and wait for response.
    ///
    /// This is the new type-safe API that uses `TypedService` to ensure compile-time
    /// correctness of request→response pairs.
    ///
    /// # Type Parameters
    ///
    /// * `S` - The service type that handles the request. Must implement `TypedService`.
    ///
    /// # Arguments
    ///
    /// * `request` - The request event to send
    /// * `context` - The bot context
    ///
    /// # Returns
    ///
    /// The typed response event matching the service's response type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let request = HeartbeatReq { /* ... */ };
    /// let response = event_ctx.send::<HeartbeatService>(request, context).await?;
    /// // response is HeartbeatResp (compile-time checked!)
    /// ```
    pub async fn send<S>(
        self: &Arc<Self>,
        request: S::Request,
        context: Arc<crate::context::BotContext>,
    ) -> Result<S::Response, crate::Error>
    where
        S: crate::protocol::TypedService,
    {
        use crate::internal::context::packet::ServiceAttribute;
        use std::any::TypeId;

        let request_type_id = TypeId::of::<S::Request>();
        let protocol = self.config.protocol as u8;

        // 1. Find the typed service entry by request type + protocol
        let registry = crate::internal::services::registry();
        let service_entry = registry
            .get_typed_service_by_request_and_protocol(request_type_id, protocol)
            .ok_or_else(|| {
                crate::Error::ServiceNotFound(format!(
                    "No typed service found for request type {:?} with protocol {:?}",
                    request_type_id, self.config.protocol
                ))
            })?;

        // 2. Build the outgoing packet (type-erased but type-safe)
        let request_any = Box::new(request) as Box<dyn std::any::Any + Send>;
        let bytes = service_entry.build(request_any, context.clone()).await?;

        // 3. Set up packet attributes
        let attributes = Some(
            ServiceAttribute::new()
                .with_request_type(service_entry.metadata.request_type)
                .with_encrypt_type(service_entry.metadata.encrypt_type),
        );

        // 4. Send the packet over the network
        let response_packet = self
            .packet
            .send_packet(
                service_entry.command.clone(),
                bytes,
                self.socket.clone(),
                attributes,
            )
            .await?;

        // 5. Parse the response (type-erased but type-safe)
        let response_any = service_entry.parse(response_packet.data, context).await?;

        // 6. Downcast the response to the concrete type
        // This is guaranteed safe because the service entry was created with
        // matching request/response types
        let response = response_any
            .downcast::<S::Response>()
            .map_err(|_| {
                crate::Error::ParseError(format!(
                    "Failed to downcast response to expected type {:?}",
                    TypeId::of::<S::Response>()
                ))
            })?;

        Ok(*response)
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
