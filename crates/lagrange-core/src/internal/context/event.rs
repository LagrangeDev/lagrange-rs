use crate::protocol::{EventMessage, ProtocolEvent};
use std::{any::TypeId, sync::Arc};
use tokio::sync::broadcast;

pub struct EventContext {
    sender: broadcast::Sender<EventMessage>,
}

impl EventContext {
    pub fn new() -> Arc<Self> {
        let (sender, _) = broadcast::channel(1024);
        Arc::new(Self { sender })
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

impl Default for EventContext {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self { sender }
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
    fn drop(&mut self) {
    }
}
