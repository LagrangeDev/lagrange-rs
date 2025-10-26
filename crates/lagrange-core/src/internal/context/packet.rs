use crate::{
    error::{Error, Result},
    internal::services::SsoPacket,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use tokio::sync::oneshot;

pub struct PacketContext {
    sequence: AtomicU32,

    pending_tasks: DashMap<u32, oneshot::Sender<SsoPacket>>,
}

impl PacketContext {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sequence: AtomicU32::new(1),
            pending_tasks: DashMap::new(),
        })
    }

    pub fn next_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn send_packet(
        &self,
        command: String,
        data: Bytes,
        socket: Arc<super::SocketContext>,
    ) -> Result<SsoPacket> {
        let sequence = self.next_sequence();
        let (tx, rx) = oneshot::channel();

        self.pending_tasks.insert(sequence, tx);

        let packet = SsoPacket::new(sequence, command, data);

        let encoded = self.encode_packet(&packet)?;
        socket.send(encoded)?;

        let response = rx.await.map_err(|_| {
            self.pending_tasks.remove(&sequence);
            Error::NetworkError("Response channel closed".to_string())
        })?;

        Ok(response)
    }

    pub fn dispatch_packet(&self, packet: SsoPacket) -> Option<SsoPacket> {
        if let Some((_, sender)) = self.pending_tasks.remove(&packet.sequence) {
            let _ = sender.send(packet);
            None
        } else {
            Some(packet)
        }
    }

    fn encode_packet(&self, packet: &SsoPacket) -> Result<Bytes> {
        Ok(packet.data.clone())
    }

    pub fn decode_packet(&self, data: Bytes) -> Result<SsoPacket> {
        Ok(SsoPacket::new(0, "unknown".to_string(), data))
    }
}

impl Default for PacketContext {
    fn default() -> Self {
        Self {
            sequence: AtomicU32::new(1),
            pending_tasks: DashMap::new(),
        }
    }
}
