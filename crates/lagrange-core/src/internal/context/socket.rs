use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct SocketContext {
    outbound_tx: mpsc::UnboundedSender<Bytes>,

    outbound_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<Bytes>>>,

    connected: std::sync::RwLock<bool>,
}

impl SocketContext {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            outbound_tx: tx,
            outbound_rx: std::sync::Mutex::new(Some(rx)),
            connected: std::sync::RwLock::new(false),
        })
    }

    pub fn send(&self, data: Bytes) -> crate::error::Result<()> {
        self.outbound_tx
            .send(data)
            .map_err(|_| crate::error::Error::NetworkError("Socket closed".to_string()))
    }

    pub fn take_outbound_receiver(&self) -> Option<mpsc::UnboundedReceiver<Bytes>> {
        self.outbound_rx.lock().expect("Mutex poisoned").take()
    }

    pub fn set_connected(&self, connected: bool) {
        *self.connected.write().expect("RwLock poisoned") = connected;
    }

    pub fn is_connected(&self) -> bool {
        *self.connected.read().expect("RwLock poisoned")
    }
}

impl Default for SocketContext {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            outbound_tx: tx,
            outbound_rx: std::sync::Mutex::new(Some(rx)),
            connected: std::sync::RwLock::new(false),
        }
    }
}

impl Drop for SocketContext {
    fn drop(&mut self) {
    }
}
