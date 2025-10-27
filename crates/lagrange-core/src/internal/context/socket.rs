use bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const IPV4_SERVER: &str = "msfwifi.3g.qq.com:8080";
const IPV6_SERVER: &str = "msfwifiv6.3g.qq.com:8080";
const HEADER_SIZE: usize = 4;

pub struct SocketContext {
    outbound_tx: mpsc::UnboundedSender<Bytes>,
    outbound_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<Bytes>>>,
    connected: std::sync::RwLock<bool>,

    read_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    write_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SocketContext {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            outbound_tx: tx,
            outbound_rx: std::sync::Mutex::new(Some(rx)),
            connected: std::sync::RwLock::new(false),
            read_task: std::sync::Mutex::new(None),
            write_task: std::sync::Mutex::new(None),
        })
    }

    pub fn send(&self, data: Bytes) -> crate::error::Result<()> {
        self.outbound_tx
            .send(data)
            .map_err(|_| crate::error::Error::NetworkError("Socket closed".to_string()))
    }

    pub fn set_connected(&self, connected: bool) {
        *self.connected.write().expect("RwLock poisoned") = connected;
    }

    pub fn is_connected(&self) -> bool {
        *self.connected.read().expect("RwLock poisoned")
    }

    pub async fn connect(
        self: &Arc<Self>,
        use_ipv6: bool,
        packet_ctx: Arc<super::PacketContext>,
    ) -> crate::error::Result<()> {
        self.disconnect().await;

        let server = if use_ipv6 { IPV6_SERVER } else { IPV4_SERVER };

        let stream = TcpStream::connect(server)
            .await
            .map_err(|e| crate::error::Error::NetworkError(format!("Failed to connect: {}", e)))?;
        let (read_half, write_half) = stream.into_split();
        let outbound_rx = self
            .outbound_rx
            .lock()
            .expect("Mutex poisoned")
            .take()
            .ok_or_else(|| {
                crate::error::Error::NetworkError("Outbound receiver already taken".to_string())
            })?;
        self.set_connected(true);

        let read_task = {
            let packet_ctx = packet_ctx.clone();
            let self_ref = Arc::downgrade(self);

            tokio::spawn(async move {
                if let Err(e) = Self::read_loop(read_half, packet_ctx, self_ref).await {
                    tracing::error!(error = %e, "Socket read loop terminated");
                }
            })
        };

        let write_task = {
            let self_ref = Arc::downgrade(self);

            tokio::spawn(async move {
                if let Err(e) = Self::write_loop(write_half, outbound_rx, self_ref).await {
                    tracing::error!(error = %e, "Socket write loop terminated");
                }
            })
        };

        *self.read_task.lock().expect("Mutex poisoned") = Some(read_task);
        *self.write_task.lock().expect("Mutex poisoned") = Some(write_task);

        Ok(())
    }

    async fn read_loop(
        mut reader: tokio::net::tcp::OwnedReadHalf,
        packet_ctx: Arc<super::PacketContext>,
        socket_ctx: std::sync::Weak<SocketContext>,
    ) -> crate::error::Result<()> {
        let mut header_buf = [0u8; HEADER_SIZE];

        loop {
            reader.read_exact(&mut header_buf).await.map_err(|e| {
                if let Some(ctx) = socket_ctx.upgrade() {
                    ctx.set_connected(false);
                }
                crate::error::Error::NetworkError(format!("Failed to read header: {}", e))
            })?;

            let length = u32::from_be_bytes(header_buf) as usize;
            let mut data = BytesMut::zeroed(length);
            reader.read_exact(&mut data).await.map_err(|e| {
                if let Some(ctx) = socket_ctx.upgrade() {
                    ctx.set_connected(false);
                }
                crate::error::Error::NetworkError(format!("Failed to read packet: {}", e))
            })?;
            if let Ok(packet) = packet_ctx.decode_packet(data.freeze()) {
                if let Some(packet) = packet_ctx.dispatch_packet(packet) {
                    drop(packet);
                }
            }
        }
    }

    async fn write_loop(
        mut writer: tokio::net::tcp::OwnedWriteHalf,
        mut outbound_rx: mpsc::UnboundedReceiver<Bytes>,
        socket_ctx: std::sync::Weak<SocketContext>,
    ) -> crate::error::Result<()> {
        while let Some(data) = outbound_rx.recv().await {
            let length = data.len() as u32;
            let mut buffer = BytesMut::with_capacity(HEADER_SIZE + data.len());
            buffer.put_u32(length); // Big-endian
            buffer.put(data);

            writer.write_all(&buffer).await.map_err(|e| {
                if let Some(ctx) = socket_ctx.upgrade() {
                    ctx.set_connected(false);
                }
                crate::error::Error::NetworkError(format!("Failed to write packet: {}", e))
            })?;
        }

        Ok(())
    }

    pub async fn disconnect(&self) {
        self.set_connected(false);

        if let Some(task) = self.read_task.lock().expect("Mutex poisoned").take() {
            task.abort();
        }
        if let Some(task) = self.write_task.lock().expect("Mutex poisoned").take() {
            task.abort();
        }

        let (_tx, rx) = mpsc::unbounded_channel();
        *self.outbound_rx.lock().expect("Mutex poisoned") = Some(rx);
    }
}

impl Default for SocketContext {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            outbound_tx: tx,
            outbound_rx: std::sync::Mutex::new(Some(rx)),
            connected: std::sync::RwLock::new(false),
            read_task: std::sync::Mutex::new(None),
            write_task: std::sync::Mutex::new(None),
        }
    }
}

impl Drop for SocketContext {
    fn drop(&mut self) {
        if let Some(task) = self.read_task.lock().expect("Mutex poisoned").take() {
            task.abort();
        }
        if let Some(task) = self.write_task.lock().expect("Mutex poisoned").take() {
            task.abort();
        }
    }
}
