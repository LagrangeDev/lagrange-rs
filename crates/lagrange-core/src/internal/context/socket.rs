use bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const IPV4_SERVER: &str = "msfwifi.3g.qq.com:8080";
const IPV6_SERVER: &str = "msfwifiv6.3g.qq.com:8080";
const HEADER_SIZE: usize = 4;

pub struct SocketContext {
    outbound_tx: tokio::sync::RwLock<mpsc::UnboundedSender<Bytes>>,
    connected: tokio::sync::RwLock<bool>,
    read_task: tokio::sync::Mutex<Option<tokio::task::AbortHandle>>,
    write_task: tokio::sync::Mutex<Option<tokio::task::AbortHandle>>,
}

impl SocketContext {
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            outbound_tx: tokio::sync::RwLock::new(tx),
            connected: tokio::sync::RwLock::new(false),
            read_task: tokio::sync::Mutex::new(None),
            write_task: tokio::sync::Mutex::new(None),
        })
    }

    pub async fn send(&self, data: Bytes) -> crate::error::Result<()> {
        self.outbound_tx
            .read()
            .await
            .send(data)
            .map_err(|_| crate::error::Error::NetworkError("Socket closed".to_string()))
    }

    async fn set_connected(&self, connected: bool) {
        *self.connected.write().await = connected;
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    pub async fn connect(
        self: &Arc<Self>,
        use_ipv6: bool,
        packet_ctx: Arc<super::PacketContext>,
    ) -> crate::error::Result<()> {
        self.disconnect().await;

        let (tx, rx) = mpsc::unbounded_channel();
        *self.outbound_tx.write().await = tx;

        let server = if use_ipv6 { IPV6_SERVER } else { IPV4_SERVER };
        let stream = TcpStream::connect(server)
            .await
            .map_err(|e| crate::error::Error::NetworkError(format!("Failed to connect: {}", e)))?;

        let (read_half, write_half) = stream.into_split();
        self.set_connected(true).await;

        let read_task = {
            let packet_ctx = packet_ctx.clone();
            let socket_ctx = Arc::clone(self);

            tokio::spawn(async move {
                if let Err(e) = Self::read_loop(read_half, packet_ctx, socket_ctx).await {
                    tracing::error!(error = %e, "Socket read loop terminated");
                }
            })
        };

        let write_task = {
            let socket_ctx = Arc::clone(self);

            tokio::spawn(async move {
                if let Err(e) = Self::write_loop(write_half, rx, socket_ctx).await {
                    tracing::error!(error = %e, "Socket write loop terminated");
                }
            })
        };

        *self.read_task.lock().await = Some(read_task.abort_handle());
        *self.write_task.lock().await = Some(write_task.abort_handle());

        Ok(())
    }

    async fn read_loop(
        mut reader: tokio::net::tcp::OwnedReadHalf,
        packet_ctx: Arc<super::PacketContext>,
        socket_ctx: Arc<SocketContext>,
    ) -> crate::error::Result<()> {
        let mut header_buf = [0u8; HEADER_SIZE];

        loop {
            match reader.read_exact(&mut header_buf).await {
                Ok(_) => {}
                Err(e) => {
                    socket_ctx.set_connected(false).await;

                    if e.kind() == std::io::ErrorKind::UnexpectedEof
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionAborted {
                        tracing::info!("Connection closed");
                    } else {
                        tracing::error!(error = %e, "Failed to read header");
                    }

                    return Err(crate::error::Error::NetworkError(format!(
                        "Failed to read header: {}",
                        e
                    )));
                }
            }

            let length = u32::from_be_bytes(header_buf) as usize;
            let mut data = BytesMut::zeroed(length - 4);

            match reader.read_exact(&mut data).await {
                Ok(_) => {}
                Err(e) => {
                    socket_ctx.set_connected(false).await;
                    return Err(crate::error::Error::NetworkError(format!(
                        "Failed to read packet: {}",
                        e
                    )));
                }
            }

            let data_frozen = data.freeze();
            let hex = data_frozen.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            tracing::debug!(
                size = data_frozen.len(),
                hex = %hex,
                "Received packet"
            );

            match packet_ctx.decode_packet(data_frozen) {
                Ok(packet) => {
                    tracing::debug!(command = %packet.command, sequence = packet.sequence, data_len = packet.data.len(), ret_code = packet.ret_code, "Decoded packet");

                    let command = packet.command.clone();
                    let sequence = packet.sequence;

                    if let Some(packet) = packet_ctx.dispatch_packet(packet) {
                        tracing::debug!(command = %packet.command, sequence = packet.sequence, "Packet routed to services");
                        drop(packet);
                    } else {
                        tracing::debug!(command = %command, sequence = sequence, "Packet matched to pending request");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e,size = length - 4, "Failed to decode packet");
                }
            }
        }
    }

    async fn write_loop(
        mut writer: tokio::net::tcp::OwnedWriteHalf,
        mut outbound_rx: mpsc::UnboundedReceiver<Bytes>,
        socket_ctx: Arc<SocketContext>,
    ) -> crate::error::Result<()> {
        while let Some(data) = outbound_rx.recv().await {
            let length = data.len() as u32;
            let mut buffer = BytesMut::with_capacity(HEADER_SIZE + data.len());
            buffer.put_u32(length + HEADER_SIZE as u32);
            buffer.put(data);

            let hex = buffer.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            tracing::debug!(
                size = buffer.len(),
                hex = %hex,
                "Sending packet"
            );

            match writer.write_all(&buffer).await {
                Ok(_) => {
                    tracing::debug!(
                        size = buffer.len(),
                        "Packet sent successfully"
                    );
                }
                Err(e) => {
                    socket_ctx.set_connected(false).await;

                    if e.kind() == std::io::ErrorKind::UnexpectedEof
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionAborted
                        || e.kind() == std::io::ErrorKind::BrokenPipe {
                        tracing::info!("Connection closed while writing");
                    } else {
                        tracing::error!(error = %e, "Failed to write packet");
                    }

                    return Err(crate::error::Error::NetworkError(format!(
                        "Failed to write packet: {}",
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    pub async fn disconnect(&self) {
        self.set_connected(false).await;

        if let Some(handle) = self.read_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.write_task.lock().await.take() {
            handle.abort();
        }
    }
}


impl Drop for SocketContext {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.read_task.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.write_task.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}
