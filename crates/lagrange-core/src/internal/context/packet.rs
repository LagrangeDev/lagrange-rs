use crate::{
    common::{sign::BoxedSignProvider, AppInfo, BotAppInfo},
    config::BotConfig,
    error::{Error, Result},
    internal::packets::{
        ServicePacker, SsoPacker, SsoPacket, SsoSecureInfo,
    },
    keystore::BotKeystore,
    protocol::{EncryptType, Protocols, RequestType},
};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, RwLock,
};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceAttribute {
    pub request_type: Option<RequestType>,
    pub encrypt_type: Option<EncryptType>,
}

impl ServiceAttribute {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_request_type(mut self, request_type: RequestType) -> Self {
        self.request_type = Some(request_type);
        self
    }

    pub fn with_encrypt_type(mut self, encrypt_type: EncryptType) -> Self {
        self.encrypt_type = Some(encrypt_type);
        self
    }
}

pub struct PacketContext {
    sequence: AtomicU32,
    pending_tasks: DashMap<u32, oneshot::Sender<SsoPacket>>,

    keystore: Arc<RwLock<BotKeystore>>,
    app_info: Arc<BotAppInfo>,
    protocol: Protocols,
    sign_provider: BoxedSignProvider,
}

impl PacketContext {
    pub fn new(
        keystore: Arc<RwLock<BotKeystore>>,
        app_info: Arc<BotAppInfo>,
        config: &BotConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            sequence: AtomicU32::new(1),
            pending_tasks: DashMap::new(),
            keystore,
            app_info,
            protocol: config.protocol,
            sign_provider: config.get_sign_provider(),
        })
    }

    fn get_app_info(&self) -> &AppInfo {
        match self.app_info.as_ref() {
            BotAppInfo::Windows(info) | BotAppInfo::Linux(info) | BotAppInfo::MacOs(info) => info,
            BotAppInfo::Android { info, .. } => info,
        }
    }

    pub fn next_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn send_packet(
        &self,
        command: String,
        data: Bytes,
        socket: Arc<super::SocketContext>,
        attributes: Option<ServiceAttribute>,
    ) -> Result<SsoPacket> {
        let sequence = self.next_sequence();
        let (tx, rx) = oneshot::channel();

        self.pending_tasks.insert(sequence, tx);

        let sso_packet = SsoPacket {
            command: command.clone(),
            data: data.clone(),
            sequence: sequence as i32,
            ret_code: 0,
            extra: String::new(),
        };

        tracing::debug!(
            sequence_u32 = sequence,
            sequence_i32 = sso_packet.sequence,
            command = %command,
            "Sending packet and registering pending task"
        );

        let encoded = self.encode_packet(&sso_packet, attributes).await?;

        socket.send(encoded).await?;

        let response = rx.await.map_err(|_| {
            tracing::warn!(
                sequence = sequence,
                command = %command,
                "Response channel closed, removing pending task"
            );
            self.pending_tasks.remove(&sequence);
            Error::NetworkError("Response channel closed".to_string())
        })?;

        Ok(response)
    }

    pub fn dispatch_packet(&self, packet: SsoPacket) -> Option<SsoPacket> {
        let sequence = packet.sequence as u32;

        tracing::debug!(
            packet_sequence_i32 = packet.sequence,
            converted_sequence_u32 = sequence,
            pending_tasks_count = self.pending_tasks.len(),
            "Attempting to dispatch packet"
        );

        if let Some((_, sender)) = self.pending_tasks.remove(&sequence) {
            if packet.ret_code != 0 {
                tracing::error!(
                    command = %packet.command,
                    ret_code = packet.ret_code,
                    extra = %packet.extra,
                    sequence = packet.sequence,
                    "Packet error received"
                );
            }

            tracing::debug!(
                sequence = sequence,
                command = %packet.command,
                "Successfully matched and removed pending task"
            );

            let _ = sender.send(packet);
            None
        } else {
            // Collect all pending sequence numbers for debugging
            let pending_sequences: Vec<u32> = self.pending_tasks.iter()
                .map(|entry| *entry.key())
                .collect();

            tracing::warn!(
                sequence_i32 = packet.sequence,
                sequence_u32 = sequence,
                command = %packet.command,
                pending_tasks_count = self.pending_tasks.len(),
                pending_sequences = ?pending_sequences,
                "Failed to find pending task for sequence - packet will be routed to services"
            );
            Some(packet)
        }
    }

    pub async fn encode_packet(
        &self,
        packet: &SsoPacket,
        attributes: Option<ServiceAttribute>,
    ) -> Result<Bytes> {
        let attrs = attributes.unwrap_or_default();
        let request_type = attrs.request_type.unwrap_or(RequestType::Simple);

        match request_type {
            RequestType::D2Auth => {
                // Acquire lock for sec_info preparation, then drop it before await
                let sec_info = self.get_secure_info(packet).await;

                // Reacquire lock for encoding
                let keystore = self.keystore.read().expect("RwLock poisoned");
                let encrypt_type = attrs.encrypt_type.unwrap_or_else(|| {
                    if keystore.sigs.d2_key.is_empty() {
                        EncryptType::EncryptEmpty
                    } else {
                        EncryptType::EncryptD2Key
                    }
                });

                let app_info = self.get_app_info();
                let sso_packer = SsoPacker::new(&keystore, app_info, self.protocol);
                let service_packer = ServicePacker::new(&keystore);

                let sso_frame = sso_packer.build_protocol_12(packet, sec_info.as_ref());
                let service_frame = service_packer.build_protocol_12(sso_frame, encrypt_type);

                Ok(Bytes::from(service_frame))
            }
            RequestType::Simple => {
                let keystore = self.keystore.read().expect("RwLock poisoned");
                let encrypt_type = attrs.encrypt_type.unwrap_or_else(|| {
                    if keystore.sigs.d2_key.is_empty() {
                        EncryptType::EncryptEmpty
                    } else {
                        EncryptType::EncryptD2Key
                    }
                });

                let app_info = self.get_app_info();
                let sso_packer = SsoPacker::new(&keystore, app_info, self.protocol);
                let service_packer = ServicePacker::new(&keystore);

                let sso_frame = sso_packer.build_protocol_13(packet);

                let service_frame = service_packer.build_protocol_13(
                    packet.sequence,
                    sso_frame.as_slice(),
                    encrypt_type,
                );

                Ok(Bytes::from(service_frame))
            }
        }
    }

    async fn get_secure_info(&self, packet: &SsoPacket) -> Option<SsoSecureInfo> {
        let sign_result = self
            .sign_provider
            .sign(&packet.command, packet.sequence as u32, &packet.data)
            .await?;

        Some(SsoSecureInfo {
            sec_sign: Some(sign_result.sign.to_vec()),
            sec_token: Some(sign_result.token.to_vec()),
            sec_extra: Some(sign_result.extra.to_vec()),
        })
    }

    pub fn decode_packet(&self, data: Bytes) -> Result<SsoPacket> {
        let keystore = self.keystore.read().expect("RwLock poisoned");

        let app_info = self.get_app_info();
        let service_packer = ServicePacker::new(&keystore);
        let sso_packer = SsoPacker::new(&keystore, app_info, self.protocol);

        let sso_data = service_packer
            .parse(&data)
            .map_err(|e| Error::ParseError(format!("Service parse failed: {}", e)))?;
        let packet = sso_packer
            .parse(&sso_data)
            .map_err(|e| Error::ParseError(format!("SSO parse failed: {}", e)))?;

        Ok(packet)
    }
}
