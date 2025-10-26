use crate::{
    common::{sign::BoxedSignProvider, AppInfo, BotAppInfo},
    config::BotConfig,
    error::{Error, Result},
    internal::packets::{EncryptType, RequestType, ServicePacker, SsoPacket, SsoPacker, SsoSecureInfo},
    keystore::BotKeystore,
    protocol::Protocols,
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

        let encoded = self.encode_packet(&sso_packet, attributes).await?;

        socket.send(encoded)?;

        let response = rx.await.map_err(|_| {
            self.pending_tasks.remove(&sequence);
            Error::NetworkError("Response channel closed".to_string())
        })?;

        Ok(response)
    }

    pub fn dispatch_packet(&self, packet: SsoPacket) -> Option<SsoPacket> {
        let sequence = packet.sequence as u32;

        if let Some((_, sender)) = self.pending_tasks.remove(&sequence) {
            if packet.ret_code != 0 {
                tracing::error!(
                    "Packet error: command={}, ret_code={}, extra={}",
                    packet.command,
                    packet.ret_code,
                    packet.extra
                );
            }

            let _ = sender.send(packet);
            None
        } else {
            Some(packet)
        }
    }

    async fn encode_packet(
        &self,
        packet: &SsoPacket,
        attributes: Option<ServiceAttribute>,
    ) -> Result<Bytes> {
        let keystore = self.keystore.read().expect("RwLock poisoned");

        let attrs = attributes.unwrap_or_default();
        let request_type = attrs.request_type.unwrap_or(RequestType::Simple);
        let encrypt_type = attrs.encrypt_type.unwrap_or_else(|| {
            if keystore.sigs.d2_key.is_empty() {
                EncryptType::EncryptEmpty
            } else {
                EncryptType::EncryptD2Key
            }
        });

        let app_info = self.get_app_info();
        let sso_packer = SsoPacker::new(&keystore, app_info, self.protocol);
        let service_packer = ServicePacker::new(&keystore, app_info);

        match request_type {
            RequestType::D2Auth => {
                let sec_info = self.get_secure_info(packet).await;
                let sso_frame = sso_packer.build_protocol_12(packet, sec_info.as_ref());
                let service_frame = service_packer.build_protocol_12(sso_frame, encrypt_type);

                Ok(Bytes::from(service_frame))
            }
            RequestType::Simple => {
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
        let sign_result = self.sign_provider
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
        let service_packer = ServicePacker::new(&keystore, app_info);
        let sso_packer = SsoPacker::new(&keystore, app_info, self.protocol);

        let sso_data = service_packer.parse(&data)
            .map_err(|e| Error::ParseError(format!("Service parse failed: {}", e)))?;
        let packet = sso_packer.parse(&sso_data)
            .map_err(|e| Error::ParseError(format!("SSO parse failed: {}", e)))?;

        Ok(packet)
    }
}
