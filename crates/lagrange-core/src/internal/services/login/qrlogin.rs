use crate::context::BotContext;
use crate::internal::packets::login::wtlogin::WtLogin;
use bytes::Bytes;
use lagrange_macros::define_service;
use std::sync::Arc;

use crate::protocol::{EncryptType, EventMessage, Protocols, RequestType};
use crate::utils::binary::{BinaryPacket, Prefix};
use crate::utils::tlv_unpack;

// QR Login service - handles both verification and closure
define_service! {
    QrLoginService {
        command: "wtlogin.qrlogin",
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        events {
            VerifyCodeEvent(protocol = Protocols::ANDROID) {
                request VerifyCodeEventReq {
                    key: Vec<u8>,
                }
                response VerifyCodeEventResp {
                    state: u8,
                    message: String,
                    platform: Option<String>,
                    location: Option<String>,
                    device: Option<String>,
                }
            }

            CloseCodeEvent(protocol = Protocols::ANDROID) {
                request CloseCodeEventReq {
                    key: Vec<u8>,
                    approved: bool,
                }
                response CloseCodeEventResp {
                    state: u8,
                    message: String,
                }
            }
        }

        async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<EventMessage> {
            let keystore = context.keystore.read().expect("RwLock poisoned");
            let app_info = context.app_info.inner();

            let packet = WtLogin::new(&keystore, app_info)
                .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

            let (command, payload) = packet
                .parse_code_2d_packet(input.as_ref())
                .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

            // Dispatch based on command code
            match command {
                0x13 => {
                    // Verify code response
                    let mut reader = BinaryPacket::from_slice(&payload);
                    let _uin = reader.read::<u64>()?;
                    let state = reader.read::<u8>()?;

                    let mut platform = None;
                    let mut location = None;
                    let mut device = None;
                    let message;

                    if state == 0 {
                        // Success - extract TLV data
                        let tlvs = tlv_unpack(&mut reader)?;

                        // TLV 0x03: Platform info
                        if let Some(platform_data) = tlvs.get(&0x03) {
                            if let Ok(platform_str) = String::from_utf8(platform_data.clone()) {
                                platform = Some(platform_str);
                            }
                        }

                        // TLV 0x05: Location info
                        if let Some(location_data) = tlvs.get(&0x05) {
                            if let Ok(location_str) = String::from_utf8(location_data.clone()) {
                                location = Some(location_str);
                            }
                        }

                        // TLV 0x20: Device name
                        if let Some(device_data) = tlvs.get(&0x20) {
                            if let Ok(device_str) = String::from_utf8(device_data.clone()) {
                                device = Some(device_str);
                            }
                        }

                        message = "QR code verified successfully".to_string();
                    } else {
                        message = format!("QR code verification failed with state: {}", state);
                    }

                    tracing::debug!(
                        state = state,
                        ?platform,
                        ?location,
                        ?device,
                        "QR code verification response"
                    );

                    Ok(EventMessage::new(VerifyCodeEventResp {
                        state,
                        message,
                        platform,
                        location,
                        device,
                    }))
                }
                0x16 => {
                    // Close code response
                    let mut reader = BinaryPacket::from_slice(&payload);
                    let state = reader.read::<u8>()?;

                    let message = if state == 0 {
                        "QR code session closed successfully".to_string()
                    } else {
                        reader
                            .read_string(Prefix::INT16)
                            .unwrap_or_else(|_| format!("Session closure failed with state: {}", state))
                    };

                    tracing::debug!(state = state, message = %message, "QR code closure response");

                    Ok(EventMessage::new(CloseCodeEventResp { state, message }))
                }
                _ => Err(crate::error::Error::ParseError(format!(
                    "Unknown QR login command: {:#x}",
                    command
                ))),
            }
        }

        async fn build(event: EventMessage, context: Arc<BotContext>) -> Result<Bytes> {
            let keystore = context.keystore.read().expect("RwLock poisoned");
            let app_info = context.app_info.inner();

            let packet = WtLogin::new(&keystore, app_info)
                .map_err(|e| crate::error::Error::BuildError(e.to_string()))?;

            // Dispatch based on event type
            if let Some(verify_event) = event.downcast_ref::<VerifyCodeEventReq>() {
                let data = packet.build_qrlogin_19(&verify_event.key);
                Ok(Bytes::from(data))
            } else if let Some(close_event) = event.downcast_ref::<CloseCodeEventReq>() {
                let data = if close_event.approved {
                    packet.build_qrlogin_20(&close_event.key)
                } else {
                    packet.build_qrlogin_22(&close_event.key)
                };
                Ok(Bytes::from(data))
            } else {
                Err(crate::error::Error::BuildError(
                    "Invalid event type for QrLoginService".to_string(),
                ))
            }
        }
    }
}
