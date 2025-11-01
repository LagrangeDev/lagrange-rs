use crate::internal::packets::login::wtlogin::WtLogin;
use crate::context::BotContext;
use bytes::Bytes;
use lagrange_macros::define_service;
use std::sync::Arc;

use crate::protocol::{EncryptType, RequestType};
use crate::utils::binary::{BinaryPacket, Prefix};
use crate::utils::tlv_unpack;

// UIN Resolve service (QID to UIN conversion)
define_service! {
    UinResolveService: "wtlogin.name2uin" {
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        request UinResolveEventReq {
            qid: String,
        }

        response UinResolveEventResp {
            state: u8,
            uin: Option<u64>,
            qid: Option<String>,
            tlv_104: Option<Vec<u8>>,
            error: Option<(String, String)>,
        }

        service(protocol = Protocols::ANDROID) {
            async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<UinResolveEventResp> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();

                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

                let (command, payload) = packet
                    .parse(input.as_ref())
                    .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

                if command != 0x810 {
                    return Err(crate::error::Error::ParseError(format!(
                        "Expected command 0x810, got {:#x}",
                        command
                    )));
                }

                let mut reader = BinaryPacket::from_slice(&payload);
                let _internal_cmd = reader.read::<u16>()?;
                let state = reader.read::<u8>()?;

                // Parse TLV collection
                let tlvs = tlv_unpack(&mut reader)?;

                tracing::debug!(
                    state = state,
                    tlv_count = tlvs.len(),
                    "UIN resolve response received"
                );

                // Check for error (TLV 0x146)
                if let Some(error_data) = tlvs.get(&0x146) {
                    let mut error_reader = BinaryPacket::from_slice(error_data);
                    let _error_code = error_reader.read::<u32>()?;
                    let error_title = error_reader.read_string(Prefix::INT16)?;
                    let error_message = error_reader.read_string(Prefix::INT16)?;

                    tracing::info!(
                        error_title = %error_title,
                        error_message = %error_message,
                        "UIN resolve error received"
                    );

                    return Ok(UinResolveEventResp {
                        state,
                        uin: None,
                        qid: None,
                        tlv_104: None,
                        error: Some((error_title, error_message)),
                    });
                }

                // On success (state == 0), extract UIN and QID from TLV 0x113
                let (uin, qid) = if state == 0 {
                    if let Some(tlv_113) = tlvs.get(&0x113) {
                        let mut tlv113_reader = BinaryPacket::from_slice(tlv_113);
                        let uin = tlv113_reader.read::<u64>()?;
                        let qid = tlv113_reader.read_string(Prefix::INT16)?;

                        tracing::debug!(
                            uin = uin,
                            qid = %qid,
                            "Successfully resolved QID to UIN"
                        );

                        (Some(uin), Some(qid))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };

                // Extract TLV 0x104 if available
                let tlv_104 = tlvs.get(&0x104).cloned();

                Ok(UinResolveEventResp {
                    state,
                    uin,
                    qid,
                    tlv_104,
                    error: None,
                })
            }

            async fn build(input: UinResolveEventReq, context: Arc<BotContext>) -> Result<Bytes> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();

                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::BuildError(e.to_string()))?;

                // For now, use empty attach parameter
                // This would normally come from the context or be calculated
                let attach = &[];
                let data = packet.build_oicq_04_android(&input.qid, attach);

                Ok(Bytes::from(data))
            }
        }
    }
}

// Helper methods for response type
impl UinResolveEventResp {
    /// Check if the resolution was successful
    pub fn is_success(&self) -> bool {
        self.state == 0 && self.uin.is_some()
    }

    /// Check if there was an error
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the error message if any
    pub fn error_message(&self) -> Option<String> {
        self.error
            .as_ref()
            .map(|(title, msg)| format!("{}: {}", title, msg))
    }
}
