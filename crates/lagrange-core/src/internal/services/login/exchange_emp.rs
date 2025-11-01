use crate::internal::packets::login::wtlogin::WtLogin;
use crate::context::BotContext;
use bytes::Bytes;
use lagrange_macros::define_service;
use std::collections::HashMap;
use std::sync::Arc;

use crate::protocol::{EncryptType, RequestType};
use crate::utils::binary::BinaryPacket;
use crate::utils::crypto::TeaProvider;
use crate::utils::tlv_unpack;

/// Exchange emp command type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExchangeEmpCommand {
    /// Refresh by A1 credential
    RefreshByA1 = 0x0f,
}

// Exchange EMP service
define_service! {
    ExchangeEmpService: "wtlogin.exchange_emp" {
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        request ExchangeEmpEventReq {
            cmd: ExchangeEmpCommand,
        }

        response ExchangeEmpEventResp {
            state: u8,
            tlvs: HashMap<u16, Vec<u8>>,
        }

        service(protocol = Protocols::ANDROID) {
            async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<ExchangeEmpEventResp> {
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
                let internal_cmd = reader.read::<u16>()?;
                let state = reader.read::<u8>()?;

                let mut parsed_tlvs = tlv_unpack(&mut reader)?;

                tracing::debug!(
                    internal_cmd = internal_cmd,
                    state = state,
                    tlv_count = parsed_tlvs.len(),
                    "Exchange EMP response received"
                );

                // Check for TLV 0x119 (contains encrypted TLV collection)
                let tlvs = if let Some(tgtgt_data) = parsed_tlvs.remove(&0x119) {
                    // Choose decryption key based on internal command
                    let decryption_key = if internal_cmd == 0x0f {
                        // Use A1 key for command 0x0f
                        if keystore.sigs.a1.is_empty() {
                            return Err(crate::error::Error::ParseError(
                                "A1 key is empty, cannot decrypt TLV 0x119".to_string(),
                            ));
                        }
                        &keystore.sigs.a1
                    } else {
                        // Use TgtgtKey for other commands
                        &keystore.sigs.tgtgt_key
                    };

                    let key_array: [u8; 16] = decryption_key[..16]
                        .try_into()
                        .map_err(|_| crate::error::Error::ParseError("Invalid key length".into()))?;

                    let decrypted = TeaProvider::decrypt(&tgtgt_data, &key_array).map_err(|e| {
                        crate::error::Error::ParseError(format!("Failed to decrypt TLV 0x119: {}", e))
                    })?;

                    let mut tlv119_reader = BinaryPacket::from_slice(&decrypted);
                    let tlv_collection = tlv_unpack(&mut tlv119_reader)?;

                    tracing::debug!(
                        inner_tlv_count = tlv_collection.len(),
                        "Decrypted TLV 0x119"
                    );

                    tlv_collection
                } else {
                    parsed_tlvs
                };

                Ok(ExchangeEmpEventResp { state, tlvs })
            }

            async fn build(input: ExchangeEmpEventReq, context: Arc<BotContext>) -> Result<Bytes> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();

                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::BuildError(e.to_string()))?;

                let data = match input.cmd {
                    ExchangeEmpCommand::RefreshByA1 => {
                        // For now, use empty arrays for energy and attach parameters
                        // These would normally come from the context or be calculated
                        let energy = &[];
                        let attach = &[];
                        packet.build_oicq_15_android(energy, attach)
                    }
                };

                Ok(Bytes::from(data))
            }
        }
    }
}

// Helper methods for response type
impl ExchangeEmpEventResp {
    /// Get a specific TLV value by tag
    pub fn get_tlv(&self, tag: u16) -> Option<&Vec<u8>> {
        self.tlvs.get(&tag)
    }

    /// Check if the exchange was successful
    pub fn is_success(&self) -> bool {
        self.state == 0
    }
}
