use crate::context::BotContext;
use crate::internal::packets::login::wtlogin::WtLogin;
use bytes::Bytes;
use lagrange_macros::define_service;
use std::collections::HashMap;
use std::sync::Arc;

use crate::protocol::{EncryptType, EventMessage, Protocols, RequestType};
use crate::utils::binary::{BinaryPacket, Prefix};
use crate::utils::tlv_unpack;

// Trans Emp service - handles both command 0x31 and 0x12
define_service! {
    TransEmpService {
        command: "wtlogin.trans_emp",
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        events {
            TransEmp31Event(protocol = Protocols::ANDROID) {
                request TransEmp31EventReq {
                    unusual_sig: Option<Vec<u8>>,
                }
                response TransEmp31EventResp {
                    qr_url: String,
                    tlvs: HashMap<u16, Vec<u8>>,
                    sig: Option<Vec<u8>>,
                }
            }

            TransEmp12Event(protocol = Protocols::ANDROID) {
                request TransEmp12EventReq {}
                response TransEmp12EventResp {
                    ret_code: u8,
                    uin: Option<u64>,
                    retry: Option<u8>,
                    tlv_1e: Option<Vec<u8>>,
                    tlv_19: Option<Vec<u8>>,
                    tlv_18: Option<Vec<u8>>,
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
                0x31 => {
                    // TransEmp31 response
                    let mut reader = BinaryPacket::from_slice(&payload);

                    // Read QR URL
                    let qr_url = reader.read_string(Prefix::INT16)?;

                    // Read TLV data
                    let tlvs = tlv_unpack(&mut reader)?;

                    // Try to read signature if available
                    let sig = if reader.remaining() >= 2 {
                        match reader.read_bytes_with_prefix(Prefix::INT16) {
                            Ok(sig_data) => Some(sig_data.to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };

                    tracing::debug!(
                        qr_url = %qr_url,
                        tlv_count = tlvs.len(),
                        has_sig = sig.is_some(),
                        "TransEmp31 response received"
                    );

                    Ok(EventMessage::new(TransEmp31EventResp {
                        qr_url,
                        tlvs,
                        sig,
                    }))
                }
                0x12 => {
                    // TransEmp12 response
                    let mut reader = BinaryPacket::from_slice(&payload);
                    let ret_code = reader.read::<u8>()?;

                    let (uin, retry, tlv_1e, tlv_19, tlv_18) = if ret_code == 0 {
                        // Success - extract UIN, retry count, and specific TLVs
                        let uin = reader.read::<u64>()?;
                        let retry = reader.read::<u8>()?;

                        // Parse TLV collection
                        let tlvs = tlv_unpack(&mut reader)?;

                        tracing::debug!(
                            ret_code = ret_code,
                            uin = uin,
                            retry = retry,
                            tlv_count = tlvs.len(),
                            "TransEmp12 success response"
                        );

                        (
                            Some(uin),
                            Some(retry),
                            tlvs.get(&0x1e).cloned(),
                            tlvs.get(&0x19).cloned(),
                            tlvs.get(&0x18).cloned(),
                        )
                    } else {
                        tracing::debug!(ret_code = ret_code, "TransEmp12 error response");
                        (None, None, None, None, None)
                    };

                    Ok(EventMessage::new(TransEmp12EventResp {
                        ret_code,
                        uin,
                        retry,
                        tlv_1e,
                        tlv_19,
                        tlv_18,
                    }))
                }
                _ => Err(crate::error::Error::ParseError(format!(
                    "Unknown TransEmp command: {:#x}",
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
            if let Some(input) = event.downcast_ref::<TransEmp31EventReq>() {
                let data = packet.build_trans_emp_31(input.unusual_sig.as_deref());
                Ok(Bytes::from(data))
            } else if let Some(_input) = event.downcast_ref::<TransEmp12EventReq>() {
                let data = packet.build_trans_emp_12();
                Ok(Bytes::from(data))
            } else {
                Err(crate::error::Error::BuildError(
                    "Invalid event type for TransEmpService".to_string(),
                ))
            }
        }
    }
}

// Helper methods for response types
impl TransEmp31EventResp {
    /// Get a specific TLV value by tag
    pub fn get_tlv(&self, tag: u16) -> Option<&Vec<u8>> {
        self.tlvs.get(&tag)
    }
}

impl TransEmp12EventResp {
    /// Check if the response was successful
    pub fn is_success(&self) -> bool {
        self.ret_code == 0
    }
}
