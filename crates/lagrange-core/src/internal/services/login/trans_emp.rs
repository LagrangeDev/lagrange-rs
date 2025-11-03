use crate::context::BotContext;
use crate::internal::packets::login::qr_login_ext_info::QrExtInfo;
use crate::internal::packets::login::wtlogin::WtLogin;
use bytes::Bytes;
use lagrange_macros::define_service;
use lagrange_proto::ProtoDecode;
use std::collections::HashMap;
use std::sync::Arc;

use crate::protocol::{EncryptType, EventMessage, Protocols, RequestType};
use crate::utils::binary::BinaryPacket;
use crate::utils::tlv_unpack;

define_service! {
    TransEmpService {
        command: "wtlogin.trans_emp",
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        events {
            TransEmp31Event(protocol = Protocols::PC) {
                request TransEmp31EventReq {
                    unusual_sig: Option<Vec<u8>>,
                }
                response TransEmp31EventResp {
                    qr_url: String,
                    tlvs: HashMap<u16, Vec<u8>>,
                    sig: Option<Vec<u8>>,
                }
            }

            TransEmp12Event(protocol = Protocols::PC) {
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
            let mut keystore = context.keystore.write().expect("RwLock poisoned");
            let app_info = context.app_info.inner();

            let packet = WtLogin::new(&mut keystore, app_info)
                .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

            let (_wtlogin_cmd, wtlogin) = packet.parse(input.as_ref())
                .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

            let (command, payload) = packet
                .parse_code_2d_packet(wtlogin.as_ref())
                .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

            let mut reader = BinaryPacket::from_slice(&payload);
            let _dummy = reader.read::<i16>()?;
            let _app_id = reader.read::<i32>()?;
            let ret_code = reader.read::<u8>()?;

            match command {
                0x31 => {
                    let sig_len = reader.read::<i16>()?;
                    let sig = if sig_len > 0 {
                        Some(reader.read_bytes(sig_len as usize)?.to_vec())
                    } else {
                        None
                    };

                    let tlvs = tlv_unpack(&mut reader)?;

                    let qr_ext_info = if let Some(tlv_d1) = tlvs.get(&0xD1) {
                        QrExtInfo::decode(tlv_d1.as_slice())
                            .map_err(|e| crate::error::Error::ParseError(format!(
                                "Failed to decode QrExtInfo: {}", e
                            )))?
                    } else {
                        return Err(crate::error::Error::ParseError(
                            "Missing tlv 0xD1 in TransEmp31 response".to_string()
                        ));
                    };

                    let qr_url = qr_ext_info.qr_url
                        .ok_or_else(|| crate::error::Error::ParseError(
                            "Missing qr_url in QrExtInfo".to_string()
                        ))?;
                    
                    Ok(EventMessage::new(TransEmp31EventResp {
                        qr_url,
                        tlvs,
                        sig,
                    }))
                }
                0x12 => {
                    let (uin, retry, tlv_1e, tlv_19, tlv_18) = if ret_code == 0 {
                        let uin = reader.read::<u64>()?;
                        let retry = reader.read::<u8>()?;
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
            let mut keystore = context.keystore.write().expect("RwLock poisoned");
            let app_info = context.app_info.inner();

            let packet = WtLogin::new(&mut keystore, app_info)
                .map_err(|e| crate::error::Error::BuildError(e.to_string()))?;

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

impl TransEmp31EventResp {
    pub fn get_tlv(&self, tag: u16) -> Option<&Vec<u8>> {
        self.tlvs.get(&tag)
    }
}

impl TransEmp12EventResp {
    pub fn is_success(&self) -> bool {
        self.ret_code == 0
    }
}
