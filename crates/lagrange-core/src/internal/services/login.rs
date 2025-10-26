use crate::internal::packets::login::wtlogin::WtLogin;
use crate::{context::BotContext, error::Result};
use bytes::Bytes;
use lagrange_macros::define_service;
use std::collections::HashMap;
use std::sync::Arc;

#[allow(unused_imports)] // Used in macro arguments
use crate::protocol::{EncryptType, RequestType, Protocols};
use crate::utils::binary::{BinaryPacket, Prefix};
use crate::utils::crypto::TeaProvider;

/// Command type for login operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// TGTGT login command (0x09)
    Tgtgt = 0x09,
    /// Captcha submission command (0x02)
    Captcha = 0x02,
    /// Fetch SMS code command (0x08)
    FetchSMSCode = 0x08,
    /// Submit SMS code command (0x07)
    SubmitSMSCode = 0x07,
}

/// Login response states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum States {
    Success = 0,
    CaptchaVerify = 2,
    SmsRequired = 160,
    DeviceLock = 204,
    DeviceLockViaSmsNewArea = 239,
    PreventByIncorrectPassword = 1,
    PreventByReceiveIssue = 3,
    PreventByTokenExpired = 15,
    PreventByAccountBanned = 40,
    PreventByOperationTimeout = 155,
    PreventBySmsSentFailed = 162,
    PreventByIncorrectSmsCode = 163,
    PreventByLoginDenied = 167,
    PreventByOutdatedVersion = 235,
    PreventByHighRiskOfEnvironment = 237,
    Unknown = 240,
}

impl From<u8> for States {
    fn from(value: u8) -> Self {
        match value {
            0 => States::Success,
            2 => States::CaptchaVerify,
            160 => States::SmsRequired,
            204 => States::DeviceLock,
            239 => States::DeviceLockViaSmsNewArea,
            1 => States::PreventByIncorrectPassword,
            3 => States::PreventByReceiveIssue,
            15 => States::PreventByTokenExpired,
            40 => States::PreventByAccountBanned,
            155 => States::PreventByOperationTimeout,
            162 => States::PreventBySmsSentFailed,
            163 => States::PreventByIncorrectSmsCode,
            167 => States::PreventByLoginDenied,
            235 => States::PreventByOutdatedVersion,
            237 => States::PreventByHighRiskOfEnvironment,
            _ => States::Unknown,
        }
    }
}

/// Unpacks TLV (Tag-Length-Value) data from a binary packet
fn tlv_unpack(reader: &mut BinaryPacket) -> Result<HashMap<u16, Vec<u8>>> {
    let mut tlvs = HashMap::new();

    let count = reader.read::<u16>()?;
    for _ in 0..count {
        let tag = reader.read::<u16>()?;
        let data = reader.read_bytes_with_prefix(Prefix::INT16)?.to_vec();
        tlvs.insert(tag, data);
    }

    Ok(tlvs)
}

/// Common parsing logic for login responses
fn parse_login_response(
    packet: &WtLogin,
    input: Bytes,
    context: Arc<BotContext>,
    ret_code: &mut u8,
    error: &mut Option<(String, String)>,
    tlvs: &mut HashMap<u16, Vec<u8>>,
) -> Result<()> {
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
    let mut parsed_tlvs = tlv_unpack(&mut reader)?;

    context.log_debug(&format!(
        "Login response: state={}, tlvs count={}",
        state,
        parsed_tlvs.len()
    ));

    *ret_code = state;

    // Check for error (TLV 0x146)
    if let Some(error_data) = parsed_tlvs.get(&0x146) {
        let mut error_reader = BinaryPacket::from_slice(error_data);
        let _error_code = error_reader.read::<u32>()?;
        let error_title = error_reader.read_string(Prefix::INT16)?;
        let error_message = error_reader.read_string(Prefix::INT16)?;

        context.log_info(&format!(
            "Login error: {} - {}",
            error_title, error_message
        ));

        *error = Some((error_title, error_message));
        return Ok(());
    }

    // Check for TLV 0x119 (contains encrypted TLV collection)
    if let Some(tgtgt_data) = parsed_tlvs.remove(&0x119) {
        let keystore = context.keystore.read().expect("RwLock poisoned");
        let tgtgt_key: [u8; 16] = keystore.sigs.tgtgt_key[..16]
            .try_into()
            .map_err(|_| crate::error::Error::ParseError("Invalid tgtgt_key length".into()))?;

        let decrypted = TeaProvider::decrypt(&tgtgt_data, &tgtgt_key)
            .map_err(|e| crate::error::Error::ParseError(format!("Failed to decrypt: {}", e)))?;

        let mut tlv119_reader = BinaryPacket::from_slice(&decrypted);
        let tlv_collection = tlv_unpack(&mut tlv119_reader)?;

        context.log_debug(&format!(
            "Decrypted TLV 0x119: {} inner TLVs",
            tlv_collection.len()
        ));

        *tlvs = tlv_collection;
        return Ok(());
    }

    *tlvs = parsed_tlvs;
    Ok(())
}

// Login service with protocol-specific service implementations
define_service! {
    LoginService: "wtlogin.login" {
        request_type: RequestType::D2Auth,
        encrypt_type: EncryptType::EncryptEmpty,

        request LoginEventReq {
            cmd: Command,
            password: String,
            ticket: String,
            code: String,
        }

        response LoginEventResp {
            ret_code: u8,
            error: Option<(String, String)>,
            tlvs: HashMap<u16, Vec<u8>>,
        }

        service(protocol = Protocols::PC) {
            async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<LoginEventResp> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();
                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

                let mut ret_code = 0;
                let mut error = None;
                let mut tlvs = HashMap::new();

                parse_login_response(&packet, input, context.clone(), &mut ret_code, &mut error, &mut tlvs)?;

                Ok(LoginEventResp {
                    ret_code,
                    error,
                    tlvs,
                })
            }

            async fn build(input: LoginEventReq, context: Arc<BotContext>) -> Result<Bytes> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();
                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::BuildError(e.to_string()))?;

                let data = match input.cmd {
                    Command::Tgtgt => packet.build_oicq_09(),
                    _ => {
                        return Err(crate::error::Error::BuildError(format!(
                            "Unknown command for PC protocol: {:?}",
                            input.cmd
                        )))
                    }
                };

                Ok(Bytes::from(data))
            }
        }

        service(protocol = Protocols::ANDROID) {
            async fn parse(input: Bytes, context: Arc<BotContext>) -> Result<LoginEventResp> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();

                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::ParseError(e.to_string()))?;

                let mut ret_code = 0;
                let mut error = None;
                let mut tlvs = HashMap::new();

                parse_login_response(&packet, input, context.clone(), &mut ret_code, &mut error, &mut tlvs)?;

                Ok(LoginEventResp {
                    ret_code,
                    error,
                    tlvs,
                })
            }

            async fn build(input: LoginEventReq, context: Arc<BotContext>) -> Result<Bytes> {
                let keystore = context.keystore.read().expect("RwLock poisoned");
                let app_info = context.app_info.inner();

                let packet = WtLogin::new(&keystore, app_info)
                    .map_err(|e| crate::error::Error::BuildError(e.to_string()))?;

                // For Android, we need additional parameters (energy, attach, tlv_548_data)
                // These would normally come from the context or be calculated
                // For now, we'll use empty arrays as placeholders
                let energy = &[];
                let attach = &[];
                let tlv_548_data = &[];

                let data = match input.cmd {
                    Command::Tgtgt => {
                        packet.build_oicq_09_android(&input.password, energy, attach, tlv_548_data)
                    }
                    Command::Captcha => packet.build_oicq_02_android(&input.ticket, energy, attach),
                    Command::FetchSMSCode => packet.build_oicq_08_android(attach),
                    Command::SubmitSMSCode => packet.build_oicq_07_android(&input.code, energy, attach),
                };

                Ok(Bytes::from(data))
            }
        }
    }
}

// Helper methods for response type
impl LoginEventResp {
    pub fn state(&self) -> States {
        States::from(self.ret_code)
    }
}
