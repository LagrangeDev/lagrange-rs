use super::{tlv::Tlv, tlv_qrcode::TlvQrCode};
use crate::{
    common::AppInfo,
    keystore::BotKeystore,
    utils::{
        binary::{BinaryPacket, Prefix},
        crypto::{EcdhProvider, EllipticCurveType, TeaProvider},
    },
};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVER_PUBLIC_KEY: [u8; 49] = [
    0x04, 0x92, 0x8D, 0x88, 0x50, 0x67, 0x30, 0x88, 0xB3, 0x43, 0x26, 0x4E, 0x0C, 0x6B, 0xAC, 0xB8,
    0x49, 0x6D, 0x69, 0x77, 0x99, 0xF3, 0x72, 0x11, 0xDE, 0xB2, 0x5B, 0xB7, 0x39, 0x06, 0xCB, 0x08,
    0x9F, 0xEA, 0x96, 0x39, 0xB4, 0xE0, 0x26, 0x04, 0x98, 0xB5, 0x1A, 0x99, 0x2D, 0x50, 0x81, 0x3D,
    0xA8,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptMethod {
    EmSt = 0x45,
    EmEcdh = 0x07,
    EmEcdhSt = 0x87,
}

/// WtLogin packet builder for QQ login operations
pub struct WtLogin<'a> {
    share_key: Vec<u8>,
    keystore: &'a BotKeystore,
    app_info: &'a AppInfo,
    ecdh_provider: EcdhProvider,
}

impl<'a> WtLogin<'a> {
    pub fn new(keystore: &'a BotKeystore, app_info: &'a AppInfo) -> Result<Self, &'static str> {
        let ecdh_provider = EcdhProvider::new(EllipticCurveType::Secp192K1);

        // Get the secret key from keystore state
        // For now, we'll generate a new one if not available
        let secret = if let Some(ref exchange_key) = keystore.state.exchange_key {
            exchange_key.clone()
        } else {
            ecdh_provider.generate_secret()
        };

        let share_key = ecdh_provider.key_exchange(&secret, &SERVER_PUBLIC_KEY, true)?;

        Ok(Self {
            share_key,
            keystore,
            app_info,
            ecdh_provider,
        })
    }

    pub fn build_trans_emp_31(&self, unusual_sig: Option<&[u8]>) -> Vec<u8> {
        let mut writer = BinaryPacket::with_capacity(300);
        writer.write(0u16);
        writer.write(self.app_info.app_id);
        writer.write(0u64); // uin
        writer.write_bytes(&[]); // TGT
        writer.write(0u8);
        writer.write_str("", Prefix::INT16);

        let mut tlvs = TlvQrCode::new(self.keystore, self.app_info);
        if let Some(sig) = unusual_sig {
            tlvs.tlv_11(sig);
        }
        tlvs.tlv_16();
        tlvs.tlv_1b();
        tlvs.tlv_1d();
        tlvs.tlv_33();
        tlvs.tlv_35();
        tlvs.tlv_66();
        tlvs.tlv_d1();

        writer.write_bytes(&tlvs.create_bytes());

        self.build_code_2d_packet(
            0x31,
            writer.as_slice(),
            EncryptMethod::EmEcdhSt,
            false,
            false,
        )
    }

    pub fn build_trans_emp_12(&self) -> Vec<u8> {
        let mut writer = BinaryPacket::with_capacity(100);
        writer.write(0u16);
        writer.write(self.app_info.app_id);

        if let Some(ref qr_sig) = self.keystore.state.qr_sig {
            writer.write_bytes_with_prefix(qr_sig, Prefix::INT16);
        } else {
            writer.write_str("", Prefix::INT16);
        }

        writer.write(0u64); // uin
        writer.write_bytes(&[]); // TGT
        writer.write(0u8);
        writer.write_str("", Prefix::INT16);
        writer.write(0u16); // tlv count = 0

        self.build_code_2d_packet(
            0x12,
            writer.as_slice(),
            EncryptMethod::EmEcdhSt,
            false,
            false,
        )
    }

    pub fn build_qrlogin_19(&self, k: &[u8]) -> Vec<u8> {
        let mut writer = BinaryPacket::with_capacity(300);
        writer.write(0u16);
        writer.write(self.app_info.app_id);
        writer.write(self.keystore.uin.unwrap_or(0));
        writer.write_bytes_with_prefix(k, Prefix::INT16); // code in java, k in qrcode url
        writer.write_bytes_with_prefix(&self.keystore.sigs.a2, Prefix::INT16);
        writer.write_bytes(&self.keystore.guid);

        writer.write(1u8);
        writer.write(1i16);
        writer.write(8u8);

        let tlv_list: [i16; 5] = [0x03, 0x05, 0x20, 0x35, 0x36];
        writer.write(tlv_list.len() as i16);
        for tlv in &tlv_list {
            writer.write(*tlv);
        }

        let mut tlvs = TlvQrCode::new(self.keystore, self.app_info);
        tlvs.tlv_09();
        tlvs.tlv_12c();
        tlvs.tlv_39();

        writer.write_bytes(&tlvs.create_bytes());

        self.build_code_2d_packet(0x13, writer.as_slice(), EncryptMethod::EmSt, true, true)
    }

    pub fn build_qrlogin_20(&self, k: &[u8]) -> Vec<u8> {
        let mut writer = BinaryPacket::with_capacity(300);
        writer.write(0u16);
        writer.write(self.app_info.app_id);
        writer.write(self.keystore.uin.unwrap_or(0));
        writer.write_bytes_with_prefix(k, Prefix::INT16); // code in java, k in qrcode url
        writer.write_bytes_with_prefix(&self.keystore.sigs.a2, Prefix::INT16);

        writer.write(8u8);
        let mut tlvs = TlvQrCode::new(self.keystore, self.app_info);
        tlvs.tlv_02();
        tlvs.tlv_04();
        tlvs.tlv_15();
        tlvs.tlv_68();
        tlvs.tlv_16();
        tlvs.tlv_18();
        tlvs.tlv_19();
        tlvs.tlv_1d();
        tlvs.tlv_12c();

        writer.write_bytes(&tlvs.create_bytes());

        self.build_code_2d_packet(0x14, writer.as_slice(), EncryptMethod::EmSt, true, true)
    }

    pub fn build_qrlogin_22(&self, k: &[u8]) -> Vec<u8> {
        let mut writer = BinaryPacket::with_capacity(300);
        writer.write(0u16);
        writer.write(self.app_info.app_id);
        writer.write_bytes_with_prefix(k, Prefix::INT16); // code in java, k in qrcode url
        writer.write(self.keystore.uin.unwrap_or(0)); // uin
        writer.write(8u8);
        writer.write_bytes_with_prefix(&self.keystore.sigs.a2, Prefix::INT16);

        writer.write(0i16);
        let mut tlvs = TlvQrCode::new(self.keystore, self.app_info);
        tlvs.tlv_12c();

        writer.write_bytes(&tlvs.create_bytes());

        self.build_code_2d_packet(0x16, writer.as_slice(), EncryptMethod::EmSt, true, true)
    }

    pub fn build_oicq_09(&self) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x09, self.keystore, self.app_info);

        tlvs.tlv_106_encrypted_a1();
        tlvs.tlv_144();
        tlvs.tlv_116();
        tlvs.tlv_142();
        tlvs.tlv_145();
        tlvs.tlv_018();
        tlvs.tlv_141();
        tlvs.tlv_177();
        tlvs.tlv_191(0);
        tlvs.tlv_100();
        tlvs.tlv_107();
        tlvs.tlv_318();
        tlvs.tlv_16a();
        tlvs.tlv_166();
        tlvs.tlv_521();

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdhSt, false)
    }

    pub fn build_oicq_09_android(
        &self,
        password: &str,
        energy: &[u8],
        attach: &[u8],
        tlv_548_data: &[u8],
    ) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x09, self.keystore, self.app_info);

        tlvs.tlv_018_android();
        tlvs.tlv_001();
        tlvs.tlv_106_pwd(password);
        tlvs.tlv_116();
        tlvs.tlv_100_android(self.app_info.sdk_info.main_sig_map);
        tlvs.tlv_107_android();
        tlvs.tlv_142();
        tlvs.tlv_144_report(false);
        tlvs.tlv_145();
        tlvs.tlv_147();
        tlvs.tlv_154();
        tlvs.tlv_141_android();
        tlvs.tlv_008();
        tlvs.tlv_511();
        tlvs.tlv_187();
        tlvs.tlv_188();
        tlvs.tlv_191(0x82);
        tlvs.tlv_177();
        tlvs.tlv_516();
        tlvs.tlv_521_android();
        tlvs.tlv_525();
        tlvs.tlv_544(energy);
        tlvs.tlv_545();
        tlvs.tlv_548(tlv_548_data);
        tlvs.tlv_553(attach);

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdhSt, false)
    }

    pub fn build_oicq_02_android(&self, ticket: &str, energy: &[u8], attach: &[u8]) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x02, self.keystore, self.app_info);

        tlvs.tlv_193(ticket.as_bytes());
        tlvs.tlv_008();
        if let Some(tlv104) = self.keystore.state.tlv_cache.get(&0x104) {
            tlvs.tlv_104(tlv104);
        }
        tlvs.tlv_116();
        if let Some(tlv547) = self.keystore.state.tlv_cache.get(&0x547) {
            tlvs.tlv_547(tlv547);
        }
        tlvs.tlv_544(energy);
        tlvs.tlv_553(attach);

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdhSt, false)
    }

    pub fn build_oicq_04_android(&self, qid: &str, attach: &[u8]) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x04, self.keystore, self.app_info);

        tlvs.tlv_100();
        tlvs.tlv_112(qid);
        tlvs.tlv_107_android();
        tlvs.tlv_154();
        tlvs.tlv_008();
        tlvs.tlv_553(attach);
        tlvs.tlv_521_android();
        tlvs.tlv_124_android();
        tlvs.tlv_128();
        tlvs.tlv_116();
        tlvs.tlv_191(0x82);
        tlvs.tlv_11b();
        tlvs.tlv_52d();
        tlvs.tlv_548(&[]);

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdh, false)
    }

    pub fn build_oicq_07_android(&self, code: &str, energy: &[u8], attach: &[u8]) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x07, self.keystore, self.app_info);

        tlvs.tlv_008();
        if let Some(tlv104) = self.keystore.state.tlv_cache.get(&0x104) {
            tlvs.tlv_104(tlv104);
        }
        tlvs.tlv_116();
        if let Some(tlv174) = self.keystore.state.tlv_cache.get(&0x174) {
            tlvs.tlv_174(tlv174);
        }
        tlvs.tlv_17c(code);
        tlvs.tlv_401();
        tlvs.tlv_198();
        tlvs.tlv_544(energy);
        tlvs.tlv_553(attach);

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdhSt, false)
    }

    pub fn build_oicq_08_android(&self, attach: &[u8]) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x08, self.keystore, self.app_info);

        tlvs.tlv_008();
        if let Some(tlv104) = self.keystore.state.tlv_cache.get(&0x104) {
            tlvs.tlv_104(tlv104);
        }
        tlvs.tlv_116();
        if let Some(tlv174) = self.keystore.state.tlv_cache.get(&0x174) {
            tlvs.tlv_174(tlv174);
        }
        tlvs.tlv_17a();
        tlvs.tlv_197();
        tlvs.tlv_553(attach);

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdhSt, false)
    }

    pub fn build_oicq_15_android(&self, energy: &[u8], attach: &[u8]) -> Vec<u8> {
        let mut tlvs = Tlv::new(0x0f, self.keystore, self.app_info);

        tlvs.tlv_018_android();
        tlvs.tlv_001();
        tlvs.tlv_106_encrypted_a1();
        tlvs.tlv_116();
        tlvs.tlv_100_android(34607328);
        tlvs.tlv_107_android();
        tlvs.tlv_144_report(true);
        tlvs.tlv_142();
        tlvs.tlv_145();
        tlvs.tlv_16a();
        tlvs.tlv_154();
        tlvs.tlv_141_android();
        tlvs.tlv_008();
        tlvs.tlv_511();
        tlvs.tlv_147();
        tlvs.tlv_177();
        tlvs.tlv_400();
        tlvs.tlv_187();
        tlvs.tlv_188();
        tlvs.tlv_516();
        tlvs.tlv_521_android();
        tlvs.tlv_525();
        tlvs.tlv_544(energy);
        tlvs.tlv_553(attach);
        tlvs.tlv_545();

        self.build_packet(0x810, &tlvs.create_bytes(), EncryptMethod::EmEcdhSt, false)
    }

    fn build_packet(
        &self,
        command: u16,
        payload: &[u8],
        method: EncryptMethod,
        use_wt_session: bool,
    ) -> Vec<u8> {
        let key = match method {
            EncryptMethod::EmEcdh | EncryptMethod::EmEcdhSt => &self.share_key,
            EncryptMethod::EmSt => {
                if use_wt_session {
                    self.keystore
                        .sigs
                        .wt_session_ticket_key
                        .as_ref()
                        .unwrap_or(&self.keystore.sigs.random_key)
                } else {
                    &self.keystore.sigs.random_key
                }
            }
        };

        let key_array: [u8; 16] = key[..16].try_into().unwrap();
        let encrypted = TeaProvider::encrypt(payload, &key_array);

        let mut writer = BinaryPacket::with_capacity(encrypted.len() + 80);

        writer.write(2u8); // getRequestEncrptedPackage
        writer
            .with_length_prefix::<u16, _, _>(true, 1, |w| {
                w.write(8001i16); // version
                w.write(command);
                w.write(0i16); // sequence
                w.write(self.keystore.uin.unwrap_or(0) as u32);
                w.write(3u8);
                w.write(method as u8);
                w.write(0u32);
                w.write(2u8);
                w.write(0i16); // insId
                w.write(self.app_info.app_client_version as i32); // insId
                w.write(0u32); // retryTime
                self.build_encrypt_head(w, use_wt_session);
                w.write_bytes(&encrypted);
                w.write(3u8);
            })
            .unwrap();

        writer.to_vec()
    }

    fn build_code_2d_packet(
        &self,
        command: u16,
        tlv: &[u8],
        method: EncryptMethod,
        encrypt: bool,
        use_wt_session: bool,
    ) -> Vec<u8> {
        let mut req_body = BinaryPacket::with_capacity(48 + tlv.len());
        req_body.write(Self::unix_timestamp() as u32);

        req_body.write(2u8); // encryptMethod == EncryptMethod.EM_ST || encryptMethod == EncryptMethod.EM_ECDH_ST | Section of length 43 + tlv.Length + 1
        req_body
            .with_length_prefix::<u16, _, _>(true, 1, |w| {
                w.write(command);
                w.skip(21);
                w.write(3u8); // flag, 4 for oidb_func, 1 for register, 3 for code_2d, 2 for name_func, 5 for devlock
                w.write(0x00i16); // close
                w.write(0x32i16); // Version Code: 50
                w.write(0u32); // trans_emp sequence
                w.write(self.keystore.uin.unwrap_or(0)); // dummy uin
                w.write_bytes(tlv);
                w.write(3u8); // oicq.wlogin_sdk.code2d.c.get_request
            })
            .unwrap();

        let req_span = if encrypt {
            let st_key = self
                .keystore
                .sigs
                .st_key
                .as_ref()
                .unwrap_or(&self.keystore.sigs.random_key);
            let key_array: [u8; 16] = st_key[..16].try_into().unwrap();
            TeaProvider::encrypt(req_body.as_slice(), &key_array)
        } else {
            req_body.as_slice().to_vec()
        };

        let mut writer = BinaryPacket::with_capacity(14 + req_span.len());
        writer.write(if encrypt { 1u8 } else { 0u8 }); // flag for encrypt, if 1, encrypt by StKey
        writer.write(req_span.len() as u16);
        writer.write(self.app_info.app_id);
        writer.write(0x72u32); // Role

        if encrypt {
            if let Some(ref st) = self.keystore.sigs.st {
                writer.write_bytes_with_prefix(st, Prefix::INT16);
            } else {
                writer.write_str("", Prefix::INT16);
            }
        } else {
            writer.write_str("", Prefix::INT16);
        }

        writer.write_str("", Prefix::INT8); // rollback
        writer.write_bytes(&req_span); // oicq.wlogin_sdk.request.d0

        self.build_packet(0x812, writer.as_slice(), method, use_wt_session)
    }

    fn build_encrypt_head(&self, writer: &mut BinaryPacket, use_wt_session: bool) {
        if use_wt_session {
            if let Some(ref wt_session_ticket) = self.keystore.sigs.wt_session_ticket {
                writer.write_bytes_with_prefix(wt_session_ticket, Prefix::INT16);
            } else {
                writer.write_str("", Prefix::INT16);
            }
        } else {
            writer.write(1u8);
            writer.write(1u8);
            writer.write_bytes(&self.keystore.sigs.random_key);
            writer.write(0x102i16); // encrypt type

            // Pack ECDH public key
            // TODO: Get the actual public key from keystore
            // For now, use a placeholder
            writer.write_str("", Prefix::INT16);
        }
    }

    pub fn parse(&self, input: &[u8]) -> Result<(u16, Vec<u8>), &'static str> {
        let mut reader = BinaryPacket::from_slice(input);

        let _header = reader.read::<u8>().map_err(|_| "Failed to read header")?;
        let _length = reader.read::<u16>().map_err(|_| "Failed to read length")?;
        let _version = reader.read::<u16>().map_err(|_| "Failed to read version")?;
        let command = reader.read::<u16>().map_err(|_| "Failed to read command")?;
        let _sequence = reader
            .read::<u16>()
            .map_err(|_| "Failed to read sequence")?;
        let _uin = reader.read::<u32>().map_err(|_| "Failed to read uin")?;
        let _flag = reader.read::<u8>().map_err(|_| "Failed to read flag")?;
        let encrypt_type = reader
            .read::<u8>()
            .map_err(|_| "Failed to read encrypt type")?;
        let state = reader.read::<u8>().map_err(|_| "Failed to read state")?;

        let remaining = reader.remaining();
        if remaining == 0 {
            return Err("No encrypted data");
        }

        let encrypted = &reader
            .read_bytes(remaining - 1)
            .map_err(|_| "Failed to read encrypted data")?;

        let key = match encrypt_type {
            0 => {
                if state == 180 {
                    &self.keystore.sigs.random_key
                } else {
                    &self.share_key
                }
            }
            3 => self
                .keystore
                .sigs
                .wt_session_ticket_key
                .as_ref()
                .unwrap_or(&self.keystore.sigs.random_key),
            4 => {
                // TODO: Handle type 4 with ECDH key exchange
                &self.share_key
            }
            _ => return Err("Unknown encrypt type"),
        };

        let key_array: [u8; 16] = key[..16].try_into().map_err(|_| "Invalid key length")?;
        let decrypted =
            TeaProvider::decrypt(encrypted, &key_array).map_err(|_| "Failed to decrypt")?;

        Ok((command, decrypted))
    }

    pub fn parse_code_2d_packet(&self, input: &[u8]) -> Result<(u16, Vec<u8>), &'static str> {
        if input.len() < 5 {
            return Err("Input too short");
        }

        let encrypt = input[1];
        let layer = u16::from_be_bytes([input[2], input[3]]);

        let span = if encrypt == 0 {
            &input[5..5 + layer as usize]
        } else {
            let st_key = self
                .keystore
                .sigs
                .st_key
                .as_ref()
                .unwrap_or(&self.keystore.sigs.random_key);
            let key_array: [u8; 16] = st_key[..16].try_into().unwrap();
            &TeaProvider::decrypt(&input[5..5 + layer as usize], &key_array)
                .map_err(|_| "Failed to decrypt code2d packet")?
        };

        let mut reader = BinaryPacket::from_slice(span);

        let _header = reader.read::<u8>().map_err(|_| "Failed to read header")?;
        let _length = reader.read::<u16>().map_err(|_| "Failed to read length")?;
        let command = reader.read::<u16>().map_err(|_| "Failed to read command")?;
        reader.skip(21);
        let _flag = reader.read::<u8>().map_err(|_| "Failed to read flag")?;
        let _retry_time = reader
            .read::<u16>()
            .map_err(|_| "Failed to read retry_time")?;
        let _version = reader.read::<u16>().map_err(|_| "Failed to read version")?;
        let _sequence = reader
            .read::<u32>()
            .map_err(|_| "Failed to read sequence")?;
        let _uin = reader.read::<i64>().map_err(|_| "Failed to read uin")?;

        Ok((command, reader.read_remaining().to_vec()))
    }

    fn unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
