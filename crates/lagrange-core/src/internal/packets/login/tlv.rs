use super::tlv_writer::TlvWritable;
use crate::{
    common::AppInfo,
    keystore::BotKeystore,
    utils::{
        binary::{BinaryPacket, Prefix},
        crypto::tea,
    },
};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

/// TLV (Tag-Length-Value) packet builder for login operations
pub struct Tlv<'a> {
    writer: BinaryPacket,
    count: u16,
    prefixed: bool,
    keystore: &'a BotKeystore,
    app_info: &'a AppInfo,
}

impl<'a> TlvWritable for Tlv<'a> {
    fn writer_mut(&mut self) -> &mut BinaryPacket {
        &mut self.writer
    }

    fn increment_count(&mut self) {
        self.count += 1;
    }
}

impl<'a> Tlv<'a> {
    pub fn new(command: i16, keystore: &'a BotKeystore, app_info: &'a AppInfo) -> Self {
        let mut writer = BinaryPacket::with_capacity(1000);
        let prefixed = if command > 0 {
            writer.write(command as u16);
            true
        } else {
            false
        };
        writer.skip(2); // Skip count field

        Self {
            writer,
            count: 0,
            prefixed,
            keystore,
            app_info,
        }
    }

    pub fn tlv_001(&mut self) {
        let uin = self.keystore.uin.unwrap_or(0) as u32;
        let timestamp = Self::unix_timestamp() as u32;
        self.write_tlv(0x01, |writer| {
            writer.write(0x0001u16);
            writer.write(rand::thread_rng().gen::<u32>());
            writer.write(uin);
            writer.write(timestamp);
            writer.write(0u32); // dummy IP Address
            writer.write(0x0000u16);
        });
    }

    pub fn tlv_008(&mut self) {
        self.write_tlv(0x08, |writer| {
            writer.write(0u16);
            writer.write(2052u32); // locale_id
            writer.write(0u16);
        });
    }

    pub fn tlv_018(&mut self) {
        let uin = self.keystore.uin.unwrap_or(0) as u32;
        self.write_tlv(0x18, |writer| {
            writer.write(0i16);
            writer.write(5u32);
            writer.write(0u32);
            writer.write(8001u32); // app client ver
            writer.write(uin);
            writer.write(0i16);
            writer.write(0i16);
        });
    }

    pub fn tlv_018_android(&mut self) {
        let app_id = self.app_info.app_id;
        let app_client_version = self.app_info.app_client_version as i32;
        let uin = self.keystore.uin.unwrap_or(0) as u32;
        self.write_tlv(0x18, |writer| {
            writer.write(0x0001i16);
            writer.write(0x00000600u32);
            writer.write(app_id);
            writer.write(app_client_version);
            writer.write(uin);
            writer.write(0x0000i16);
            writer.write(0x0000i16);
        });
    }

    pub fn tlv_100(&mut self) {
        let app_id = self.app_info.app_id;
        let sub_app_id = self.app_info.sub_app_id;
        let app_client_version = self.app_info.app_client_version as i32;
        let main_sig_map = self.app_info.sdk_info.main_sig_map;
        self.write_tlv(0x100, |writer| {
            writer.write(0u16); // db buf ver
            writer.write(5u32); // sso ver, dont over 7
            writer.write(app_id);
            writer.write(sub_app_id);
            writer.write(app_client_version); // app client ver
            writer.write(main_sig_map);
        });
    }

    pub fn tlv_100_android(&mut self, main_sig_map: u32) {
        let sso_version = self.app_info.sso_version;
        let app_id = self.app_info.app_id;
        let sub_app_id = self.app_info.sub_app_id;
        let app_client_version = self.app_info.app_client_version as i32;
        self.write_tlv(0x100, |writer| {
            writer.write(1u16); // db buf ver
            writer.write(sso_version); // sso ver, dont over 7
            writer.write(app_id);
            writer.write(sub_app_id);
            writer.write(app_client_version); // app client ver
            writer.write(main_sig_map);
        });
    }

    pub fn tlv_104(&mut self, verification_token: &[u8]) {
        self.write_tlv(0x104, |writer| {
            writer.write_bytes(verification_token);
        });
    }

    pub fn tlv_106_pwd(&mut self, password: &str) {
        let md5_hash = md5::compute(password.as_bytes());

        let mut key_writer = BinaryPacket::with_capacity(16 + 4 + 4);
        key_writer.write_bytes(&md5_hash.0);
        key_writer.write(0u32); // empty 4 bytes
        key_writer.write(self.keystore.uin.unwrap_or(0) as u32);
        let key = md5::compute(key_writer.as_slice());
        let key_array: [u8; 16] = key.0;

        let mut plain_writer = BinaryPacket::with_capacity(100);
        plain_writer.write(4i16); // TGTGT Version
        plain_writer.write(rand::thread_rng().gen::<u32>());
        plain_writer.write(self.app_info.sso_version);
        plain_writer.write(self.app_info.app_id);
        plain_writer.write(self.app_info.app_client_version as i32);
        plain_writer.write(self.keystore.uin.unwrap_or(0));
        plain_writer.write(Self::unix_timestamp() as i32);
        plain_writer.write(0u32); // dummy IP Address
        plain_writer.write(1u8);
        plain_writer.write_bytes(&md5_hash.0);
        plain_writer.write_bytes(&self.keystore.sigs.tgtgt_key);
        plain_writer.write(0u32); // unknown
        plain_writer.write(1u8); // guidAvailable
        plain_writer.write_bytes(&self.keystore.guid);
        plain_writer.write(self.app_info.sub_app_id);
        plain_writer.write(1u32); // flag
        plain_writer.write_str(&self.keystore.uin.unwrap_or(0).to_string(), Prefix::INT16);
        plain_writer.write(0i16);
        let encrypted = tea::encrypt(plain_writer.as_slice(), &key_array);

        self.write_tlv(0x106, |writer| {
            writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_106_encrypted_a1(&mut self) {
        let a1 = &self.keystore.sigs.a1;
        self.write_tlv(0x106, |writer| {
            writer.write_bytes(a1);
        });
    }

    pub fn tlv_107(&mut self) {
        self.write_tlv(0x107, |writer| {
            writer.write(1u16); // pic type
            writer.write(0x0Du8); // captcha type
            writer.write(0u16); // pic size
            writer.write(1u8); // ret type
        });
    }

    pub fn tlv_107_android(&mut self) {
        self.write_tlv(0x107, |writer| {
            writer.write(0u16); // pic type
            writer.write(0u8); // captcha type
            writer.write(0u16); // pic size
            writer.write(1u8); // ret type
        });
    }

    pub fn tlv_109(&mut self) {
        let android_id = &self.keystore.android_id;
        self.write_tlv(0x109, |writer| {
            let hash = md5::compute(android_id.as_bytes());
            writer.write_bytes(&hash.0);
        });
    }

    pub fn tlv_112(&mut self, qid: &str) {
        self.write_tlv(0x112, |writer| {
            writer.write_bytes(qid.as_bytes());
        });
    }

    pub fn tlv_116(&mut self) {
        let misc_bit_map = self.app_info.sdk_info.misc_bit_map;
        let sub_sig_map = self.app_info.sdk_info.sub_sig_map;
        self.write_tlv(0x116, |writer| {
            writer.write(0u8); // version
            writer.write(misc_bit_map); // miscBitMap
            writer.write(sub_sig_map);
            writer.write(0u8); // length of subAppId
        });
    }

    pub fn tlv_11b(&mut self) {
        self.write_tlv(0x11B, |writer| {
            writer.write(2u8);
        });
    }

    pub fn tlv_124(&mut self) {
        self.write_tlv(0x124, |writer| {
            writer.skip(12);
        });
    }

    pub fn tlv_124_android(&mut self) {
        self.write_tlv(0x124, |writer| {
            writer.write_str("android", Prefix::INT16);
            writer.write_str("13", Prefix::INT16); // os version
            writer.write(0x02i16); // network type
            writer.write_str("", Prefix::INT16); // sim info
            writer.write_str("wifi", Prefix::INT32); // apn
        });
    }

    pub fn tlv_128(&mut self) {
        let os = &self.app_info.os;
        let guid = &self.keystore.guid;
        self.write_tlv(0x128, |writer| {
            writer.write(0u16);
            writer.write(0u8); // guid new
            writer.write(0u8); // guid available
            writer.write(0u8); // guid changed
            writer.write(0u32); // guid flag
            writer.write_str(os, Prefix::INT16);
            writer.write_bytes_with_prefix(guid, Prefix::INT16);
            writer.write_str("", Prefix::INT16); // brand
        });
    }

    pub fn tlv_141(&mut self) {
        self.write_tlv(0x141, |writer| {
            writer.write(0u16);
            writer.write_str("Unknown", Prefix::INT16);
            writer.write(0u32);
        });
    }

    pub fn tlv_141_android(&mut self) {
        self.write_tlv(0x141, |writer| {
            writer.write(1u16);
            writer.write_str("", Prefix::INT16);
            writer.write_str("", Prefix::INT16);
            writer.write_str("wifi", Prefix::INT16);
        });
    }

    pub fn tlv_142(&mut self) {
        let package_name = &self.app_info.package_name;
        self.write_tlv(0x142, |writer| {
            writer.write(0u16);
            writer.write_str(package_name, Prefix::INT16);
        });
    }

    pub fn tlv_144(&mut self) {
        let mut tlv = Tlv::new(-1, self.keystore, self.app_info);

        tlv.tlv_16e();
        tlv.tlv_147();
        tlv.tlv_128();
        tlv.tlv_124();

        let span = tlv.create_bytes();
        let tgtgt_key: [u8; 16] = self.keystore.sigs.tgtgt_key[..16].try_into().unwrap();
        let encrypted = tea::encrypt(&span, &tgtgt_key);

        self.write_tlv(0x144, |writer| {
            writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_144_report(&mut self, use_a1_key: bool) {
        let mut tlv = Tlv::new(-1, self.keystore, self.app_info);

        tlv.tlv_109();
        tlv.tlv_52d();
        tlv.tlv_124_android();
        tlv.tlv_128();
        tlv.tlv_16e();

        let span = tlv.create_bytes();
        let key = if use_a1_key {
            &self.keystore.sigs.a1
        } else {
            &self.keystore.sigs.tgtgt_key
        };
        let key_array: [u8; 16] = key[..16].try_into().unwrap();
        let encrypted = tea::encrypt(&span, &key_array);

        self.write_tlv(0x144, |writer| {
            writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_145(&mut self) {
        let guid = &self.keystore.guid;
        self.write_tlv(0x145, |writer| {
            writer.write_bytes(guid);
        });
    }

    pub fn tlv_147(&mut self) {
        let app_id = self.app_info.app_id;
        let pt_version = &self.app_info.pt_version;
        let apk_signature_md5 = &self.app_info.apk_signature_md5;
        self.write_tlv(0x147, |writer| {
            writer.write(app_id);
            writer.write_str(pt_version, Prefix::INT16);
            writer.write_bytes_with_prefix(apk_signature_md5, Prefix::INT16);
        });
    }

    pub fn tlv_154(&mut self) {
        self.write_tlv(0x154, |writer| {
            writer.write(0u32); // seq
        });
    }

    pub fn tlv_166(&mut self) {
        self.write_tlv(0x166, |writer| {
            writer.write(5u8);
        });
    }

    pub fn tlv_16a(&mut self) {
        let no_pic_sig = self.keystore.sigs.no_pic_sig.as_ref();
        self.write_tlv(0x16A, |writer| {
            if let Some(no_pic_sig) = no_pic_sig {
                writer.write_bytes(no_pic_sig);
            }
        });
    }

    pub fn tlv_16e(&mut self) {
        let device_name = &self.keystore.device_name;
        self.write_tlv(0x16E, |writer| {
            writer.write_bytes(device_name.as_bytes());
        });
    }

    pub fn tlv_174(&mut self, session: &[u8]) {
        self.write_tlv(0x174, |writer| {
            writer.write_bytes(session);
        });
    }

    pub fn tlv_177(&mut self) {
        let sdk_version = &self.app_info.sdk_info.sdk_version;
        self.write_tlv(0x177, |writer| {
            writer.write(1u8);
            writer.write(0u32); // sdk build time
            writer.write_str(sdk_version, Prefix::INT16);
        });
    }

    pub fn tlv_17a(&mut self) {
        self.write_tlv(0x17A, |writer| {
            writer.write(9u32);
        });
    }

    pub fn tlv_17c(&mut self, code: &str) {
        self.write_tlv(0x17C, |writer| {
            writer.write_str(code, Prefix::INT16);
        });
    }

    pub fn tlv_187(&mut self) {
        self.write_tlv(0x187, |writer| {
            let hash = md5::compute([0x02, 0x00, 0x00, 0x00, 0x00, 0x00]); // Dummy Mac Address
            writer.write_bytes(&hash.0);
        });
    }

    pub fn tlv_188(&mut self) {
        let android_id = &self.keystore.android_id;
        self.write_tlv(0x188, |writer| {
            let hash = md5::compute(android_id.as_bytes());
            writer.write_bytes(&hash.0);
        });
    }

    pub fn tlv_191(&mut self, k: u8) {
        self.write_tlv(0x191, |writer| {
            writer.write(k);
        });
    }

    pub fn tlv_193(&mut self, ticket: &[u8]) {
        self.write_tlv(0x193, |writer| {
            writer.write_bytes(ticket);
        });
    }

    pub fn tlv_197(&mut self) {
        self.write_tlv(0x197, |writer| {
            writer.write(0u8);
        });
    }

    pub fn tlv_198(&mut self) {
        self.write_tlv(0x198, |writer| {
            writer.write(0u8);
        });
    }

    pub fn tlv_318(&mut self) {
        self.write_tlv(0x318, |_writer| {});
    }

    pub fn tlv_400(&mut self) {
        let mut random_key = [0u8; 16];
        rand::thread_rng().fill(&mut random_key);
        let mut rand_seed = [0u8; 8];
        rand::thread_rng().fill(&mut rand_seed);

        let mut inner_writer = BinaryPacket::with_capacity(100);
        inner_writer.write(1i16);
        inner_writer.write(self.keystore.uin.unwrap_or(0));
        inner_writer.write_bytes(&self.keystore.guid);
        inner_writer.write_bytes(&random_key);
        inner_writer.write(16u32);
        inner_writer.write(1u32);
        inner_writer.write(Self::unix_timestamp() as u32);
        inner_writer.write_bytes(&rand_seed);

        let guid_key: [u8; 16] = self.keystore.guid[..16].try_into().unwrap();
        let encrypted = tea::encrypt(inner_writer.as_slice(), &guid_key);

        self.write_tlv(0x400, |writer| {
            writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_401(&mut self) {
        let mut random = [0u8; 16];
        rand::thread_rng().fill(&mut random);
        self.write_tlv(0x401, |writer| {
            writer.write_bytes(&random);
        });
    }

    pub fn tlv_511(&mut self) {
        let domains = [
            "office.qq.com",
            "qun.qq.com",
            "gamecenter.qq.com",
            "docs.qq.com",
            "mail.qq.com",
            "tim.qq.com",
            "ti.qq.com",
            "vip.qq.com",
            "tenpay.com",
            "qqweb.qq.com",
            "qzone.qq.com",
            "mma.qq.com",
            "game.qq.com",
            "openmobile.qq.com",
            "connect.qq.com",
        ];

        self.write_tlv(0x511, |writer| {
            writer.write(domains.len() as i16);
            for domain in &domains {
                writer.write(1u8);
                writer.write_str(domain, Prefix::INT16);
            }
        });
    }

    pub fn tlv_516(&mut self) {
        self.write_tlv(0x516, |writer| {
            writer.write(0u32);
        });
    }

    pub fn tlv_521(&mut self) {
        self.write_tlv(0x521, |writer| {
            writer.write(0x13u32);
            writer.write_str("basicim", Prefix::INT16);
        });
    }

    pub fn tlv_521_android(&mut self) {
        self.write_tlv(0x521, |writer| {
            writer.write(0u32);
            writer.write_str("", Prefix::INT16);
        });
    }

    pub fn tlv_525(&mut self) {
        self.write_tlv(0x525, |writer| {
            writer.write(1i16); // tlvCount
            writer.write(0x536i16); // tlv536
            writer.write_bytes_with_prefix(&[0x02, 0x01, 0x00], Prefix::INT16);
        });
    }

    pub fn tlv_52d(&mut self) {
        self.write_tlv(0x52D, |_writer| {
            // TODO: Implement DeviceReport proto serialization
            // For now, just write empty data
            // This would require implementing the proto message serialization
        });
    }

    pub fn tlv_544(&mut self, energy: &[u8]) {
        self.write_tlv(0x544, |writer| {
            writer.write_bytes(energy);
        });
    }

    pub fn tlv_545(&mut self) {
        let qimei = &self.keystore.qimei;
        self.write_tlv(0x545, |writer| {
            writer.write_bytes(qimei.as_bytes());
        });
    }

    pub fn tlv_547(&mut self, client_pow: &[u8]) {
        self.write_tlv(0x547, |writer| {
            writer.write_bytes(client_pow);
        });
    }

    pub fn tlv_548(&mut self, native_get_test_data: &[u8]) {
        self.write_tlv(0x548, |writer| {
            writer.write_bytes(native_get_test_data);
        });
    }

    pub fn tlv_553(&mut self, fekit_attach: &[u8]) {
        self.write_tlv(0x553, |writer| {
            writer.write_bytes(fekit_attach);
        });
    }

    pub fn create_bytes(mut self) -> Vec<u8> {
        let offset = if self.prefixed { 2 } else { 0 };
        let _ = self.writer.write_at(offset, self.count);
        self.writer.to_vec()
    }

    fn unix_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
