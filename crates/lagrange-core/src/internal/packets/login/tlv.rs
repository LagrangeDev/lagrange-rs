use crate::{
    common::AppInfo,
    keystore::BotKeystore,
    utils::{
        binary::{BinaryPacket, Prefix},
        crypto::TeaProvider,
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

impl<'a> Tlv<'a> {
    pub fn new(command: i16, keystore: &'a BotKeystore, app_info: &'a AppInfo) -> Self {
        let mut writer = BinaryPacket::with_capacity(1000);
        let prefixed = if command > 0 {
            writer.write(command as u16);
            true
        } else {
            false
        };
        writer.skip(2); // Skip length field

        Self {
            writer,
            count: 0,
            prefixed,
            keystore,
            app_info,
        }
    }

    /// Writes a TLV entry using a closure-based approach.
    ///
    /// This method provides a functional way to write TLV (Tag-Length-Value) entries.
    /// It automatically writes the tag, reserves space for the length, executes the closure
    /// to write the value, calculates the length, and writes it back.
    ///
    /// # Parameters
    ///
    /// * `tag` - The TLV tag identifier
    /// * `f` - Closure that receives `&mut Self` to write the TLV value
    fn write_tlv<F>(&mut self, tag: u16, f: F)
    where
        F: FnOnce(&mut Self),
    {
        self.writer.write(tag);
        let length_pos = self.writer.offset();
        self.writer.skip(2); // Reserve space for u16 length

        f(self);

        let length = (self.writer.offset() - length_pos - 2) as u16;
        self.writer.write_at(length_pos, length).unwrap();
        self.count += 1;
    }

    pub fn tlv_001(&mut self) {
        self.write_tlv(0x01, |this| {
            this.writer.write(0x0001u16);
            this.writer.write(rand::thread_rng().gen::<u32>());
            this.writer.write(this.keystore.uin.unwrap_or(0) as u32);
            this.writer.write(Self::unix_timestamp() as u32);
            this.writer.write(0u32); // dummy IP Address
            this.writer.write(0x0000u16);
        });
    }

    pub fn tlv_008(&mut self) {
        self.write_tlv(0x08, |this| {
            this.writer.write(0u16);
            this.writer.write(2052u32); // locale_id
            this.writer.write(0u16);
        });
    }

    pub fn tlv_018(&mut self) {
        self.write_tlv(0x18, |this| {
            this.writer.write(0i16);
            this.writer.write(5u32);
            this.writer.write(0u32);
            this.writer.write(8001u32); // app client ver
            this.writer.write(this.keystore.uin.unwrap_or(0) as u32);
            this.writer.write(0i16);
            this.writer.write(0i16);
        });
    }

    pub fn tlv_018_android(&mut self) {
        self.write_tlv(0x18, |this| {
            this.writer.write(0x0001i16);
            this.writer.write(0x00000600u32);
            this.writer.write(this.app_info.app_id);
            this.writer.write(this.app_info.app_client_version as i32);
            this.writer.write(this.keystore.uin.unwrap_or(0) as u32);
            this.writer.write(0x0000i16);
            this.writer.write(0x0000i16);
        });
    }

    pub fn tlv_100(&mut self) {
        self.write_tlv(0x100, |this| {
            this.writer.write(0u16); // db buf ver
            this.writer.write(5u32); // sso ver, dont over 7
            this.writer.write(this.app_info.app_id);
            this.writer.write(this.app_info.sub_app_id);
            this.writer.write(this.app_info.app_client_version as i32); // app client ver
            this.writer.write(this.app_info.sdk_info.main_sig_map);
        });
    }

    pub fn tlv_100_android(&mut self, main_sig_map: u32) {
        self.write_tlv(0x100, |this| {
            this.writer.write(1u16); // db buf ver
            this.writer.write(this.app_info.sso_version); // sso ver, dont over 7
            this.writer.write(this.app_info.app_id);
            this.writer.write(this.app_info.sub_app_id);
            this.writer.write(this.app_info.app_client_version as i32); // app client ver
            this.writer.write(main_sig_map);
        });
    }

    pub fn tlv_104(&mut self, verification_token: &[u8]) {
        self.write_tlv(0x104, |this| {
            this.writer.write_bytes(verification_token);
        });
    }

    pub fn tlv_106_pwd(&mut self, password: &str) {
        self.write_tlv(0x106, |this| {
            let md5_hash = md5::compute(password.as_bytes());

            let mut key_writer = BinaryPacket::with_capacity(16 + 4 + 4);
            key_writer.write_bytes(&md5_hash.0);
            key_writer.write(0u32); // empty 4 bytes
            key_writer.write(this.keystore.uin.unwrap_or(0) as u32);
            let key = md5::compute(key_writer.as_slice());
            let key_array: [u8; 16] = key.0;

            let mut plain_writer = BinaryPacket::with_capacity(100);
            plain_writer.write(4i16); // TGTGT Version
            plain_writer.write(rand::thread_rng().gen::<u32>());
            plain_writer.write(this.app_info.sso_version);
            plain_writer.write(this.app_info.app_id);
            plain_writer.write(this.app_info.app_client_version as i32);
            plain_writer.write(this.keystore.uin.unwrap_or(0));
            plain_writer.write(Self::unix_timestamp() as i32);
            plain_writer.write(0u32); // dummy IP Address
            plain_writer.write(1u8);
            plain_writer.write_bytes(&md5_hash.0);
            plain_writer.write_bytes(&this.keystore.sigs.tgtgt_key);
            plain_writer.write(0u32);  // unknown
            plain_writer.write(1u8); // guidAvailable
            plain_writer.write_bytes(&this.keystore.guid);
            plain_writer.write(this.app_info.sub_app_id);
            plain_writer.write(1u32); // flag
            plain_writer.write_str(&this.keystore.uin.unwrap_or(0).to_string(), Prefix::INT16);
            plain_writer.write(0i16);
            let encrypted = TeaProvider::encrypt(plain_writer.as_slice(), &key_array);
            this.writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_106_encrypted_a1(&mut self) {
        self.write_tlv(0x106, |this| {
            this.writer.write_bytes(&this.keystore.sigs.a1);
        });
    }

    pub fn tlv_107(&mut self) {
        self.write_tlv(0x107, |this| {
            this.writer.write(1u16); // pic type
            this.writer.write(0x0Du8); // captcha type
            this.writer.write(0u16); // pic size
            this.writer.write(1u8); // ret type
        });
    }

    pub fn tlv_107_android(&mut self) {
        self.write_tlv(0x107, |this| {
            this.writer.write(0u16); // pic type
            this.writer.write(0u8); // captcha type
            this.writer.write(0u16); // pic size
            this.writer.write(1u8); // ret type
        });
    }

    pub fn tlv_109(&mut self) {
        self.write_tlv(0x109, |this| {
            let hash = md5::compute(this.keystore.android_id.as_bytes());
            this.writer.write_bytes(&hash.0);
        });
    }

    pub fn tlv_112(&mut self, qid: &str) {
        self.write_tlv(0x112, |this| {
            this.writer.write_bytes(qid.as_bytes());
        });
    }

    pub fn tlv_116(&mut self) {
        self.write_tlv(0x116, |this| {
            this.writer.write(0u8); // version
            this.writer.write(this.app_info.sdk_info.misc_bit_map); // miscBitMap
            this.writer.write(this.app_info.sdk_info.sub_sig_map);
            this.writer.write(0u8); // length of subAppId
        });
    }

    pub fn tlv_11b(&mut self) {
        self.write_tlv(0x11B, |this| {
            this.writer.write(2u8);
        });
    }

    pub fn tlv_124(&mut self) {
        self.write_tlv(0x124, |this| {
            this.writer.skip(12);
        });
    }

    pub fn tlv_124_android(&mut self) {
        self.write_tlv(0x124, |this| {
            this.writer.write_str("android", Prefix::INT16);
            this.writer.write_str("13", Prefix::INT16); // os version
            this.writer.write(0x02i16); // network type
            this.writer.write_str("", Prefix::INT16); // sim info
            this.writer.write_str("wifi", Prefix::INT32); // apn
        });
    }

    pub fn tlv_128(&mut self) {
        self.write_tlv(0x128, |this| {
            this.writer.write(0u16);
            this.writer.write(0u8); // guid new
            this.writer.write(0u8); // guid available
            this.writer.write(0u8); // guid changed
            this.writer.write(0u32); // guid flag
            this.writer.write_str(&this.app_info.os, Prefix::INT16);
            this.writer.write_bytes_with_prefix(&this.keystore.guid, Prefix::INT16);
            this.writer.write_str("", Prefix::INT16); // brand
        });
    }

    pub fn tlv_141(&mut self) {
        self.write_tlv(0x141, |this| {
            this.writer.write(0u16);
            this.writer.write_str("Unknown", Prefix::INT16);
            this.writer.write(0u32);
        });
    }

    pub fn tlv_141_android(&mut self) {
        self.write_tlv(0x141, |this| {
            this.writer.write(1u16);
            this.writer.write_str("", Prefix::INT16);
            this.writer.write_str("", Prefix::INT16);
            this.writer.write_str("wifi", Prefix::INT16);
        });
    }

    pub fn tlv_142(&mut self) {
        self.write_tlv(0x142, |this| {
            this.writer.write(0u16);
            this.writer.write_str(&this.app_info.package_name, Prefix::INT16);
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
        let encrypted = TeaProvider::encrypt(&span, &tgtgt_key);

        self.write_tlv(0x144, |this| {
            this.writer.write_bytes(&encrypted);
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
        let encrypted = TeaProvider::encrypt(&span, &key_array);

        self.write_tlv(0x144, |this| {
            this.writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_145(&mut self) {
        self.write_tlv(0x145, |this| {
            this.writer.write_bytes(&this.keystore.guid);
        });
    }

    pub fn tlv_147(&mut self) {
        self.write_tlv(0x147, |this| {
            this.writer.write(this.app_info.app_id);
            this.writer.write_str(&this.app_info.pt_version, Prefix::INT16);
            this.writer.write_bytes_with_prefix(&this.app_info.apk_signature_md5, Prefix::INT16);
        });
    }

    pub fn tlv_154(&mut self) {
        self.write_tlv(0x154, |this| {
            this.writer.write(0u32);  // seq
        });
    }

    pub fn tlv_166(&mut self) {
        self.write_tlv(0x166, |this| {
            this.writer.write(5u8);
        });
    }

    pub fn tlv_16a(&mut self) {
        self.write_tlv(0x16A, |this| {
            if let Some(ref no_pic_sig) = this.keystore.sigs.no_pic_sig {
                this.writer.write_bytes(no_pic_sig);
            }
        });
    }

    pub fn tlv_16e(&mut self) {
        self.write_tlv(0x16E, |this| {
            this.writer.write_bytes(this.keystore.device_name.as_bytes());
        });
    }

    pub fn tlv_174(&mut self, session: &[u8]) {
        self.write_tlv(0x174, |this| {
            this.writer.write_bytes(session);
        });
    }

    pub fn tlv_177(&mut self) {
        self.write_tlv(0x177, |this| {
            this.writer.write(1u8);
            this.writer.write(0u32); // sdk build time
            this.writer.write_str(&this.app_info.sdk_info.sdk_version, Prefix::INT16);
        });
    }

    pub fn tlv_17a(&mut self) {
        self.write_tlv(0x17A, |this| {
            this.writer.write(9u32);
        });
    }

    pub fn tlv_17c(&mut self, code: &str) {
        self.write_tlv(0x17C, |this| {
            this.writer.write_str(code, Prefix::INT16);
        });
    }

    pub fn tlv_187(&mut self) {
        self.write_tlv(0x187, |this| {
            let hash = md5::compute(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]); // Dummy Mac Address
            this.writer.write_bytes(&hash.0);
        });
    }

    pub fn tlv_188(&mut self) {
        self.write_tlv(0x188, |this| {
            let hash = md5::compute(this.keystore.android_id.as_bytes());
            this.writer.write_bytes(&hash.0);
        });
    }

    pub fn tlv_191(&mut self, k: u8) {
        self.write_tlv(0x191, |this| {
            this.writer.write(k);
        });
    }

    pub fn tlv_193(&mut self, ticket: &[u8]) {
        self.write_tlv(0x193, |this| {
            this.writer.write_bytes(ticket);
        });
    }

    pub fn tlv_197(&mut self) {
        self.write_tlv(0x197, |this| {
            this.writer.write(0u8);
        });
    }

    pub fn tlv_198(&mut self) {
        self.write_tlv(0x198, |this| {
            this.writer.write(0u8);
        });
    }

    pub fn tlv_318(&mut self) {
        self.write_tlv(0x318, |_this| {
        });
    }

    pub fn tlv_400(&mut self) {
        self.write_tlv(0x400, |this| {
            let mut random_key = [0u8; 16];
            rand::thread_rng().fill(&mut random_key);
            let mut rand_seed = [0u8; 8];
            rand::thread_rng().fill(&mut rand_seed);

            let mut inner_writer = BinaryPacket::with_capacity(100);
            inner_writer.write(1i16);
            inner_writer.write(this.keystore.uin.unwrap_or(0));
            inner_writer.write_bytes(&this.keystore.guid);
            inner_writer.write_bytes(&random_key);
            inner_writer.write(16u32);
            inner_writer.write(1u32);
            inner_writer.write(Self::unix_timestamp() as u32);
            inner_writer.write_bytes(&rand_seed);

            let guid_key: [u8; 16] = this.keystore.guid[..16].try_into().unwrap();
            let encrypted = TeaProvider::encrypt(inner_writer.as_slice(), &guid_key);

            this.writer.write_bytes(&encrypted);
        });
    }

    pub fn tlv_401(&mut self) {
        self.write_tlv(0x401, |this| {
            let mut random = [0u8; 16];
            rand::thread_rng().fill(&mut random);
            this.writer.write_bytes(&random);
        });
    }

    pub fn tlv_511(&mut self) {
        self.write_tlv(0x511, |this| {
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

            this.writer.write(domains.len() as i16);
            for domain in &domains {
                this.writer.write(1u8);
                this.writer.write_str(domain, Prefix::INT16);
            }
        });
    }

    pub fn tlv_516(&mut self) {
        self.write_tlv(0x516, |this| {
            this.writer.write(0u32);
        });
    }

    pub fn tlv_521(&mut self) {
        self.write_tlv(0x521, |this| {
            this.writer.write(0x13u32);
            this.writer.write_str("basicim", Prefix::INT16);
        });
    }

    pub fn tlv_521_android(&mut self) {
        self.write_tlv(0x521, |this| {
            this.writer.write(0u32);
            this.writer.write_str("", Prefix::INT16);
        });
    }

    pub fn tlv_525(&mut self) {
        self.write_tlv(0x525, |this| {
            this.writer.write(1i16); // tlvCount
            this.writer.write(0x536i16); // tlv536
            this.writer.write_bytes_with_prefix(&[0x02, 0x01, 0x00], Prefix::INT16);
        });
    }

    pub fn tlv_52d(&mut self) {
        self.write_tlv(0x52D, |_this| {
            // TODO: Implement DeviceReport proto serialization
            // For now, just write empty data
            // This would require implementing the proto message serialization
        });
    }

    pub fn tlv_544(&mut self, energy: &[u8]) {
        self.write_tlv(0x544, |this| {
            this.writer.write_bytes(energy);
        });
    }

    pub fn tlv_545(&mut self) {
        self.write_tlv(0x545, |this| {
            this.writer.write_bytes(this.keystore.qimei.as_bytes());
        });
    }

    pub fn tlv_547(&mut self, client_pow: &[u8]) {
        self.write_tlv(0x547, |this| {
            this.writer.write_bytes(client_pow);
        });
    }

    pub fn tlv_548(&mut self, native_get_test_data: &[u8]) {
        self.write_tlv(0x548, |this| {
            this.writer.write_bytes(native_get_test_data);
        });
    }

    pub fn tlv_553(&mut self, fekit_attach: &[u8]) {
        self.write_tlv(0x553, |this| {
            this.writer.write_bytes(fekit_attach);
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
