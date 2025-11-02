use super::{
    qr_login_ext_info::{DevInfo, GenInfo, QrExtInfo, ScanExtInfo},
    tlv_writer::TlvWritable,
};
use crate::{
    common::AppInfo,
    keystore::BotKeystore,
    utils::binary::{BinaryPacket, Prefix},
};

/// TLV builder for QR code login packets
pub struct TlvQrCode<'a> {
    writer: BinaryPacket,
    count: u16,
    keystore: &'a BotKeystore,
    app_info: &'a AppInfo,
}

impl<'a> TlvWritable for TlvQrCode<'a> {
    fn writer_mut(&mut self) -> &mut BinaryPacket {
        &mut self.writer
    }

    fn increment_count(&mut self) {
        self.count += 1;
    }
}

impl<'a> TlvQrCode<'a> {
    pub fn new(keystore: &'a BotKeystore, app_info: &'a AppInfo) -> Self {
        let mut writer = BinaryPacket::with_capacity(300);
        writer.skip(2); // Skip count field

        Self {
            writer,
            count: 0,
            keystore,
            app_info,
        }
    }

    pub fn tlv_02(&mut self) {
        self.write_tlv(0x02, |writer| {
            writer.write(0u32);
            writer.write(0x0Bu32);
        });
    }

    pub fn tlv_04(&mut self) {
        let uin_str = self.keystore.uin.unwrap_or(0).to_string();
        self.write_tlv(0x04, |writer| {
            writer.write(0x00i16); // uin for 0, uid for 1
            writer.write_str(&uin_str, Prefix::INT16);
        });
    }

    pub fn tlv_09(&mut self) {
        let package_name = &self.app_info.package_name;
        self.write_tlv(0x09, |writer| {
            writer.write_bytes(package_name.as_bytes());
        });
    }

    pub fn tlv_11(&mut self, unusual_sig: &[u8]) {
        self.write_tlv(0x11, |writer| {
            writer.write_bytes(unusual_sig);
        });
    }

    pub fn tlv_15(&mut self) {
        self.write_tlv(0x15, |writer| {
            writer.write(0u32);
        });
    }

    pub fn tlv_16(&mut self) {
        let app_id = self.app_info.app_id;
        let sub_app_id = self.app_info.sub_app_id;
        let guid = &self.keystore.guid;
        let package_name = &self.app_info.package_name;
        let pt_version = &self.app_info.pt_version;
        self.write_tlv(0x16, |writer| {
            writer.write(0u32);
            writer.write(app_id);
            writer.write(sub_app_id);
            writer.write_bytes(guid);
            writer.write_str(package_name, Prefix::INT16);
            writer.write_str(pt_version, Prefix::INT16);
            writer.write_str(package_name, Prefix::INT16);
        });
    }

    pub fn tlv_18(&mut self) {
        let a1 = &self.keystore.sigs.a1;
        self.write_tlv(0x18, |writer| {
            writer.write_bytes(a1);
        });
    }

    pub fn tlv_19(&mut self) {
        let no_pic_sig = self.keystore.sigs.no_pic_sig.as_ref();
        self.write_tlv(0x19, |writer| {
            if let Some(no_pic_sig) = no_pic_sig {
                writer.write_bytes(no_pic_sig);
            }
        });
    }

    pub fn tlv_1b(&mut self) {
        self.write_tlv(0x1B, |writer| {
            writer.write(0u32); // micro
            writer.write(0u32); // version
            writer.write(3u32); // size
            writer.write(4u32); // margin
            writer.write(72u32); // dpi
            writer.write(2u32); // eclevel
            writer.write(2u32); // hint
            writer.write(0u16); // unknown
        });
    }

    pub fn tlv_1d(&mut self) {
        let misc_bit_map = self.app_info.sdk_info.misc_bit_map;
        self.write_tlv(0x1D, |writer| {
            writer.write(1u8);
            writer.write(misc_bit_map);
            writer.write(0u32);
            writer.write(0u8);
        });
    }

    pub fn tlv_33(&mut self) {
        let guid = &self.keystore.guid;
        self.write_tlv(0x33, |writer| {
            writer.write_bytes(guid);
        });
    }

    pub fn tlv_35(&mut self) {
        let sso_version = self.app_info.sso_version;
        self.write_tlv(0x35, |writer| {
            writer.write(sso_version);
        });
    }

    pub fn tlv_39(&mut self) {
        self.write_tlv(0x39, |writer| {
            writer.write(0x01u32);
        });
    }

    pub fn tlv_66(&mut self) {
        let sso_version = self.app_info.sso_version;
        self.write_tlv(0x66, |writer| {
            writer.write(sso_version);
        });
    }

    pub fn tlv_68(&mut self) {
        let guid = &self.keystore.guid;
        self.write_tlv(0x68, |writer| {
            writer.write_bytes(guid);
        });
    }

    pub fn tlv_d1(&mut self) {
        let qr_ext_info = QrExtInfo {
            dev_info: Some(DevInfo {
                dev_type: self.app_info.os.clone(),
                dev_name: self.keystore.device_name.clone(),
            }),
            qr_url: None,
            qr_sig: None,
            gen_info: Some(GenInfo {
                client_type: None,
                client_ver: None,
                client_appid: None,
                field6: 1,
            }),
        };

        // Serialize the proto message
        let bytes = lagrange_proto::to_bytes(&qr_ext_info);

        self.write_tlv(0xD1, |writer| {
            if let Ok(bytes) = bytes {
                writer.write_bytes(&bytes);
            }
        });
    }

    pub fn tlv_12c(&mut self) {
        let scan_ext_info = ScanExtInfo {
            guid: bytes::Bytes::copy_from_slice(&self.keystore.guid),
            imei: self.keystore.qimei.clone(),
            scan_scene: 1,
            allow_auto_renew_ticket: true,
            invalid_gen_ticket: None,
        };

        // Serialize the proto message
        let bytes = lagrange_proto::to_bytes(&scan_ext_info);

        self.write_tlv(0x12C, |writer| {
            if let Ok(bytes) = bytes {
                writer.write_bytes(&bytes);
            }
        });
    }

    pub fn create_bytes(mut self) -> Vec<u8> {
        let _ = self.writer.write_at(0, self.count);
        self.writer.to_vec()
    }
}
