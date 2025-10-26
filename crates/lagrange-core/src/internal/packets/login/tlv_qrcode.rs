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

    pub fn tlv_02(&mut self) {
        self.write_tlv(0x02, |this| {
            this.writer.write(0u32);
            this.writer.write(0x0Bu32);
        });
    }

    pub fn tlv_04(&mut self) {
        self.write_tlv(0x04, |this| {
            this.writer.write(0x00i16); // uin for 0, uid for 1
            this.writer
                .write_str(&this.keystore.uin.unwrap_or(0).to_string(), Prefix::INT16);
        });
    }

    pub fn tlv_09(&mut self) {
        self.write_tlv(0x09, |this| {
            this.writer
                .write_bytes(this.app_info.package_name.as_bytes());
        });
    }

    pub fn tlv_11(&mut self, unusual_sig: &[u8]) {
        self.write_tlv(0x11, |this| {
            this.writer.write_bytes(unusual_sig);
        });
    }

    pub fn tlv_15(&mut self) {
        self.write_tlv(0x15, |this| {
            this.writer.write(0u32);
        });
    }

    pub fn tlv_16(&mut self) {
        self.write_tlv(0x16, |this| {
            this.writer.write(0u32);
            this.writer.write(this.app_info.app_id);
            this.writer.write(this.app_info.sub_app_id);
            this.writer.write_bytes(&this.keystore.guid);
            this.writer
                .write_str(&this.app_info.package_name, Prefix::INT16);
            this.writer
                .write_str(&this.app_info.pt_version, Prefix::INT16);
            this.writer
                .write_str(&this.app_info.package_name, Prefix::INT16);
        });
    }

    pub fn tlv_18(&mut self) {
        self.write_tlv(0x18, |this| {
            this.writer.write_bytes(&this.keystore.sigs.a1);
        });
    }

    pub fn tlv_19(&mut self) {
        self.write_tlv(0x19, |this| {
            if let Some(ref no_pic_sig) = this.keystore.sigs.no_pic_sig {
                this.writer.write_bytes(no_pic_sig);
            }
        });
    }

    pub fn tlv_1b(&mut self) {
        self.write_tlv(0x1B, |this| {
            this.writer.write(0u32); // micro
            this.writer.write(0u32); // version
            this.writer.write(3u32); // size
            this.writer.write(4u32); // margin
            this.writer.write(72u32); // dpi
            this.writer.write(2u32); // eclevel
            this.writer.write(2u32); // hint
            this.writer.write(0u16); // unknown
        });
    }

    pub fn tlv_1d(&mut self) {
        self.write_tlv(0x1D, |this| {
            this.writer.write(1u8);
            this.writer.write(this.app_info.sdk_info.misc_bit_map);
            this.writer.write(0u32);
            this.writer.write(0u8);
        });
    }

    pub fn tlv_33(&mut self) {
        self.write_tlv(0x33, |this| {
            this.writer.write_bytes(&this.keystore.guid);
        });
    }

    pub fn tlv_35(&mut self) {
        self.write_tlv(0x35, |this| {
            this.writer.write(this.app_info.sso_version);
        });
    }

    pub fn tlv_39(&mut self) {
        self.write_tlv(0x39, |this| {
            this.writer.write(0x01u32);
        });
    }

    pub fn tlv_66(&mut self) {
        self.write_tlv(0x66, |this| {
            this.writer.write(this.app_info.sso_version);
        });
    }

    pub fn tlv_68(&mut self) {
        self.write_tlv(0x68, |this| {
            this.writer.write_bytes(&this.keystore.guid);
        });
    }

    pub fn tlv_d1(&mut self) {
        self.write_tlv(0xD1, |_this| {
            // TODO: Implement QrExtInfo proto serialization
            // For now, just write minimal data
            // This would require implementing the proto message serialization
        });
    }

    pub fn tlv_12c(&mut self) {
        self.write_tlv(0x12C, |_this| {
            // TODO: Implement ScanExtInfo proto serialization
            // For now, just write minimal data
            // This would require implementing the proto message serialization
        });
    }

    pub fn create_bytes(mut self) -> Vec<u8> {
        let _ = self.writer.write_at(0, self.count);
        self.writer.to_vec()
    }
}
