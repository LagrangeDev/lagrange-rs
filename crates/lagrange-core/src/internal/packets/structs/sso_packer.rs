use super::{
    sso_packet::SsoPacket, sso_reserved_fields::SsoReservedFields, sso_secure_info::SsoSecureInfo,
};
use crate::{
    common::AppInfo,
    keystore::BotKeystore,
    protocol::Protocols,
    utils::binary::{BinaryPacket, Prefix},
};
use bytes::Bytes;
use lagrange_proto::ProtoMessage;
use rand::Rng;

const HEX_CHARS: &[u8] = b"0123456789abcdef";

/// SSO-level packet packer (Protocol 12/13)
pub struct SsoPacker<'a> {
    keystore: &'a BotKeystore,
    app_info: &'a AppInfo,
    protocol: Protocols,
}

impl<'a> SsoPacker<'a> {
    pub fn new(keystore: &'a BotKeystore, app_info: &'a AppInfo, protocol: Protocols) -> Self {
        Self {
            keystore,
            app_info,
            protocol,
        }
    }

    fn guid_hex(&self) -> String {
        self.keystore
            .guid
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Build a Protocol 12 SSO packet (with full header)
    pub fn build_protocol_12(
        &self,
        sso: &SsoPacket,
        sec_info: Option<&SsoSecureInfo>,
    ) -> BinaryPacket {
        let mut head = BinaryPacket::with_capacity(0x200);

        head.write(sso.sequence); // sequence
        head.write(self.app_info.sub_app_id); // subAppId
        head.write(2052u32); // unknown locale
        head.write_bytes(&[
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        head.write_bytes_with_prefix(&self.keystore.sigs.a2, Prefix::INT32 | Prefix::WITH_PREFIX); // tgt
        head.write_str(&sso.command, Prefix::INT32 | Prefix::WITH_PREFIX); // command
        head.write_str("", Prefix::INT32 | Prefix::WITH_PREFIX); // message_cookies (empty)
        head.write_str(&self.guid_hex(), Prefix::INT32 | Prefix::WITH_PREFIX); // guid
        head.write_str("", Prefix::INT32 | Prefix::WITH_PREFIX); // empty
        head.write_str(
            &self.app_info.current_version,
            Prefix::INT16 | Prefix::WITH_PREFIX,
        );
        self.write_sso_reserved_field(&mut head, sec_info);

        let head_span = head.as_slice();
        let mut result = BinaryPacket::with_capacity(head_span.len() + sso.data.len() + 2 * 4);

        result.write_bytes_with_prefix(head_span, Prefix::INT32 | Prefix::WITH_PREFIX);
        result.write_bytes_with_prefix(&sso.data, Prefix::INT32 | Prefix::WITH_PREFIX); // payload

        result
    }

    /// Build a Protocol 13 SSO packet (simplified header)
    pub fn build_protocol_13(&self, sso: &SsoPacket) -> BinaryPacket {
        let mut head = BinaryPacket::with_capacity(0x200);

        head.write_str(&sso.command, Prefix::INT32 | Prefix::WITH_PREFIX); // command
        head.write_str("", Prefix::INT32 | Prefix::WITH_PREFIX); // message_cookies (empty)
        self.write_sso_reserved_field(&mut head, None);

        let head_span = head.as_slice();
        let mut result = BinaryPacket::with_capacity(head_span.len() + sso.data.len() + 2 * 4);

        result.write_bytes_with_prefix(head_span, Prefix::INT32 | Prefix::WITH_PREFIX);
        result.write_bytes_with_prefix(&sso.data, Prefix::INT32 | Prefix::WITH_PREFIX); // payload

        result
    }

    /// Parse an SSO packet response
    pub fn parse(&self, data: &[u8]) -> Result<SsoPacket, &'static str> {
        let mut parent = BinaryPacket::from_slice(data);
        let head = parent
            .read_bytes_with_prefix(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read head")?
            .to_vec();
        let body = parent
            .read_bytes_with_prefix(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read body")?
            .to_vec();

        let mut head_reader = BinaryPacket::from_slice(&head);
        let sequence = head_reader
            .read::<i32>()
            .map_err(|_| "Failed to read sequence")?;
        let ret_code = head_reader
            .read::<i32>()
            .map_err(|_| "Failed to read ret_code")?;
        let extra = head_reader
            .read_string(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read extra")?;
        let command = head_reader
            .read_string(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read command")?;
        let _msg_cookie = head_reader
            .read_bytes_with_prefix(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read msg_cookie")?;
        let data_flag = head_reader
            .read::<i32>()
            .map_err(|_| "Failed to read data_flag")?;
        let _reserve_field = head_reader
            .read_bytes_with_prefix(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read reserve_field")?;

        let payload = match data_flag {
            0 | 4 => Bytes::copy_from_slice(&body),
            1 => {
                // TODO: Implement ZCompression decompression
                // For now, return error or empty bytes
                return Err("Compression not yet implemented");
            }
            _ => return Err("Unknown data flag"),
        };

        if ret_code == 0 {
            Ok(SsoPacket::new(command, payload, sequence))
        } else {
            Ok(SsoPacket::new_error(command, sequence, ret_code, extra))
        }
    }

    fn write_sso_reserved_field(
        &self,
        writer: &mut BinaryPacket,
        sec_info: Option<&SsoSecureInfo>,
    ) {
        // Generate trace parent string: 01-{32 hex chars}-{16 hex chars}-01
        let mut trace = String::with_capacity(55);
        trace.push_str("01-");

        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            let idx = rng.gen_range(0..HEX_CHARS.len());
            trace.push(HEX_CHARS[idx] as char);
        }

        trace.push('-');

        for _ in 0..16 {
            let idx = rng.gen_range(0..HEX_CHARS.len());
            trace.push(HEX_CHARS[idx] as char);
        }

        trace.push_str("-01");

        // Build the SsoReservedFields using lagrange-proto
        let reserved_fields = SsoReservedFields {
            trace_parent: Some(trace),
            uid: self.keystore.uid.clone(),
            msg_type: self.protocol.is_android().then_some(32),
            sec_info: sec_info.cloned(),
            nt_core_version: self.protocol.is_android().then_some(100),
        };

        // Encode to bytes using lagrange-proto
        let serialized = reserved_fields.encode_to_vec().unwrap_or_default();

        // Write with u32 length prefix
        writer.write_bytes_with_prefix(&serialized, Prefix::INT32 | Prefix::WITH_PREFIX);
    }
}
