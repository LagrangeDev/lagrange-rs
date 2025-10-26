use super::{sso_packet::SsoPacket, sso_secure_info::SsoSecureInfo, struct_base::StructBase};
use crate::{
    common::AppInfo,
    keystore::BotKeystore,
    protocol::Protocols,
    utils::binary::{BinaryPacket, Prefix},
};
use bytes::Bytes;
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

        writer
            .with_length_prefix::<u32, _, _>(true, 0, |w| {
                // TODO: Implement proper SsoReserveFields protobuf serialization
                // For now, write minimal fields

                // TODO: Implement proper protobuf encoding with varint
                // For now, write basic fields with length prefixes

                // Field 15: TraceParent (string)
                if !trace.is_empty() {
                    w.write((15u32 << 3) | 2); // field 15, wire type 2 (length-delimited)
                    w.write(trace.len() as u32);
                    w.write_bytes(trace.as_bytes());
                }

                // Field 16: Uid (string)
                if let Some(ref uid) = self.keystore.uid {
                    w.write((16u32 << 3) | 2); // field 16, wire type 2
                    w.write(uid.len() as u32);
                    w.write_bytes(uid.as_bytes());
                }

                // Field 24: SecInfo (message)
                if let Some(sec_info) = sec_info {
                    use lagrange_proto::ProtoMessage;
                    let serialized = sec_info.encode_to_vec().unwrap_or_default();
                    if !serialized.is_empty() {
                        w.write((24u32 << 3) | 2); // field 24, wire type 2
                        w.write(serialized.len() as u32);
                        w.write_bytes(&serialized);
                    }
                }

                // Android-specific fields
                if self.protocol.is_android() {
                    // Field 21: MsgType (uint32)
                    w.write(21u32 << 3); // field 21, wire type 0 (varint)
                    w.write(32u32); // msg_type = 32

                    // Field 26: NtCoreVersion (uint32)
                    w.write(26u32 << 3); // field 26, wire type 0
                    w.write(100u32); // nt_core_version = 100
                }
            })
            .unwrap();
    }
}

impl<'a> StructBase for SsoPacker<'a> {
    fn keystore(&self) -> &BotKeystore {
        self.keystore
    }

    fn app_info(&self) -> &AppInfo {
        self.app_info
    }
}
