use crate::{
    keystore::BotKeystore,
    utils::{
        binary::{BinaryPacket, Prefix},
        crypto::TeaProvider,
    },
};

const EMPTY_D2_KEY: [u8; 16] = [0u8; 16];

/// Encryption type for service packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptType {
    NoEncrypt = 0x00,
    EncryptD2Key = 0x01,
    EncryptEmpty = 0x02,
}

/// Request type for protocol packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    D2Auth = 0x0C,
    Simple = 0x0D,
}

/// Service-level packet packer (Protocol 12/13)
pub struct ServicePacker<'a> {
    keystore: &'a BotKeystore,
}

impl<'a> ServicePacker<'a> {
    pub fn new(keystore: &'a BotKeystore) -> Self {
        Self { keystore }
    }

    /// Build a Protocol 12 packet (D2 authentication)
    pub fn build_protocol_12(&self, sso: BinaryPacket, encrypt_type: EncryptType) -> Vec<u8> {
        let cipher = match encrypt_type {
            EncryptType::NoEncrypt => sso.as_slice().to_vec(),
            EncryptType::EncryptEmpty => TeaProvider::encrypt(sso.as_slice(), &EMPTY_D2_KEY),
            EncryptType::EncryptD2Key => {
                let d2_key: [u8; 16] = self.keystore.sigs.d2_key[..16]
                    .try_into()
                    .unwrap_or(EMPTY_D2_KEY);
                TeaProvider::encrypt(sso.as_slice(), &d2_key)
            }
        };

        let mut writer = BinaryPacket::with_capacity(0x200);

        writer
            .with_length_prefix::<u32, _, _>(true, 0, |w| {
                w.write(12i32);
                w.write(encrypt_type as u8);

                if encrypt_type == EncryptType::EncryptD2Key {
                    w.write_bytes_with_prefix(
                        &self.keystore.sigs.d2,
                        Prefix::INT32 | Prefix::WITH_PREFIX,
                    );
                } else {
                    w.write(4u32);
                }

                w.write(0u8);
                w.write_str(
                    &self.keystore.uin.unwrap_or(0).to_string(),
                    Prefix::INT32 | Prefix::WITH_PREFIX,
                );
                w.write_bytes(&cipher);
            })
            .unwrap();

        writer.to_vec()
    }

    /// Build a Protocol 13 packet (simple)
    pub fn build_protocol_13(
        &self,
        sequence: i32,
        payload: &[u8],
        encrypt_type: EncryptType,
    ) -> Vec<u8> {
        let cipher = match encrypt_type {
            EncryptType::NoEncrypt => payload.to_vec(),
            EncryptType::EncryptEmpty => TeaProvider::encrypt(payload, &EMPTY_D2_KEY),
            EncryptType::EncryptD2Key => {
                let d2_key: [u8; 16] = self.keystore.sigs.d2_key[..16]
                    .try_into()
                    .unwrap_or(EMPTY_D2_KEY);
                TeaProvider::encrypt(payload, &d2_key)
            }
        };

        let mut writer = BinaryPacket::with_capacity(0x200);

        writer
            .with_length_prefix::<u32, _, _>(true, 0, |w| {
                w.write(13i32);
                w.write(encrypt_type as u8);
                w.write(sequence);
                w.write(0u8);
                w.write_str(
                    &self.keystore.uin.unwrap_or(0).to_string(),
                    Prefix::INT32 | Prefix::WITH_PREFIX,
                );
                w.write_bytes(&cipher);
            })
            .unwrap();

        writer.to_vec()
    }

    /// Parse a service packet response
    pub fn parse(&self, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut reader = BinaryPacket::from_slice(input);

        let _length = reader.read::<u32>().map_err(|_| "Failed to read length")?;
        let _protocol = reader
            .read::<i32>()
            .map_err(|_| "Failed to read protocol")?;
        let auth_flag = reader
            .read::<u8>()
            .map_err(|_| "Failed to read auth flag")?;
        let _dummy = reader.read::<u8>().map_err(|_| "Failed to read dummy")?;

        let _uin_str = reader
            .read_string(Prefix::INT32 | Prefix::WITH_PREFIX)
            .map_err(|_| "Failed to read UIN")?;

        let encrypted = reader.read_remaining();

        let decrypted = match auth_flag {
            0x00 => encrypted.to_vec(), // NoEncrypt
            0x02 => {
                // EncryptEmpty
                TeaProvider::decrypt(encrypted, &EMPTY_D2_KEY)
                    .map_err(|_| "Failed to decrypt with empty key")?
            }
            0x01 => {
                // EncryptD2Key
                let d2_key: [u8; 16] = self.keystore.sigs.d2_key[..16]
                    .try_into()
                    .unwrap_or(EMPTY_D2_KEY);
                TeaProvider::decrypt(encrypted, &d2_key)
                    .map_err(|_| "Failed to decrypt with D2 key")?
            }
            _ => return Err("Unrecognized auth flag"),
        };

        Ok(decrypted)
    }
}
