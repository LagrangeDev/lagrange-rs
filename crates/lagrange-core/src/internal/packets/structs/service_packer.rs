use crate::{
    keystore::BotKeystore,
    protocol::EncryptType,
    utils::{
        binary::{BinaryPacket, Prefix},
        crypto::tea,
    },
};

const EMPTY_D2_KEY: [u8; 16] = [0u8; 16];

/// Build a Protocol 12 service packet (D2 authentication)
pub fn service_build_protocol_12(
    keystore: &BotKeystore,
    sso: BinaryPacket,
    encrypt_type: EncryptType,
) -> Vec<u8> {
    let cipher = match encrypt_type {
        EncryptType::NoEncrypt => sso.as_slice().to_vec(),
        EncryptType::EncryptEmpty => tea::encrypt(sso.as_slice(), &EMPTY_D2_KEY),
        EncryptType::EncryptD2Key => {
            let d2_key: [u8; 16] = keystore.sigs.d2_key[..16]
                .try_into()
                .unwrap_or(EMPTY_D2_KEY);
            tea::encrypt(sso.as_slice(), &d2_key)
        }
    };

    let mut writer = BinaryPacket::with_capacity(0x200);

    writer.write(12i32);
    writer.write(encrypt_type as u8);

    if encrypt_type == EncryptType::EncryptD2Key {
        writer.write_bytes_with_prefix(
            &keystore.sigs.d2,
            Prefix::INT32 | Prefix::WITH_PREFIX,
        );
    } else {
        writer.write(4u32);
    }

    writer.write(0u8);
    writer.write_str(
        &keystore.uin.unwrap_or(0).to_string(),
        Prefix::INT32 | Prefix::WITH_PREFIX,
    );
    writer.write_bytes(&cipher);

    writer.to_vec()
}

/// Build a Protocol 13 service packet (simple)
pub fn service_build_protocol_13(
    keystore: &BotKeystore,
    sequence: i32,
    payload: &[u8],
    encrypt_type: EncryptType,
) -> Vec<u8> {
    let cipher = match encrypt_type {
        EncryptType::NoEncrypt => payload.to_vec(),
        EncryptType::EncryptEmpty => tea::encrypt(payload, &EMPTY_D2_KEY),
        EncryptType::EncryptD2Key => {
            let d2_key: [u8; 16] = keystore.sigs.d2_key[..16]
                .try_into()
                .unwrap_or(EMPTY_D2_KEY);
            tea::encrypt(payload, &d2_key)
        }
    };

    let mut writer = BinaryPacket::with_capacity(0x200);

    writer.write(13i32);
    writer.write(encrypt_type as u8);
    writer.write(sequence);
    writer.write(0u8);
    writer.write_str(
        &keystore.uin.unwrap_or(0).to_string(),
        Prefix::INT32 | Prefix::WITH_PREFIX,
    );
    writer.write_bytes(&cipher);

    writer.to_vec()
}

/// Parse a service packet response
pub fn service_parse(keystore: &BotKeystore, input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut reader = BinaryPacket::from_slice(input);

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
        0x00 => encrypted.to_vec(),
        0x02 => {
            tea::decrypt(encrypted, &EMPTY_D2_KEY)
                .map_err(|_| "Failed to decrypt with empty key")?
        }
        0x01 => {
            let d2_key: [u8; 16] = keystore.sigs.d2_key[..16]
                .try_into()
                .unwrap_or(EMPTY_D2_KEY);
            tea::decrypt(encrypted, &d2_key)
                .map_err(|_| "Failed to decrypt with D2 key")?
        }
        _ => return Err("Unrecognized auth flag"),
    };

    Ok(decrypted)
}
