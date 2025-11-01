use crate::error::Result;
use crate::utils::binary::{BinaryPacket, Prefix};
use std::collections::HashMap;

pub fn tlv_unpack(reader: &mut BinaryPacket) -> Result<HashMap<u16, Vec<u8>>> {
    let mut tlvs = HashMap::new();

    let count = reader.read::<u16>()?;
    for _ in 0..count {
        let tag = reader.read::<u16>()?;
        let data = reader.read_bytes_with_prefix(Prefix::INT16)?.to_vec();
        tlvs.insert(tag, data);
    }

    Ok(tlvs)
}
