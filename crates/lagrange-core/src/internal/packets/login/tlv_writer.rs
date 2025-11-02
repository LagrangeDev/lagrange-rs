use crate::utils::binary::BinaryPacket;

pub trait TlvWritable {
    fn writer_mut(&mut self) -> &mut BinaryPacket;

    fn increment_count(&mut self);

    #[inline]
    fn write_tlv<F>(&mut self, tag: u16, f: F)
    where
        F: FnOnce(&mut BinaryPacket),
    {
        let writer = self.writer_mut();
        writer.write(tag);
        writer
            .with_length_prefix::<u16, _, _>(false, 0, f)
            .unwrap();
        self.increment_count();
    }
}
