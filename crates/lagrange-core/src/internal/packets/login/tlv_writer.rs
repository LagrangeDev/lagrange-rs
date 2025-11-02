use crate::utils::binary::BinaryPacket;

pub trait TlvWritable {
    fn writer_mut(&mut self) -> &mut BinaryPacket;

    fn increment_count(&mut self);

    #[inline]
    fn write_tlv<F>(&mut self, tag: u16, f: F)
    where
        F: FnOnce(&mut Self),
    {
        self.writer_mut().write(tag);

        let length_pos = self.writer_mut().offset();
        self.writer_mut().skip(2); // Reserve space for u16 length

        f(self);

        let length = (self.writer_mut().offset() - length_pos - 2) as u16;
        self.writer_mut().write_at(length_pos, length).unwrap();
        self.increment_count();
    }
}
