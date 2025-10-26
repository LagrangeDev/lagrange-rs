pub trait EndianSwap: private::Sealed {
    fn swap_bytes(self) -> Self;
}

mod private {
    pub trait Sealed {}
    impl Sealed for i8 {}
    impl Sealed for u8 {}
    impl Sealed for i16 {}
    impl Sealed for u16 {}
    impl Sealed for i32 {}
    impl Sealed for u32 {}
    impl Sealed for i64 {}
    impl Sealed for u64 {}
    impl Sealed for i128 {}
    impl Sealed for u128 {}
    impl Sealed for isize {}
    impl Sealed for usize {}
}

impl EndianSwap for i8 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        self
    }
}

impl EndianSwap for u8 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        self
    }
}

impl EndianSwap for i16 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        i16::swap_bytes(self)
    }
}

impl EndianSwap for u16 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        u16::swap_bytes(self)
    }
}

impl EndianSwap for i32 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        i32::swap_bytes(self)
    }
}

impl EndianSwap for u32 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        u32::swap_bytes(self)
    }
}

impl EndianSwap for i64 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        i64::swap_bytes(self)
    }
}

impl EndianSwap for u64 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        u64::swap_bytes(self)
    }
}

impl EndianSwap for i128 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        i128::swap_bytes(self)
    }
}

impl EndianSwap for u128 {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        u128::swap_bytes(self)
    }
}

impl EndianSwap for isize {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        isize::swap_bytes(self)
    }
}

impl EndianSwap for usize {
    #[inline(always)]
    fn swap_bytes(self) -> Self {
        usize::swap_bytes(self)
    }
}

#[inline(always)]
pub fn reverse_endianness<T: EndianSwap>(value: T) -> T {
    value.swap_bytes()
}

#[inline(always)]
pub fn to_be<T: EndianSwap>(value: T) -> T {
    if cfg!(target_endian = "little") {
        value.swap_bytes()
    } else {
        value
    }
}

#[inline(always)]
pub fn from_be<T: EndianSwap>(value: T) -> T {
    if cfg!(target_endian = "little") {
        value.swap_bytes()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_endianness() {
        assert_eq!(reverse_endianness(0x12u8), 0x12u8);
        assert_eq!(reverse_endianness(0x1234u16), 0x3412u16);
        assert_eq!(reverse_endianness(0x12345678u32), 0x78563412u32);
        assert_eq!(
            reverse_endianness(0x123456789ABCDEF0u64),
            0xF0DEBC9A78563412u64
        );
    }

    #[test]
    fn test_to_be_from_be() {
        let value: u32 = 0x12345678;
        let be = to_be(value);
        let native = from_be(be);
        assert_eq!(native, value);
    }

    #[test]
    fn test_signed_types() {
        assert_eq!(reverse_endianness(-1i16), -1i16);
        assert_eq!(reverse_endianness(0x1234i16), 0x3412i16);
        assert_eq!(reverse_endianness(-12345i32), reverse_endianness(-12345i32));
    }
}
