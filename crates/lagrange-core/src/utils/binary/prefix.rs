#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix(u8);

impl Prefix {
    pub const NONE: Self = Self(0b0000);
    pub const INT8: Self = Self(0b0001);
    pub const INT16: Self = Self(0b0010);
    pub const INT32: Self = Self(0b0100);
    pub const WITH_PREFIX: Self = Self(0b1000);

    #[inline]
    pub const fn prefix_length(self) -> usize {
        (self.0 & 0b0111) as usize
    }

    #[inline]
    pub const fn is_length_counted(self) -> bool {
        (self.0 & Self::WITH_PREFIX.0) != 0
    }

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl std::ops::BitOr for Prefix {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for Prefix {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_length() {
        assert_eq!(Prefix::NONE.prefix_length(), 0);
        assert_eq!(Prefix::INT8.prefix_length(), 1);
        assert_eq!(Prefix::INT16.prefix_length(), 2);
        assert_eq!(Prefix::INT32.prefix_length(), 4);
    }

    #[test]
    fn test_is_length_counted() {
        assert!(!Prefix::INT8.is_length_counted());
        assert!((Prefix::INT8 | Prefix::WITH_PREFIX).is_length_counted());
        assert!((Prefix::INT16 | Prefix::WITH_PREFIX).is_length_counted());
    }

    #[test]
    fn test_bitwise_operations() {
        let combined = Prefix::INT16 | Prefix::WITH_PREFIX;
        assert_eq!(combined.prefix_length(), 2);
        assert!(combined.is_length_counted());

        let masked = combined & Prefix::from_bits(0b0111);
        assert_eq!(masked, Prefix::INT16);
    }
}
