use std::fmt::Debug;

pub trait VarIntTarget: Debug + Copy + Sized + PartialEq + Eq + PartialOrd + Ord {
    type Signed: SignedVarIntTarget<Unsigned = Self>;

    const MAX_VARINT_BYTES: usize;

    const MAX_LAST_VARINT_BYTE: u8;

    fn decode_varint(buf: &[u8]) -> Result<(Self, usize), crate::error::DecodeError>;

    fn encode_varint(self, buf: &mut [u8]) -> usize;

    fn cast_u32(num: u32) -> Self;

    fn cast_u64(num: u64) -> Self;

    fn num_to_scalar_stage1(self) -> u64;

    fn num_to_vector_stage1(self) -> [u8; 16];

    fn scalar_to_num(x: u64) -> Self;

    fn vector_to_num(res: [u8; 16]) -> Self;

    fn zigzag(from: Self::Signed) -> Self;

    fn unzigzag(self) -> Self::Signed;
}

pub trait SignedVarIntTarget: Debug + Copy + Sized + PartialEq + Eq + PartialOrd + Ord {
    type Unsigned: VarIntTarget<Signed = Self>;

    #[inline(always)]
    fn zigzag(from: Self) -> Self::Unsigned {
        Self::Unsigned::zigzag(from)
    }

    #[inline(always)]
    fn unzigzag(from: Self::Unsigned) -> Self {
        Self::Unsigned::unzigzag(from)
    }
}

impl SignedVarIntTarget for i8 {
    type Unsigned = u8;
}

impl SignedVarIntTarget for i16 {
    type Unsigned = u16;
}

impl SignedVarIntTarget for i32 {
    type Unsigned = u32;
}

impl SignedVarIntTarget for i64 {
    type Unsigned = u64;
}

impl VarIntTarget for u8 {
    type Signed = i8;
    const MAX_VARINT_BYTES: usize = 2;
    const MAX_LAST_VARINT_BYTE: u8 = 0b00000001;

    #[inline(always)]
    fn decode_varint(buf: &[u8]) -> Result<(Self, usize), crate::error::DecodeError> {
        if buf.is_empty() {
            return Err(crate::error::DecodeError::UnexpectedEof);
        }

        let first = buf[0];
        if first < 0x80 {
            return Ok((first, 1));
        }

        if buf.len() < 2 {
            return Err(crate::error::DecodeError::UnexpectedEof);
        }

        let second = buf[1];
        if second >= 0x80 {
            return Err(crate::error::DecodeError::InvalidVarint);
        }

        let result = (first & 0x7F) | ((second & 0x7F) << 7);
        Ok((result, 2))
    }

    #[inline(always)]
    fn encode_varint(self, buf: &mut [u8]) -> usize {
        if self < 0x80 {
            buf[0] = self;
            return 1;
        }
        buf[0] = self | 0x80;
        buf[1] = self >> 7;
        2
    }

    #[inline(always)]
    fn cast_u32(num: u32) -> Self {
        num as u8
    }

    #[inline(always)]
    fn cast_u64(num: u64) -> Self {
        num as u8
    }

    #[inline(always)]
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    fn num_to_scalar_stage1(self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_pdep_u64;

        let x = self as u64;
        unsafe { _pdep_u64(x, 0x000000000000017f) }
    }

    #[inline(always)]
    #[cfg(not(all(target_arch = "x86_64", target_feature = "bmi2")))]
    fn num_to_scalar_stage1(self) -> u64 {
        let x = self as u64;
        (x & 0x000000000000007f) | ((x & 0x0000000000000080) << 1)
    }

    #[inline(always)]
    fn num_to_vector_stage1(self) -> [u8; 16] {
        let mut res = [0u8; 16];
        let stage1 = self.num_to_scalar_stage1();
        res[0..8].copy_from_slice(&stage1.to_le_bytes());
        res
    }

    #[inline(always)]
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    fn scalar_to_num(x: u64) -> Self {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_pext_u64;

        unsafe { _pext_u64(x, 0x000000000000017f) as u8 }
    }

    #[inline(always)]
    #[cfg(not(all(target_arch = "x86_64", target_feature = "bmi2")))]
    fn scalar_to_num(x: u64) -> Self {
        ((x & 0x000000000000007f) | ((x & 0x0000000000000100) >> 1)) as u8
    }

    #[inline(always)]
    fn vector_to_num(stage1: [u8; 16]) -> Self {
        let bytes = u64::from_le_bytes(stage1[0..8].try_into().unwrap());
        Self::scalar_to_num(bytes)
    }

    #[inline(always)]
    fn zigzag(from: i8) -> Self {
        ((from << 1) ^ (from >> 7)) as u8
    }

    #[inline(always)]
    fn unzigzag(self) -> i8 {
        ((self >> 1) as i8) ^ (-((self & 1) as i8))
    }
}

impl VarIntTarget for u16 {
    type Signed = i16;
    const MAX_VARINT_BYTES: usize = 3;
    const MAX_LAST_VARINT_BYTE: u8 = 0b00000011;

    #[inline(always)]
    fn decode_varint(buf: &[u8]) -> Result<(Self, usize), crate::error::DecodeError> {
        if buf.is_empty() {
            return Err(crate::error::DecodeError::UnexpectedEof);
        }

        let first = buf[0];
        if first < 0x80 {
            return Ok((first as u16, 1));
        }

        let mut result = 0u16;
        let mut shift = 0;

        for (i, &byte) in buf.iter().enumerate().take(3) {
            result |= ((byte & 0x7F) as u16) << shift;

            if byte < 0x80 {
                return Ok((result, i + 1));
            }

            shift += 7;
        }

        if buf.len() < 3 {
            Err(crate::error::DecodeError::UnexpectedEof)
        } else {
            Err(crate::error::DecodeError::InvalidVarint)
        }
    }

    #[inline(always)]
    fn encode_varint(self, buf: &mut [u8]) -> usize {
        if self < 0x80 {
            buf[0] = self as u8;
            return 1;
        }

        let mut n = self as u32;
        let mut len = 0;
        while n >= 0x80 {
            buf[len] = (n as u8) | 0x80;
            n >>= 7;
            len += 1;
        }
        buf[len] = n as u8;
        len + 1
    }

    #[inline(always)]
    fn cast_u32(num: u32) -> Self {
        num as u16
    }

    #[inline(always)]
    fn cast_u64(num: u64) -> Self {
        num as u16
    }

    #[inline(always)]
    fn num_to_scalar_stage1(self) -> u64 {
        let x = self as u64;
        (x & 0x7f) | ((x & 0x3f80) << 1) | ((x & 0xc000) << 2)
    }

    #[inline(always)]
    fn num_to_vector_stage1(self) -> [u8; 16] {
        let mut res = [0u8; 16];
        let stage1 = self.num_to_scalar_stage1();
        res[0..8].copy_from_slice(&stage1.to_le_bytes());
        res
    }

    #[inline(always)]
    fn scalar_to_num(x: u64) -> Self {
        ((x & 0x000000000000007f)
            | ((x & 0x0000000000030000) >> 2)
            | ((x & 0x0000000000007f00) >> 1)) as u16
    }

    #[inline(always)]
    fn vector_to_num(stage1: [u8; 16]) -> Self {
        let bytes = u64::from_le_bytes(stage1[0..8].try_into().unwrap());
        Self::scalar_to_num(bytes)
    }

    #[inline(always)]
    fn zigzag(from: i16) -> Self {
        ((from << 1) ^ (from >> 15)) as u16
    }

    #[inline(always)]
    fn unzigzag(self) -> i16 {
        ((self >> 1) as i16) ^ (-((self & 1) as i16))
    }
}

impl VarIntTarget for u32 {
    type Signed = i32;
    const MAX_VARINT_BYTES: usize = 5;
    const MAX_LAST_VARINT_BYTE: u8 = 0b00001111;

    #[inline(always)]
    fn decode_varint(buf: &[u8]) -> Result<(Self, usize), crate::error::DecodeError> {
        if buf.is_empty() {
            return Err(crate::error::DecodeError::UnexpectedEof);
        }

        let first = buf[0];
        if first < 0x80 {
            return Ok((first as u32, 1));
        }

        let mut result = 0u32;
        let mut shift = 0;

        for (i, &byte) in buf.iter().enumerate().take(5) {
            if shift >= 32 {
                return Err(crate::error::DecodeError::InvalidVarint);
            }

            result |= ((byte & 0x7F) as u32) << shift;

            if byte < 0x80 {
                return Ok((result, i + 1));
            }

            shift += 7;
        }

        if buf.len() < 5 {
            Err(crate::error::DecodeError::UnexpectedEof)
        } else {
            Err(crate::error::DecodeError::InvalidVarint)
        }
    }

    #[inline(always)]
    fn encode_varint(self, buf: &mut [u8]) -> usize {
        if self < 0x80 {
            buf[0] = self as u8;
            return 1;
        }

        let mut n = self;
        let mut len = 0;
        while n >= 0x80 {
            buf[len] = (n as u8) | 0x80;
            n >>= 7;
            len += 1;
        }
        buf[len] = n as u8;
        len + 1
    }

    #[inline(always)]
    fn cast_u32(num: u32) -> Self {
        num
    }

    #[inline(always)]
    fn cast_u64(num: u64) -> Self {
        num as u32
    }

    #[inline(always)]
    fn num_to_scalar_stage1(self) -> u64 {
        let x = self as u64;
        (x & 0x7f)
            | ((x & 0x3f80) << 1)
            | ((x & 0x1fc000) << 2)
            | ((x & 0xfe00000) << 3)
            | ((x & 0xf0000000) << 4)
    }

    #[inline(always)]
    fn num_to_vector_stage1(self) -> [u8; 16] {
        let mut res = [0u8; 16];
        let stage1 = self.num_to_scalar_stage1();
        res[0..8].copy_from_slice(&stage1.to_le_bytes());
        res
    }

    #[inline(always)]
    fn scalar_to_num(x: u64) -> Self {
        ((x & 0x000000000000007f)
            | ((x & 0x0000000f00000000) >> 4)
            | ((x & 0x000000007f000000) >> 3)
            | ((x & 0x00000000007f0000) >> 2)
            | ((x & 0x0000000000007f00) >> 1)) as u32
    }

    #[inline(always)]
    fn vector_to_num(stage1: [u8; 16]) -> Self {
        let bytes = u64::from_le_bytes(stage1[0..8].try_into().unwrap());
        Self::scalar_to_num(bytes)
    }

    #[inline(always)]
    fn zigzag(from: i32) -> Self {
        ((from << 1) ^ (from >> 31)) as u32
    }

    #[inline(always)]
    fn unzigzag(self) -> i32 {
        ((self >> 1) as i32) ^ (-((self & 1) as i32))
    }
}

impl VarIntTarget for u64 {
    type Signed = i64;
    const MAX_VARINT_BYTES: usize = 10;
    const MAX_LAST_VARINT_BYTE: u8 = 0b00000001;

    #[inline(always)]
    fn decode_varint(buf: &[u8]) -> Result<(Self, usize), crate::error::DecodeError> {
        if buf.is_empty() {
            return Err(crate::error::DecodeError::UnexpectedEof);
        }

        let first = buf[0];
        if first < 0x80 {
            return Ok((first as u64, 1));
        }

        let mut result = 0u64;
        let mut shift = 0;

        for (i, &byte) in buf.iter().enumerate().take(10) {
            if shift >= 64 {
                return Err(crate::error::DecodeError::InvalidVarint);
            }

            result |= ((byte & 0x7F) as u64) << shift;

            if byte < 0x80 {
                return Ok((result, i + 1));
            }

            shift += 7;
        }

        if buf.len() < 10 {
            Err(crate::error::DecodeError::UnexpectedEof)
        } else {
            Err(crate::error::DecodeError::InvalidVarint)
        }
    }

    #[inline(always)]
    fn encode_varint(self, buf: &mut [u8]) -> usize {
        if self < 0x80 {
            buf[0] = self as u8;
            return 1;
        }

        let mut n = self;
        let mut len = 0;
        while n >= 0x80 {
            buf[len] = (n as u8) | 0x80;
            n >>= 7;
            len += 1;
        }
        buf[len] = n as u8;
        len + 1
    }

    #[inline(always)]
    fn cast_u32(num: u32) -> Self {
        num as u64
    }

    #[inline(always)]
    fn cast_u64(num: u64) -> Self {
        num
    }

    #[inline(always)]
    fn num_to_scalar_stage1(self) -> u64 {
        panic!("u64 should use vector stage1")
    }

    #[inline(always)]
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    fn num_to_vector_stage1(self) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_pdep_u64;

        let mut res = [0u64; 2];
        let x = self;

        res[0] = unsafe { _pdep_u64(x, 0x7f7f7f7f7f7f7f7f) };
        res[1] = unsafe { _pdep_u64(x >> 56, 0x000000000000017f) };

        unsafe { core::mem::transmute(res) }
    }

    #[inline(always)]
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(target_feature = "bmi2")
    ))]
    fn num_to_vector_stage1(self) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;

        let mut res = [0u64; 2];
        let x = self;

        let b = unsafe { _mm_set1_epi64x(self as i64) };
        let c = unsafe {
            _mm_or_si128(
                _mm_or_si128(
                    _mm_sllv_epi64(
                        _mm_and_si128(b, _mm_set_epi64x(0x00000007f0000000, 0x000003f800000000)),
                        _mm_set_epi64x(4, 5),
                    ),
                    _mm_sllv_epi64(
                        _mm_and_si128(b, _mm_set_epi64x(0x0001fc0000000000, 0x00fe000000000000)),
                        _mm_set_epi64x(6, 7),
                    ),
                ),
                _mm_or_si128(
                    _mm_sllv_epi64(
                        _mm_and_si128(b, _mm_set_epi64x(0x000000000000007f, 0x0000000000003f80)),
                        _mm_set_epi64x(0, 1),
                    ),
                    _mm_sllv_epi64(
                        _mm_and_si128(b, _mm_set_epi64x(0x00000000001fc000, 0x000000000fe00000)),
                        _mm_set_epi64x(2, 3),
                    ),
                ),
            )
        };
        let d = unsafe { _mm_or_si128(c, _mm_bsrli_si128(c, 8)) };

        res[0] = unsafe { _mm_extract_epi64(d, 0) as u64 };
        res[1] = ((x & 0x7f00000000000000) >> 56) | ((x & 0x8000000000000000) >> 55);

        unsafe { core::mem::transmute(res) }
    }

    #[inline(always)]
    #[cfg(not(any(
        target_feature = "avx2",
        all(target_arch = "x86_64", target_feature = "bmi2")
    )))]
    fn num_to_vector_stage1(self) -> [u8; 16] {
        let mut res = [0u64; 2];
        let x = self;

        res[0] = (x & 0x000000000000007f)
            | ((x & 0x0000000000003f80) << 1)
            | ((x & 0x00000000001fc000) << 2)
            | ((x & 0x000000000fe00000) << 3)
            | ((x & 0x00000007f0000000) << 4)
            | ((x & 0x000003f800000000) << 5)
            | ((x & 0x0001fc0000000000) << 6)
            | ((x & 0x00fe000000000000) << 7);
        res[1] = ((x & 0x7f00000000000000) >> 56) | ((x & 0x8000000000000000) >> 55);

        unsafe { core::mem::transmute(res) }
    }

    #[inline(always)]
    fn scalar_to_num(_stage1: u64) -> Self {
        panic!("u64 should use vector_to_num")
    }

    #[inline(always)]
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    fn vector_to_num(res: [u8; 16]) -> Self {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_pext_u64;

        let arr: [u64; 2] = unsafe { core::mem::transmute(res) };

        let x = arr[0];
        let y = arr[1];

        let res = unsafe { _pext_u64(x, 0x7f7f7f7f7f7f7f7f) }
            | (unsafe { _pext_u64(y, 0x000000000000017f) } << 56);

        res
    }

    #[inline(always)]
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(target_feature = "bmi2")
    ))]
    fn vector_to_num(res: [u8; 16]) -> Self {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;

        let pt1 = unsafe {
            let b = core::mem::transmute::<[u8; 16], __m128i>(res);

            let c = _mm_broadcastq_epi64(b);
            let d = _mm_or_si128(
                _mm_or_si128(
                    _mm_srlv_epi64(
                        _mm_and_si128(c, _mm_set_epi64x(0x000000000000007f, 0x7f00000000000000)),
                        _mm_set_epi64x(0, 7),
                    ),
                    _mm_srlv_epi64(
                        _mm_and_si128(c, _mm_set_epi64x(0x007f000000000000, 0x00007f0000000000)),
                        _mm_set_epi64x(6, 5),
                    ),
                ),
                _mm_or_si128(
                    _mm_srlv_epi64(
                        _mm_and_si128(c, _mm_set_epi64x(0x0000007f00000000, 0x000000007f000000)),
                        _mm_set_epi64x(4, 3),
                    ),
                    _mm_srlv_epi64(
                        _mm_and_si128(c, _mm_set_epi64x(0x00000000007f0000, 0x0000000000007f00)),
                        _mm_set_epi64x(2, 1),
                    ),
                ),
            );

            let e = _mm_or_si128(d, _mm_bsrli_si128(d, 8));
            _mm_extract_epi64(e, 0) as u64
        };

        let arr: [u64; 2] = unsafe { core::mem::transmute(res) };

        let y = arr[1];

        pt1 | ((y & 0x0000000000000100) << 55) | ((y & 0x000000000000007f) << 56)
    }

    #[inline(always)]
    #[cfg(not(any(
        target_feature = "avx2",
        all(target_arch = "x86_64", target_feature = "bmi2")
    )))]
    fn vector_to_num(res: [u8; 16]) -> Self {
        let arr: [u64; 2] = unsafe { core::mem::transmute(res) };

        let x = arr[0];
        let y = arr[1];

        (x & 0x000000000000007f)
            | ((x & 0x7f00000000000000) >> 7)
            | ((x & 0x007f000000000000) >> 6)
            | ((x & 0x00007f0000000000) >> 5)
            | ((x & 0x0000007f00000000) >> 4)
            | ((x & 0x000000007f000000) >> 3)
            | ((x & 0x00000000007f0000) >> 2)
            | ((x & 0x0000000000007f00) >> 1)
            | ((y & 0x0000000000000100) << 55)
            | ((y & 0x000000000000007f) << 56)
    }

    #[inline(always)]
    fn zigzag(from: i64) -> Self {
        ((from << 1) ^ (from >> 63)) as u64
    }

    #[inline(always)]
    fn unzigzag(self) -> i64 {
        ((self >> 1) as i64) ^ (-((self & 1) as i64))
    }
}
