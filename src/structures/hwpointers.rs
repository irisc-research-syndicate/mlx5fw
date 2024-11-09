use deku::ctx::Endian;
use deku::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big", ctx="_ctx_endian: Endian")]
pub struct HwPointer {
    #[deku(bits = "32")]
    pub ptr: usize,
    #[deku(pad_bits_before = "16", bits="16")]
    pub crc: u16
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct HwPointers {
    pub boot_record: HwPointer,
    pub boot2: HwPointer,
    pub toc: HwPointer,
    pub tools: HwPointer,
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Boot2 {
    #[deku(bits = "32")]
    pub header: u32,

    #[deku(bits = "32")]
    pub size: usize,

    #[deku(count = "size")]
    pub data: Vec<u32>,

    #[deku(bits = "32")]
    pub dword0: u32,

    #[deku(bits = "32")]
    pub dword1: u32,
}