use deku::ctx::{BitSize, Endian};
use deku::prelude::*;

use crate::firmware::FirmwareStructure;

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(
    id_type = "u8",
    endian = "big",
    bits = "8",
    ctx = "_ctx_endian: Endian, _ctx_bitsize: BitSize"
)]
pub enum ItocEntryType {
    #[deku(id = 0x02)]
    PciCode,

    #[deku(id = 0x03)]
    MainCode,

    #[deku(id = 0x04)]
    PcieLinkCode,

    #[deku(id = 0x05)]
    IronPrepCode,

    #[deku(id = 0x06)]
    PostIronBootCode,

    #[deku(id = 0x07)]
    UpgradeCode,

    #[deku(id = 0x8)]
    HwBootCfg,

    #[deku(id = 0x9)]
    HwMainCfg,

    #[deku(id = 0x0a)]
    PhyUcCode,

    #[deku(id = 0x0b)]
    PhyUcConsts,

    #[deku(id = 0x0c)]
    PciePhyUcCode,

    #[deku(id = 0x10)]
    ImageInfo,

    #[deku(id = 0x11)]
    FwBootCfg,

    #[deku(id = 0x12)]
    FwMainCfg,

    #[deku(id = 0x18)]
    RomCode,

    #[deku(id = 0x20)]
    ResetInfo,

    #[deku(id = 0x30)]
    DbgFwIni,

    #[deku(id = 0x32)]
    DbgFwParams,

    #[deku(id = 0xa0)]
    ImageSignature256,

    #[deku(id = 0xa1)]
    PublicKeys2048,

    #[deku(id = 0xa2)]
    ForbiddenVersions,

    #[deku(id = 0xa3)]
    ImageSignature512,

    #[deku(id = 0xa4)]
    PublicKeys4096,

    #[deku(id = 0xe9)]
    CrDumpMaskData,

    #[deku(id = 0xeb)]
    ProgrammableHwFw,

    #[deku(id_pat = "_")]
    Unknown(u8),
}

impl std::fmt::Display for ItocEntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::PciCode => write!(f, "PCI_CODE"),
            Self::MainCode => write!(f, "MAIN_CODE"),
            Self::PcieLinkCode => write!(f, "PCIE_LINK_CODE"),
            Self::IronPrepCode => write!(f, "IRON_PREP_CODE"),
            Self::PostIronBootCode => write!(f, "POST_IRON_BOOT_CODE"),
            Self::UpgradeCode => write!(f, "UPGRADE_CODE"),
            Self::HwBootCfg => write!(f, "HW_BOOT_CFG"),
            Self::HwMainCfg => write!(f, "HW_MAIN_CFG"),
            Self::PhyUcCode => write!(f, "PHY_UC_CODE"),
            Self::PhyUcConsts => write!(f, "PHY_UC_CONSTS"),
            Self::PciePhyUcCode => write!(f, "PCIE_PHY_UC_CODE"),
            Self::ImageInfo => write!(f, "IMAGE_INFO"),
            Self::FwBootCfg => write!(f, "FW_BOOT_CFG"),
            Self::FwMainCfg => write!(f, "FW_MAIN_CFG"),
            Self::RomCode => write!(f, "ROM_CODE"),
            Self::ResetInfo => write!(f, "RESET_INFO"),
            Self::DbgFwIni => write!(f, "DBG_FW_INI"),
            Self::DbgFwParams => write!(f, "DBG_FW_PARAMS"),
            Self::ImageSignature256 => write!(f, "IMAGE_SIGNATURE_256"),
            Self::PublicKeys2048 => write!(f, "PUBLIC_KEYS_2048"),
            Self::ForbiddenVersions => write!(f, "FORBIDDEN_VERSIONS"),
            Self::ImageSignature512 => write!(f, "IMAGE_SIGNATURE_512"),
            Self::PublicKeys4096 => write!(f, "PUBLIC_KEYS_4096"),
            Self::CrDumpMaskData => write!(f, "CRDUMP_MASK_DATA"),
            Self::ProgrammableHwFw => write!(f, "PROGRAMMABLE_HW_FW"),
            ItocEntryType::Unknown(id) => write!(f, "UNKNOWN_SECTION_{:02x}", id),
        }
    }
}

impl ItocEntryType {
    pub fn is_code(&self) -> bool {
        matches!(
            *self,
            ItocEntryType::PciCode
                | ItocEntryType::MainCode
                | ItocEntryType::PcieLinkCode
                | ItocEntryType::IronPrepCode
                | ItocEntryType::PostIronBootCode
                | ItocEntryType::UpgradeCode
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct ItocEntry {
    #[deku(bits = "8")]
    pub entry_type: ItocEntryType,
    #[deku(bits = "24")]
    pub size: usize,

    #[deku(bits = "1")]
    pub zipped_image: bool,
    #[deku(bits = "1")]
    pub cache_line_crc: bool,
    #[deku(bits = "30")]
    pub load_address: u32, // param0

    #[deku(bits = "32")]
    pub entry_point: u32, // param1

    #[deku(pad_bytes_before = "4", pad_bits_before = "16", bits = "16")]
    pub version: u16,

    #[deku(bits = "32")]
    pub flash_addr: usize,

    #[deku(bits = "1")]
    pub encrypted_section: bool,

    #[deku(pad_bits_before = "7", bits = "8")]
    pub crc: u8,
    #[deku(bits = "16")]
    pub section_crc: u16,

    #[deku(
        pad_bits_before = "16",
        bits = "16",
        update = "self.calc_itoc_entry_crc()"
    )]
    pub itoc_entry_crc: u16,
}

impl ItocEntry {
    pub fn calc_itoc_entry_crc(&self) -> u16 {
        let bytes = self.to_bytes().unwrap();
        crate::crc::calc_crc16(0x0000, &bytes[..0x1e])
    }

    pub fn content(&self) -> FirmwareStructure<usize> {
        FirmwareStructure(self.flash_addr, self.size)
    }
}
