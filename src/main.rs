use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use anyhow::{ensure, Context, Result};
use deku::prelude::*;
use deku::ctx::{Endian, BitSize};

mod crc;

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type="u8", endian="big", bits="8", ctx="_ctx_endian: Endian, _ctx_bitsize: BitSize")]
enum ItocEntryType {
    #[deku(id=0x02)]
    PciCode,

    #[deku(id=0x03)]
    MainCode,

    #[deku(id=0x04)]
    PcieLinkCode,

    #[deku(id=0x05)]
    IronPrepCode,

    #[deku(id=0x06)]
    PostIronBootCode,

    #[deku(id=0x07)]
    UpgradeCode,

    #[deku(id=0x8)]
    HwBootCfg,

    #[deku(id=0x9)]
    HwMainCfg,

    #[deku(id=0x0a)]
    PhyUcCode,

    #[deku(id=0x0b)]
    PhyUcConsts,

    #[deku(id=0x0c)]
    PciePhyUcCode,

    #[deku(id=0x10)]
    ImageInfo,

    #[deku(id=0x11)]
    FwBootCfg,

    #[deku(id=0x12)]
    FwMainCfg,

    #[deku(id=0x18)]
    RomCode,

    #[deku(id=0x20)]
    ResetInfo,

    #[deku(id=0x30)]
    DbgFwIni,

    #[deku(id=0x32)]
    DbgFwParams,

    #[deku(id=0xa0)]
    ImageSignature256,

    #[deku(id=0xa1)]
    PublicKeys2048,

    #[deku(id=0xa2)]
    ForbiddenVersions,

    #[deku(id=0xa3)]
    ImageSignature512,

    #[deku(id=0xa4)]
    PublicKeys4096,

    #[deku(id=0xe9)]
    CrDumpMaskData,

    #[deku(id=0xeb)]
    ProgrammableHwFw,

    #[deku(id_pat="_")]
    Unknown(u8)
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
        match *self {
            ItocEntryType::PciCode => true,
            ItocEntryType::MainCode => true,
            ItocEntryType::PcieLinkCode => true,
            ItocEntryType::IronPrepCode => true,
            ItocEntryType::PostIronBootCode => true,
            ItocEntryType::UpgradeCode => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firmware(Vec<u8>);

impl std::ops::Deref for Firmware {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Firmware {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Firmware {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self(std::fs::read(path)?))
    }

    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        Ok(std::fs::write(path, &self.0)?)
    }

    pub fn slice<'a>(&'a self, offset: usize, size: usize) -> FirmwareStructure<&'a [u8]> {
        FirmwareStructure(offset, &self[offset..][..size])
    }

    pub fn slice_ptr(&self, offset: usize, size: usize) -> FirmwareStructure<usize> {
        FirmwareStructure(offset, size)
    }

    fn read_itoc(&self) -> Result<Vec<FirmwareStructure<ItocEntry>>> {
        let mut itoc = vec![];

        for offset in (0x4020..).step_by(32) {
            if self[offset..offset+32] == [0xffu8; 32] {
                break;
            }
            itoc.push(FirmwareStructure::read(self, offset)?);
        }

        Ok(itoc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareStructure<T>(usize, T);

impl<T> std::ops::Deref for FirmwareStructure<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl<T> std::ops::DerefMut for FirmwareStructure<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}

impl<T> FirmwareStructure<T> {
    pub fn write_bytes(&self, firmware: &mut Firmware, value: &[u8]) -> Result<()> {
        ensure!(self.0 + value.len() < firmware.len(), "Firmware structure out of bounds");
        firmware[self.0..self.0+value.len()].copy_from_slice(&value);
        Ok(())
    }
}

impl FirmwareStructure<usize> {
    pub fn read_bytes<'a>(&self, firmware: &'a Firmware) -> &'a [u8] {
        &firmware.0[self.0..][..self.1]
    }
}

impl<'a> FirmwareStructure<&'a [u8]> {
    pub fn decode<T: DekuContainerRead<'a>>(&self) -> Result<FirmwareStructure<T>> {
        let inner = T::from_bytes((self.1, 0))?.1;
        Ok(FirmwareStructure(self.0, inner))
    }

}

impl<'a, T: DekuContainerRead<'a>> FirmwareStructure<T> {
    pub fn read(firmware: &'a Firmware, offset: usize) -> Result<Self> {
        let inner = T::from_bytes((&firmware[offset..], 0))?.1;
        Ok(Self(offset, inner))
    }
}

impl<T: DekuContainerWrite> FirmwareStructure<T> {
    pub fn write(&self, firmware: &mut Firmware) -> Result<()> {
        self.write_bytes(firmware, &self.1.to_bytes()?)
    }
}



#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian="big")]
struct ItocEntry {
    #[deku(bits="8")]
    entry_type: ItocEntryType,
    #[deku(bits="24")]
    size: usize,

    #[deku(bits="1")]
    zipped_image: bool,
    #[deku(bits="1")]
    cache_line_crc: bool,
    #[deku(bits="30")]
    load_address: u32,  // param0

    #[deku(bits="32")]
    entry_point: u32,   // param1

    #[deku(pad_bytes_before="4", pad_bits_before="16", bits="16")]
    version: u16,

    #[deku(bits="32")]
    flash_addr: usize,

    #[deku(bits="1")]
    encrypted_section: bool,

    #[deku(pad_bits_before="7", bits="8")]
    crc: u8,
    #[deku(bits="16")]
    section_crc: u16,

    #[deku(pad_bits_before="16", bits="16", update="self.calc_itoc_entry_crc()")]
    itoc_entry_crc: u16,
}

impl ItocEntry {
    pub fn calc_itoc_entry_crc(&self) -> u16 {
        let bytes = self.to_bytes().unwrap();
        crc::calc_crc16(0x0000, &bytes[..0x1e])
    }

    pub fn content(&self) -> FirmwareStructure<usize> {
        FirmwareStructure(self.flash_addr, self.size)
    }
}


fn show_sections(firmware: Firmware) -> Result<()> {
    for (i, itoc_entry) in firmware.read_itoc()?.iter().enumerate() {
        println!("{:2} {:#010x}/{:#010x} {:#010x} {:#010x}: {} {} {}",
            i,
            itoc_entry.flash_addr,
            itoc_entry.size,
            itoc_entry.load_address,
            itoc_entry.entry_point,
            itoc_entry.encrypted_section,
            itoc_entry.cache_line_crc,
            itoc_entry.entry_type,
        );
    }
    Ok(())
}

fn dump_sections(firmware: Firmware, dir: &PathBuf) -> Result<()> {
    std::fs::create_dir(dir).context("Failed to create output directory")?;
    for itoc_entry in firmware.read_itoc()? {
        let content = firmware.slice(itoc_entry.flash_addr, itoc_entry.size);
        std::fs::write(dir.join(format!("{:08x}_{}", itoc_entry.flash_addr, itoc_entry.entry_type)), content.1)?;
    }
    Ok(())
}

fn dump_code(firmware: Firmware, dir: &PathBuf) -> Result<()> {
    std::fs::create_dir(dir).context("Failed to create output directory")?;
    for itoc_entry in firmware.read_itoc()? {
        if itoc_entry.entry_type.is_code() {
            let content = &firmware[(itoc_entry.flash_addr as usize)..][..(itoc_entry.size as usize)];
            let section_path = dir.join(format!("{:08x}_{}", itoc_entry.load_address, itoc_entry.entry_type));
            if itoc_entry.cache_line_crc {
                let mut code = vec![];
                for chunk in content.chunks(0x44) {
                    if chunk.len() == 0x44 {
                        code.extend_from_slice(&chunk[..0x40]);
                    }
                }
                std::fs::write(section_path, code)?;
            } else {
                std::fs::write(section_path, content)?;
            }
        }
    }
    Ok(())
}

fn replace_section(mut firmware: Firmware, args: CliReplaceSection) -> Result<()> {
    let itoc = firmware.read_itoc()?;
    ensure!(args.section_index < itoc.len(), "Section index out of range");

    let mut itoc_entry = itoc[args.section_index].clone();

    let section_content = if itoc_entry.cache_line_crc && !args.no_fix_cache_line_crc {
        let section = std::fs::read(args.section_content).context("Could not read new section content")?;
        let mut content = vec![];
        for cache_line in section.chunks(0x40) {
            let mut cache_line = cache_line.to_vec();
            cache_line.extend_from_slice(&[0x00, 0x00]);
            cache_line.extend_from_slice(&crc::calc_hwcrc(0x0000, &cache_line).to_le_bytes());
            content.extend_from_slice(&cache_line);
        }
        content
    } else {
        std::fs::read(args.section_content).context("Could not read new section content")?
    };

    ensure!(section_content.len() <= itoc_entry.size as usize, "New Section content is too big");

    let section = firmware.slice_ptr(itoc_entry.flash_addr, itoc_entry.size);
    section.write_bytes(&mut firmware, &section_content)?;

    itoc_entry.section_crc = crc::calc_crc16(0x0000, section.read_bytes(&firmware));
    itoc_entry.section_crc = crc::calc_crc16(itoc_entry.section_crc, &[0x00, 0x00]);
    itoc_entry.update()?;

    itoc_entry.write(&mut firmware)?;

    firmware.write(args.output)?;

    Ok(())
}

#[derive(Debug, Clone, Parser)]
struct CliReplaceSection {
    #[arg(long, default_value_t=false)]
    no_update_itoc: bool,
    #[arg(long, default_value_t=false)]
    no_fix_cache_line_crc: bool,

    section_index: usize,
    section_content: PathBuf,
    output: PathBuf,
}

#[derive(Debug, Clone, Subcommand)]
enum CliCommand {
    #[command(name="showsections")]
    ShowSections,
    #[command(name="dumpsections")]
    DumpSections {
        dir: PathBuf
    },
    #[command(name="dumpcode")]
    DumpCode {
        dir: PathBuf
    },
    #[command(name="replacesection")]
    ReplaceSection(CliReplaceSection)
}

#[derive(Debug, Clone, Parser)]
struct CliArgs {
    firmware_path: PathBuf,
    #[command(subcommand)]
    command: CliCommand
}

fn main() -> Result<()> {
    let args = CliArgs::parse();
    let firmware = Firmware::read(args.firmware_path).context("Could not open firmware")?;
    match args.command {
        CliCommand::ShowSections => show_sections(firmware),
        CliCommand::DumpSections { dir } => dump_sections(firmware, &dir),
        CliCommand::DumpCode { dir } => dump_code(firmware, &dir),
        CliCommand::ReplaceSection(args) => replace_section(firmware, args),
    }
}
