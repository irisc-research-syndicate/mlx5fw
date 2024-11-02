use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::{ensure, Context, Result};
use deku::prelude::*;

pub mod crc;
pub mod firmware;
pub mod structures;

use firmware::Firmware;

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
            let content = &firmware[itoc_entry.flash_addr..][..itoc_entry.size];
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

    ensure!(section_content.len() <= itoc_entry.size, "New Section content is too big");

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
