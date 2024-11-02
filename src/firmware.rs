use anyhow::{ensure, Result};
use std::path::Path;
use deku::prelude::*;

use crate::structures::itoc::ItocEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firmware(pub Vec<u8>);

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

    pub fn slice(&self, offset: usize, size: usize) -> FirmwareStructure<&[u8]> {
        FirmwareStructure(offset, &self[offset..][..size])
    }

    pub fn slice_ptr(&self, offset: usize, size: usize) -> FirmwareStructure<usize> {
        FirmwareStructure(offset, size)
    }

    pub fn read_itoc(&self) -> Result<Vec<FirmwareStructure<ItocEntry>>> {
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
pub struct FirmwareStructure<T>(pub usize, pub T);

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
        firmware[self.0..self.0+value.len()].copy_from_slice(value);
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