// NCSD/NCCH header parsing structs and readers

use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::crypto::round_up;

pub const MEDIA_UNIT_SIZE: u64 = 0x200;

pub const NCSD_PARTITIONS: [&str; 8] = [
    "Main",
    "Manual",
    "DownloadPlay",
    "Partition4",
    "Partition5",
    "Partition6",
    "Partition7",
    "UpdateData",
];

#[derive(Debug, Clone, Copy)]
pub struct OffsetSize {
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct NcsdHeader {
    pub title_id: [u8; 8],
    pub offset_size_table: [OffsetSize; 8],
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct NcchHeader {
    pub signature: [u8; 0x100],
    pub title_id: [u8; 8],
    pub format_version: u8,
    pub program_id: [u8; 8],
    pub exhdr_hash: [u8; 0x20],
    pub exhdr_size: u32,
    pub flags: [u8; 8],
    pub plain_region_offset: u32,
    pub plain_region_size: u32,
    pub exefs_offset: u32,
    pub exefs_size: u32,
    pub romfs_offset: u32,
    pub romfs_size: u32,
    pub product_code: [u8; 0x10],
}

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum NcchSectionType {
    Exheader = 1,
    Exefs = 2,
    Romfs = 3,
}

pub fn read_ncsd_header<R: Read + Seek>(r: &mut R) -> io::Result<NcsdHeader> {
    r.seek(SeekFrom::Start(0))?;
    let mut sig_magic = [0u8; 0x100 + 4 + 4];
    r.read_exact(&mut sig_magic)?;
    let mut title_id = [0u8; 8];
    r.read_exact(&mut title_id)?;
    let mut pad0 = [0u8; 0x10];
    r.read_exact(&mut pad0)?;
    let mut offset_size_table = [OffsetSize { offset: 0, size: 0 }; 8];
    for entry in &mut offset_size_table {
        entry.offset = r.read_u32::<LittleEndian>()?;
        entry.size = r.read_u32::<LittleEndian>()?;
    }
    Ok(NcsdHeader {
        title_id,
        offset_size_table,
    })
}

pub fn read_ncch_header<R: Read + Seek>(r: &mut R, offset: u64) -> io::Result<NcchHeader> {
    r.seek(SeekFrom::Start(offset))?;
    let mut signature = [0u8; 0x100];
    r.read_exact(&mut signature)?;
    let mut _magic = [0u8; 4];
    r.read_exact(&mut _magic)?;
    let _ncch_size = r.read_u32::<LittleEndian>()?;
    let mut title_id = [0u8; 8];
    r.read_exact(&mut title_id)?;
    let _maker_code = r.read_u16::<LittleEndian>()?;
    let format_version = r.read_u8()?;
    let _format_version2 = r.read_u8()?;
    let _padding0 = r.read_u32::<LittleEndian>()?;
    let mut program_id = [0u8; 8];
    r.read_exact(&mut program_id)?;
    let mut _padding1 = [0u8; 0x10];
    r.read_exact(&mut _padding1)?;
    let mut _logo_hash = [0u8; 0x20];
    r.read_exact(&mut _logo_hash)?;
    let mut product_code = [0u8; 0x10];
    r.read_exact(&mut product_code)?;
    let mut exhdr_hash = [0u8; 0x20];
    r.read_exact(&mut exhdr_hash)?;
    let exhdr_size = r.read_u32::<LittleEndian>()?;
    let _padding2 = r.read_u32::<LittleEndian>()?;
    let mut flags = [0u8; 8];
    r.read_exact(&mut flags)?;
    let plain_region_offset = r.read_u32::<LittleEndian>()?;
    let plain_region_size = r.read_u32::<LittleEndian>()?;
    let _logo_offset = r.read_u32::<LittleEndian>()?;
    let _logo_size = r.read_u32::<LittleEndian>()?;
    let exefs_offset = r.read_u32::<LittleEndian>()?;
    let exefs_size = r.read_u32::<LittleEndian>()?;
    let _exefs_hash_size = r.read_u32::<LittleEndian>()?;
    let _padding4 = r.read_u32::<LittleEndian>()?;
    let romfs_offset = r.read_u32::<LittleEndian>()?;
    let romfs_size = r.read_u32::<LittleEndian>()?;
    Ok(NcchHeader {
        signature,
        title_id,
        format_version,
        program_id,
        exhdr_hash,
        exhdr_size,
        flags,
        plain_region_offset,
        plain_region_size,
        exefs_offset,
        exefs_size,
        romfs_offset,
        romfs_size,
        product_code,
    })
}

pub fn reverse_ctype_array(arr: &[u8; 8]) -> String {
    arr.iter().rev().map(|b| format!("{:02X}", b)).collect()
}

pub fn get_ncch_aes_counter(header: &NcchHeader, section_type: NcchSectionType) -> [u8; 16] {
    let mut counter = [0u8; 16];
    if header.format_version == 2 || header.format_version == 0 {
        for i in 0..8 {
            counter[i] = header.title_id[7 - i];
        }
        counter[8] = section_type as u8;
    } else if header.format_version == 1 {
        let x: u64 = match section_type {
            NcchSectionType::Exheader => 0x200,
            NcchSectionType::Exefs => header.exefs_offset as u64 * MEDIA_UNIT_SIZE,
            NcchSectionType::Romfs => header.romfs_offset as u64 * MEDIA_UNIT_SIZE,
        };
        counter[..8].copy_from_slice(&header.title_id);
        for i in 0..4 {
            counter[12 + i] = ((x >> ((3 - i) * 8)) & 0xFF) as u8;
        }
    }
    counter
}

pub fn parse_ncch_section(header: &NcchHeader, section_type: NcchSectionType) -> Vec<u8> {
    let (_offset, section_size) = match section_type {
        NcchSectionType::Exheader => (0x200u64, header.exhdr_size as u64),
        NcchSectionType::Exefs => (
            header.exefs_offset as u64 * MEDIA_UNIT_SIZE,
            header.exefs_size as u64 * MEDIA_UNIT_SIZE,
        ),
        NcchSectionType::Romfs => (
            header.romfs_offset as u64 * MEDIA_UNIT_SIZE,
            header.romfs_size as u64 * MEDIA_UNIT_SIZE,
        ),
    };
    let counter = get_ncch_aes_counter(header, section_type);
    let key_y: [u8; 16] = header.signature[..16].try_into().unwrap();
    let title_id_val = u64::from_le_bytes(header.program_id);
    let section_mb = round_up(section_size, 1024 * 1024) / (1024 * 1024);
    let section_mb = if section_mb == 0 { 1 } else { section_mb };
    let ncch_flag7 = if header.flags[7] == 0x1 { 1u32 } else { 0u32 };
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&counter);
    data.extend_from_slice(&key_y);
    data.extend_from_slice(&(section_mb as u32).to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&ncch_flag7.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&title_id_val.to_le_bytes());
    data
}
