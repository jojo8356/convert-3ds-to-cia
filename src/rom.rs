// ROM extraction and CXI fixing

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::{sha256, xor_bytes};
use crate::ncsd::*;

pub fn extract_rom<R: Read + Seek>(fh: &mut R, tmpdir: &Path) -> io::Result<()> {
    let header = read_ncsd_header(fh)?;
    for i in 0..6 {
        let entry = &header.offset_size_table[i];
        if entry.offset != 0 {
            let ext = if i == 0 { ".cxi" } else { ".cfa" };
            let out_path = tmpdir.join(format!("{}{}", i, ext));
            fh.seek(SeekFrom::Start(entry.offset as u64 * MEDIA_UNIT_SIZE))?;
            let mut out_file = File::create(&out_path)?;
            let total_bytes = entry.size as u64 * MEDIA_UNIT_SIZE;
            let mut remaining = total_bytes;
            let mut buf = vec![0u8; 256 * 1024];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
                fh.read_exact(&mut buf[..to_read])?;
                out_file.write_all(&buf[..to_read])?;
                remaining -= to_read as u64;
            }
        }
    }
    Ok(())
}

pub fn fix_cxi(filename: &Path, xorpad_file: Option<&Path>) -> io::Result<u64> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(filename)?;
    f.seek(SeekFrom::Start(0x200))?;
    let mut exheader = vec![0u8; 0x400];
    f.read_exact(&mut exheader)?;
    if let Some(xp_path) = xorpad_file {
        let mut xp_data = vec![0u8; 0x400];
        File::open(xp_path)?.read_exact(&mut xp_data)?;
        exheader = xor_bytes(&exheader, &xp_data);
    }
    exheader[0xD] |= 2;
    let save_data_size = u64::from_le_bytes(exheader[0x1C0..0x1C8].try_into().unwrap()) / 1024;
    let hash = sha256(&exheader);
    f.seek(SeekFrom::Start(0x160))?;
    f.write_all(&hash)?;
    if let Some(xp_path) = xorpad_file {
        let mut xp_data = vec![0u8; 0x400];
        File::open(xp_path)?.read_exact(&mut xp_data)?;
        exheader = xor_bytes(&exheader, &xp_data);
    }
    f.seek(SeekFrom::Start(0x200))?;
    f.write_all(&exheader)?;
    Ok(save_data_size)
}

pub fn get_title_id<R: Read + Seek>(fh: &mut R) -> io::Result<String> {
    let header = read_ncsd_header(fh)?;
    Ok(reverse_ctype_array(&header.title_id))
}

pub fn get_title_id_bytes<R: Read + Seek>(fh: &mut R) -> io::Result<[u8; 8]> {
    let header = read_ncsd_header(fh)?;
    let mut be = header.title_id;
    be.reverse(); // Convert from LE (file) to BE (CIA ticket/TMD)
    Ok(be)
}

pub fn get_ncch_flag7<R: Read + Seek>(fh: &mut R) -> io::Result<u8> {
    let header = read_ncsd_header(fh)?;
    let ncch_offset = header.offset_size_table[0].offset as u64 * MEDIA_UNIT_SIZE;
    let ncch_hdr = read_ncch_header(fh, ncch_offset)?;
    Ok(ncch_hdr.flags[7])
}

pub fn get_ncch_flags<R: Read + Seek>(fh: &mut R) -> io::Result<(u8, u8)> {
    let header = read_ncsd_header(fh)?;
    let ncch_offset = header.offset_size_table[0].offset as u64 * MEDIA_UNIT_SIZE;
    let ncch_hdr = read_ncch_header(fh, ncch_offset)?;
    Ok((ncch_hdr.flags[3], ncch_hdr.flags[7]))
}
