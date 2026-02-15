// CIA generation (ticket, TMD, meta, assembly)

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};

use crate::constants::*;
use crate::crypto::{align_up, encrypt_title_key, sha256};
use crate::ncsd::*;

pub struct ContentInfo {
    pub id: u32,
    pub index: u16,
    pub size: u64,
    pub hash: [u8; 32],
}

fn generate_ticket(title_id: &[u8; 8], save_data_size: u64) -> Vec<u8> {
    let title_key = [0u8; 16];
    let encrypted_title_key = encrypt_title_key(&title_key, title_id);

    // Signature: sig_type (4 BE) + signature (256) + padding (0x3C)
    let sig_size = 4 + 256 + 0x3C; // = 0x140
    // Ticket struct: 0x210 bytes
    let ticket_struct_size = 0x210;
    let total = sig_size + ticket_struct_size; // = 0x350

    let mut buf = vec![0u8; total];

    // Sig type: RSA_2048_SHA256 = 0x00010004
    buf[0] = 0x00;
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 0x04;

    let t = &mut buf[sig_size..]; // ticket struct starts here

    // Issuer (0x00, 64 bytes)
    t[0x00..0x40].copy_from_slice(&TICKET_ISSUER);
    // TicketFormatVersion (0x7C) = 1
    t[0x7C] = 1;
    // EncryptedTitleKey (0x7F, 16 bytes)
    t[0x7F..0x8F].copy_from_slice(&encrypted_title_key);
    // TitleID (0x9C, 8 bytes)
    t[0x9C..0xA4].copy_from_slice(title_id);
    // Static data at 0x164 (0x30 bytes) - dev mode
    #[rustfmt::skip]
    let dev_static_data: [u8; 0x30] = [
        0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0xAC,
        0x00, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x84,
        0x00, 0x00, 0x00, 0x84, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    t[0x164..0x194].copy_from_slice(&dev_static_data);

    let _ = save_data_size;

    buf
}

fn generate_tmd(
    title_id: &[u8; 8],
    save_data_size: u64,
    contents: &[ContentInfo],
) -> Vec<u8> {
    let content_count = contents.len() as u16;

    let sig_size: usize = 4 + 256 + 0x3C; // 0x140
    let tmd_header_size: usize = 0xC4; // includes issuer
    let info_records_size: usize = 0x24 * 0x40; // 0x900
    let content_chunk_size: usize = 0x30 * contents.len();
    let total = sig_size + tmd_header_size + info_records_size + content_chunk_size;

    let mut buf = vec![0u8; total];

    // Sig type: RSA_2048_SHA256
    buf[0] = 0x00;
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 0x04;

    let h = &mut buf[sig_size..]; // TMD header starts here

    // Issuer (0x00, 64 bytes)
    h[0x00..0x40].copy_from_slice(&TMD_ISSUER);
    // version (0x40) = 1
    h[0x40] = 1;
    // title_id (0x4C, 8 bytes)
    h[0x4C..0x54].copy_from_slice(title_id);
    // title_type (0x54, 4 bytes BE) = 0x40 (CTR)
    h[0x57] = 0x40;
    // save_data_size (0x5A, 4 bytes LE)
    let sds = (save_data_size * 1024) as u32;
    h[0x5A] = (sds & 0xFF) as u8;
    h[0x5B] = ((sds >> 8) & 0xFF) as u8;
    h[0x5C] = ((sds >> 16) & 0xFF) as u8;
    h[0x5D] = ((sds >> 24) & 0xFF) as u8;
    // content_count (0x9E, 2 bytes BE)
    h[0x9E] = (content_count >> 8) as u8;
    h[0x9F] = (content_count & 0xFF) as u8;

    // Content info records start after TMD header (at offset 0xC4)
    let info_records_start = 0xC4;

    // Content chunks start after info records
    let chunks_start = info_records_start + info_records_size;

    // Build content chunks
    for (i, content) in contents.iter().enumerate() {
        let chunk_offset = chunks_start + i * 0x30;
        // content_id (4 bytes BE)
        h[chunk_offset] = ((content.id >> 24) & 0xFF) as u8;
        h[chunk_offset + 1] = ((content.id >> 16) & 0xFF) as u8;
        h[chunk_offset + 2] = ((content.id >> 8) & 0xFF) as u8;
        h[chunk_offset + 3] = (content.id & 0xFF) as u8;
        // content_index (2 bytes BE)
        h[chunk_offset + 4] = (content.index >> 8) as u8;
        h[chunk_offset + 5] = (content.index & 0xFF) as u8;
        // content_type (2 bytes BE) = 0
        // content_size (8 bytes BE)
        let size = content.size;
        for j in 0..8 {
            h[chunk_offset + 8 + j] = ((size >> ((7 - j) * 8)) & 0xFF) as u8;
        }
        // sha_256_hash (32 bytes)
        h[chunk_offset + 0x10..chunk_offset + 0x30].copy_from_slice(&content.hash);
    }

    // Fill first info record: compute chunks hash first to avoid borrow issues
    let chunks_hash = sha256(&h[chunks_start..chunks_start + content_chunk_size].to_vec());
    // content_command_count (2 bytes BE) at info_records_start + 2
    h[info_records_start + 2] = (content_count >> 8) as u8;
    h[info_records_start + 3] = (content_count & 0xFF) as u8;
    // SHA256 of content chunks at info_records_start + 4
    h[info_records_start + 4..info_records_start + 0x24].copy_from_slice(&chunks_hash);

    // SHA256 of all info records -> store in TMD header at 0xA4
    let info_hash = sha256(&h[info_records_start..info_records_start + info_records_size].to_vec());
    h[0xA4..0xA4 + 32].copy_from_slice(&info_hash);

    buf
}

fn generate_meta(cxi_path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut f = BufReader::new(File::open(cxi_path)?);
    let ncch = read_ncch_header(&mut f, 0)?;

    // Check if this is a CXI (has exheader) not a CFA
    if ncch.exhdr_size == 0 {
        return Ok(None);
    }
    // Check flags[5] bit 1 for CFA
    if ncch.flags[5] & 0x02 != 0 {
        return Ok(None);
    }

    // Read extended header for DependList and CoreVersion
    f.seek(SeekFrom::Start(0x200 + 0x40))?;
    let mut depend_list = vec![0u8; 0x180];
    f.read_exact(&mut depend_list)?;

    f.seek(SeekFrom::Start(0x200 + 0x208))?;
    let mut core_version = [0u8; 4];
    f.read_exact(&mut core_version)?;

    // Read icon from ExeFS
    let exefs_offset = ncch.exefs_offset as u64 * MEDIA_UNIT_SIZE;
    if exefs_offset == 0 {
        return Ok(None);
    }

    f.seek(SeekFrom::Start(exefs_offset))?;
    let mut icon_data: Option<Vec<u8>> = None;
    for _ in 0..10 {
        let mut name = [0u8; 8];
        f.read_exact(&mut name)?;
        let offset = f.read_u32::<LittleEndian>()?;
        let size = f.read_u32::<LittleEndian>()?;
        if &name[..4] == b"icon" && size > 0 {
            let saved_pos = f.stream_position()?;
            f.seek(SeekFrom::Start(exefs_offset + 0x200 + offset as u64))?;
            let mut data = vec![0u8; size as usize];
            f.read_exact(&mut data)?;
            icon_data = Some(data);
            f.seek(SeekFrom::Start(saved_pos))?;
            break;
        }
    }

    let icon = match icon_data {
        Some(d) => d,
        None => return Ok(None),
    };

    // Build meta section: META_STRUCT (0x400) + icon
    let mut meta = vec![0u8; 0x400 + icon.len()];
    meta[0x00..0x180].copy_from_slice(&depend_list);
    meta[0x180..0x184].copy_from_slice(&core_version);
    meta[0x400..].copy_from_slice(&icon);

    Ok(Some(meta))
}

pub fn build_cia(
    contents: &[PathBuf],
    output_path: &Path,
    save_data_size: u64,
    title_id: &[u8; 8],
    verbose: bool,
) -> io::Result<bool> {
    if verbose {
        println!(
            "Building CIA: {} contents, save_data_size={}",
            contents.len(),
            save_data_size
        );
    }

    // Compute content info (hash + padded size)
    let mut content_infos = Vec::new();
    let mut total_content_size: u64 = 0;

    for (i, content_path) in contents.iter().enumerate() {
        let file_size = fs::metadata(content_path)?.len();
        let padded_size = align_up(file_size, 16);

        // SHA256 of the padded content
        let mut hasher = Sha256::new();
        let mut f = BufReader::with_capacity(256 * 1024, File::open(content_path)?);
        let mut buf = vec![0u8; 256 * 1024];
        let mut remaining = file_size;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            f.read_exact(&mut buf[..to_read])?;
            hasher.update(&buf[..to_read]);
            remaining -= to_read as u64;
        }
        let pad_bytes = (padded_size - file_size) as usize;
        if pad_bytes > 0 {
            hasher.update(&vec![0u8; pad_bytes]);
        }
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

        content_infos.push(ContentInfo {
            id: i as u32,
            index: i as u16,
            size: padded_size,
            hash,
        });

        total_content_size += padded_size;
    }

    // Generate sections
    let cert_chain = &CIA_CERT_CHAIN;
    let ticket = generate_ticket(title_id, save_data_size);
    let tmd = generate_tmd(title_id, save_data_size, &content_infos);

    // Generate meta (only if content0 is CXI)
    let meta = if !contents.is_empty() {
        generate_meta(&contents[0])?.unwrap_or_default()
    } else {
        Vec::new()
    };

    let cert_size = cert_chain.len() as u64;
    let tik_size = ticket.len() as u64;
    let tmd_size = tmd.len() as u64;
    let meta_size = meta.len() as u64;

    // Build content index bitmap
    let mut content_index = [0u8; 0x2000];
    for info in &content_infos {
        let idx = info.index as usize;
        let byte_idx = idx / 8;
        let bit_idx = 7 - (idx % 8);
        if byte_idx < content_index.len() {
            content_index[byte_idx] |= 1 << bit_idx;
        }
    }

    // Write CIA file
    let mut out = File::create(output_path)?;

    // Header
    out.write_u32::<LittleEndian>(CIA_HEADER_SIZE)?;
    out.write_u16::<LittleEndian>(0)?; // type
    out.write_u16::<LittleEndian>(0)?; // version
    out.write_u32::<LittleEndian>(cert_size as u32)?;
    out.write_u32::<LittleEndian>(tik_size as u32)?;
    out.write_u32::<LittleEndian>(tmd_size as u32)?;
    out.write_u32::<LittleEndian>(meta_size as u32)?;
    out.write_u64::<LittleEndian>(total_content_size)?;
    out.write_all(&content_index)?;

    // Pad to 0x40
    let pos = CIA_HEADER_SIZE as u64;
    let padded = align_up(pos, CIA_ALIGN);
    if padded > pos {
        out.write_all(&vec![0u8; (padded - pos) as usize])?;
    }

    // Certificate chain
    out.write_all(cert_chain)?;
    let pos = padded + cert_size;
    let padded = align_up(pos, CIA_ALIGN);
    if padded > pos {
        out.write_all(&vec![0u8; (padded - pos) as usize])?;
    }

    // Ticket
    out.write_all(&ticket)?;
    let pos = padded + tik_size;
    let padded = align_up(pos, CIA_ALIGN);
    if padded > pos {
        out.write_all(&vec![0u8; (padded - pos) as usize])?;
    }

    // TMD
    out.write_all(&tmd)?;
    let pos = padded + tmd_size;
    let padded = align_up(pos, CIA_ALIGN);
    if padded > pos {
        out.write_all(&vec![0u8; (padded - pos) as usize])?;
    }

    // Content
    for (i, content_path) in contents.iter().enumerate() {
        let file_size = fs::metadata(content_path)?.len();
        let padded_size = content_infos[i].size;

        let mut f = BufReader::with_capacity(256 * 1024, File::open(content_path)?);
        let mut buf = vec![0u8; 256 * 1024];
        let mut remaining = file_size;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            f.read_exact(&mut buf[..to_read])?;
            out.write_all(&buf[..to_read])?;
            remaining -= to_read as u64;
        }
        let pad = (padded_size - file_size) as usize;
        if pad > 0 {
            out.write_all(&vec![0u8; pad])?;
        }
    }

    // Pad after content + Meta
    if meta_size > 0 {
        let pos = out.stream_position()?;
        let padded = align_up(pos, CIA_ALIGN);
        if padded > pos {
            out.write_all(&vec![0u8; (padded - pos) as usize])?;
        }
        out.write_all(&meta)?;
    }

    if verbose {
        println!("CIA written to {}", output_path.display());
    }

    Ok(true)
}
