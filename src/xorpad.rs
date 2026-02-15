// Xorpad finding and verification

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::crypto::{sha256, xor_bytes};
use crate::ncsd::*;

pub fn find_xorpad(title_id: &str, crc32: u32, tmpdir: &Path) -> Option<PathBuf> {
    let expected_name = format!("{}.{:08x}.Main.exheader.xorpad", title_id, crc32);
    let legacy_name = format!("{}.Main.exheader.xorpad", title_id);
    let xorpad_dir = Path::new("xorpads");
    if !xorpad_dir.exists() {
        return None;
    }
    let patterns = [
        "xorpads/*.[xX][oO][rR][pP][aA][dD]",
        "xorpads/*.[zZ][iI][pP]",
    ];
    let mut xorpads = Vec::new();
    for pattern in &patterns {
        if let Ok(paths) = glob::glob(pattern) {
            for path in paths.flatten() {
                xorpads.push(path);
            }
        }
    }
    for xorpad in &xorpads {
        if zip::ZipArchive::new(File::open(xorpad).ok()?).is_ok() {
            if let Ok(mut archive) = zip::ZipArchive::new(File::open(xorpad).ok()?) {
                for i in 0..archive.len() {
                    if let Ok(entry) = archive.by_index(i) {
                        let entry_name = entry
                            .enclosed_name()
                            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));
                        if let Some(basename) = entry_name {
                            if basename.to_lowercase() == expected_name.to_lowercase() {
                                drop(entry);
                                if let Ok(mut archive2) =
                                    zip::ZipArchive::new(File::open(xorpad).ok()?)
                                {
                                    if let Ok(mut entry2) = archive2.by_index(i) {
                                        let out_path = tmpdir.join(&expected_name);
                                        if let Ok(mut out_file) = File::create(&out_path) {
                                            let _ = io::copy(&mut entry2, &mut out_file);
                                            return Some(out_path);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let basename = xorpad
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if basename.to_lowercase() == expected_name.to_lowercase()
                || basename.to_lowercase() == legacy_name.to_lowercase()
            {
                return Some(xorpad.clone());
            }
        }
    }
    None
}

pub fn verify_xorpad<R: Read + Seek>(fh: &mut R, xorpad_file: Option<&Path>) -> io::Result<bool> {
    let mut offset: u64 = 0;
    fh.seek(SeekFrom::Start(0x100))?;
    let mut magic = [0u8; 4];
    fh.read_exact(&mut magic)?;
    if &magic == b"NCSD" {
        let header = read_ncsd_header(fh)?;
        for entry in &header.offset_size_table {
            if entry.offset != 0 {
                offset = entry.offset as u64 * MEDIA_UNIT_SIZE;
                break;
            }
        }
    }
    fh.seek(SeekFrom::Start(offset + 0x200))?;
    let mut exheader = vec![0u8; 0x400];
    fh.read_exact(&mut exheader)?;
    if let Some(xp_path) = xorpad_file {
        let mut xp_data = vec![0u8; 0x400];
        File::open(xp_path)?.read_exact(&mut xp_data)?;
        exheader = xor_bytes(&exheader, &xp_data);
    }
    fh.seek(SeekFrom::Start(offset + 0x160))?;
    let mut orig_sha256 = [0u8; 0x20];
    fh.read_exact(&mut orig_sha256)?;
    Ok(sha256(&exheader) == orig_sha256)
}
