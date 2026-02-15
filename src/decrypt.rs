// NCCH decryption using AES-128-CTR with key scrambler
//
// Implements the 3DS key scrambler algorithm to derive normal keys from
// KeyX/KeyY pairs, then decrypts NCCH sections (ExHeader, ExeFS, RomFS)
// in-place.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use sha2::{Digest, Sha256};

use crate::ncsd::*;

// KeyX constants (retail, from boot9)
const KEYX_SLOT_2C: u128 = 0xB98E95CECA3E4D171F76A94DE934C053;
const KEYX_SLOT_25: u128 = 0xCEE7D8AB30C00DAE850EF5E382AC5AF3;
const KEYX_FW93: u128 = 0x82E9C9BEBFB8BDB875ECC0A07D474374;
const KEYX_FW96: u128 = 0x45AD04953992C7C893724A9A7BCE6182;
const SCRAMBLER_C: u128 = 0x1FF9E9AAC5FE0408024591DC5D52768A;

fn rotate_left_128(val: u128, shift: u32) -> u128 {
    (val << shift) | (val >> (128 - shift))
}

fn rotate_right_128(val: u128, shift: u32) -> u128 {
    (val >> shift) | (val << (128 - shift))
}

/// 3DS key scrambler: normal_key = ror128((rol128(KeyX, 2) XOR KeyY) + C, 41)
fn key_scramble(key_x: u128, key_y: u128) -> u128 {
    rotate_right_128(
        (rotate_left_128(key_x, 2) ^ key_y).wrapping_add(SCRAMBLER_C),
        41,
    )
}

fn u128_to_be_bytes(val: u128) -> [u8; 16] {
    val.to_be_bytes()
}

fn increment_counter(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

fn add_to_counter(counter: &mut [u8; 16], blocks: u64) {
    let mut carry = blocks as u128;
    for i in (0..16).rev() {
        carry += counter[i] as u128;
        counter[i] = carry as u8;
        carry >>= 8;
        if carry == 0 {
            break;
        }
    }
}

/// Decrypt data in-place using AES-128-CTR
fn aes_ctr_decrypt(data: &mut [u8], key: &[u8; 16], counter: &mut [u8; 16]) {
    let cipher = Aes128::new(key.into());
    let mut keystream_block = aes::Block::default();

    for chunk in data.chunks_mut(16) {
        keystream_block.copy_from_slice(counter);
        cipher.encrypt_block(&mut keystream_block);
        for (d, k) in chunk.iter_mut().zip(keystream_block.iter()) {
            *d ^= k;
        }
        increment_counter(counter);
    }
}

fn get_key_x(flags3: u8) -> Option<u128> {
    match flags3 {
        0x00 => Some(KEYX_SLOT_2C),
        0x01 => Some(KEYX_SLOT_25),
        0x0A => Some(KEYX_FW93),
        0x0B => Some(KEYX_FW96),
        _ => None,
    }
}

/// Check if an NCCH partition can be decrypted based on its flags.
/// Returns true if the ROM is encrypted and we have the keys to decrypt it.
pub fn can_decrypt_ncch(flag3: u8, flag7: u8) -> bool {
    // Already decrypted
    if flag7 & 0x04 != 0 {
        return false;
    }
    // Fixed crypto key (system titles) - not supported
    if flag7 & 0x01 != 0 {
        return false;
    }
    // Seed crypto - needs seeddb, not supported
    if flag7 & 0x20 != 0 {
        return false;
    }
    // Must have a known crypto method
    matches!(flag3, 0x00 | 0x01 | 0x0A | 0x0B)
}

/// Decrypt a .3ds ROM file in-place.
/// Decrypts all NCCH partitions and sets the NoCrypto flag.
pub fn decrypt_rom(path: &Path) -> io::Result<()> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    let ncsd = read_ncsd_header(&mut f)?;

    for partition_idx in 0..8 {
        let entry = &ncsd.offset_size_table[partition_idx];
        if entry.offset == 0 || entry.size == 0 {
            continue;
        }

        let ncch_offset = entry.offset as u64 * MEDIA_UNIT_SIZE;
        let ncch = read_ncch_header(&mut f, ncch_offset)?;

        // Skip if already decrypted
        if ncch.flags[7] & 0x04 != 0 {
            continue;
        }

        // Skip fixed crypto key (system titles)
        if ncch.flags[7] & 0x01 != 0 {
            continue;
        }

        // Skip seed crypto (needs seeddb)
        if ncch.flags[7] & 0x20 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Seed crypto (9.6+) requires seeddb.bin, not supported",
            ));
        }

        // KeyY = first 16 bytes of NCCH signature
        let key_y_bytes: [u8; 16] = ncch.signature[..16].try_into().unwrap();
        let key_y = u128::from_be_bytes(key_y_bytes);

        // Key0: always slot 0x2C (FW1) for exheader and ExeFS header
        let key0 = u128_to_be_bytes(key_scramble(KEYX_SLOT_2C, key_y));

        // Key1: based on flags[3] for rest of ExeFS and RomFS
        let key_x_1 = get_key_x(ncch.flags[3]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unknown crypto method: 0x{:02X}", ncch.flags[3]),
            )
        })?;
        let key1 = u128_to_be_bytes(key_scramble(key_x_1, key_y));

        let has_secondary_crypto = ncch.flags[3] != 0x00;

        // Decrypt ExHeader (0x800 bytes at ncch_offset + 0x200)
        if ncch.exhdr_size > 0 {
            let exhdr_offset = ncch_offset + 0x200;
            let exhdr_size = 0x800u64; // ExHeader + Access Descriptor
            let mut counter = get_ncch_aes_counter(&ncch, NcchSectionType::Exheader);

            decrypt_section_in_file(&mut f, exhdr_offset, exhdr_size, &key0, &mut counter)?;

            // Recalculate SHA-256 of the first 0x400 bytes (exheader only, not access descriptor)
            f.seek(SeekFrom::Start(exhdr_offset))?;
            let mut exhdr_data = vec![0u8; 0x400];
            f.read_exact(&mut exhdr_data)?;

            let mut hasher = Sha256::new();
            hasher.update(&exhdr_data);
            let hash = hasher.finalize();

            // Write updated hash to NCCH header (offset 0x160 from NCCH start)
            f.seek(SeekFrom::Start(ncch_offset + 0x160))?;
            f.write_all(&hash)?;
        }

        // Decrypt ExeFS
        if ncch.exefs_offset > 0 && ncch.exefs_size > 0 {
            let exefs_abs_offset = ncch_offset + ncch.exefs_offset as u64 * MEDIA_UNIT_SIZE;
            let exefs_total_size = ncch.exefs_size as u64 * MEDIA_UNIT_SIZE;

            if has_secondary_crypto {
                // First 0x200 bytes (ExeFS header) use key0
                let mut counter0 = get_ncch_aes_counter(&ncch, NcchSectionType::Exefs);
                decrypt_section_in_file(
                    &mut f,
                    exefs_abs_offset,
                    0x200,
                    &key0,
                    &mut counter0,
                )?;

                // Rest uses key1, counter starts at block offset 0x200/16 = 0x20
                if exefs_total_size > 0x200 {
                    let mut counter1 = get_ncch_aes_counter(&ncch, NcchSectionType::Exefs);
                    add_to_counter(&mut counter1, 0x200 / 16);
                    decrypt_section_in_file(
                        &mut f,
                        exefs_abs_offset + 0x200,
                        exefs_total_size - 0x200,
                        &key1,
                        &mut counter1,
                    )?;
                }
            } else {
                // All ExeFS uses key0
                let mut counter = get_ncch_aes_counter(&ncch, NcchSectionType::Exefs);
                decrypt_section_in_file(
                    &mut f,
                    exefs_abs_offset,
                    exefs_total_size,
                    &key0,
                    &mut counter,
                )?;
            }
        }

        // Decrypt RomFS
        if ncch.romfs_offset > 0 && ncch.romfs_size > 0 {
            let romfs_abs_offset = ncch_offset + ncch.romfs_offset as u64 * MEDIA_UNIT_SIZE;
            let romfs_total_size = ncch.romfs_size as u64 * MEDIA_UNIT_SIZE;
            let key_romfs = if has_secondary_crypto { &key1 } else { &key0 };
            let mut counter = get_ncch_aes_counter(&ncch, NcchSectionType::Romfs);
            decrypt_section_in_file(
                &mut f,
                romfs_abs_offset,
                romfs_total_size,
                key_romfs,
                &mut counter,
            )?;
        }

        // Set NoCrypto flag and clear crypto method
        f.seek(SeekFrom::Start(ncch_offset + 0x188 + 3))?; // flags[3]
        f.write_all(&[0x00])?;
        f.seek(SeekFrom::Start(ncch_offset + 0x188 + 7))?; // flags[7]
        let new_flag7 = ncch.flags[7] | 0x04;
        f.write_all(&[new_flag7])?;
    }

    f.flush()?;
    Ok(())
}

/// Decrypt a section of a file in-place using AES-128-CTR, processing in 4MB chunks
fn decrypt_section_in_file(
    f: &mut (impl Read + Write + Seek),
    offset: u64,
    size: u64,
    key: &[u8; 16],
    counter: &mut [u8; 16],
) -> io::Result<()> {
    const CHUNK_SIZE: u64 = 4 * 1024 * 1024; // 4MB
    let mut remaining = size;
    let mut pos = offset;
    let mut buf = vec![0u8; CHUNK_SIZE as usize];

    while remaining > 0 {
        let to_process = std::cmp::min(remaining, CHUNK_SIZE) as usize;
        f.seek(SeekFrom::Start(pos))?;
        f.read_exact(&mut buf[..to_process])?;

        aes_ctr_decrypt(&mut buf[..to_process], key, counter);

        f.seek(SeekFrom::Start(pos))?;
        f.write_all(&buf[..to_process])?;

        pos += to_process as u64;
        remaining -= to_process as u64;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotate_left_128() {
        let val: u128 = 0x80000000_00000000_00000000_00000001;
        assert_eq!(
            rotate_left_128(val, 1),
            0x00000000_00000000_00000000_00000003
        );
    }

    #[test]
    fn test_rotate_right_128() {
        let val: u128 = 0x00000000_00000000_00000000_00000003;
        assert_eq!(
            rotate_right_128(val, 1),
            0x80000000_00000000_00000000_00000001
        );
    }

    #[test]
    fn test_key_scramble_deterministic() {
        let key_x = KEYX_SLOT_2C;
        let key_y: u128 = 0;
        let result = key_scramble(key_x, key_y);
        assert_ne!(result, 0);
        assert_eq!(result, key_scramble(key_x, key_y));
    }

    #[test]
    fn test_key_scramble_different_keys() {
        let key1 = key_scramble(KEYX_SLOT_2C, 0x0123456789ABCDEF0123456789ABCDEF);
        let key2 = key_scramble(KEYX_SLOT_2C, 0xFEDCBA9876543210FEDCBA9876543210);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_increment_counter() {
        let mut counter = [0u8; 16];
        counter[15] = 0xFE;
        increment_counter(&mut counter);
        assert_eq!(counter[15], 0xFF);
        increment_counter(&mut counter);
        assert_eq!(counter[15], 0x00);
        assert_eq!(counter[14], 0x01);
    }

    #[test]
    fn test_increment_counter_full_carry() {
        let mut counter = [0xFF; 16];
        increment_counter(&mut counter);
        assert_eq!(counter, [0u8; 16]);
    }

    #[test]
    fn test_add_to_counter() {
        let mut counter = [0u8; 16];
        counter[15] = 0x10;
        add_to_counter(&mut counter, 0x20);
        assert_eq!(counter[15], 0x30);

        let mut counter2 = [0u8; 16];
        counter2[15] = 0xFF;
        add_to_counter(&mut counter2, 1);
        assert_eq!(counter2[15], 0x00);
        assert_eq!(counter2[14], 0x01);
    }

    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut counter1 = [0u8; 16];
        counter1[15] = 1;
        let mut counter2 = counter1;

        let original = b"Hello 3DS World! This is a test of AES-CTR mode!!";
        let mut data = original.to_vec();

        aes_ctr_decrypt(&mut data, &key, &mut counter1);
        assert_ne!(&data[..], &original[..]);

        aes_ctr_decrypt(&mut data, &key, &mut counter2);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_aes_ctr_partial_block() {
        let key = [0x01; 16];
        let mut counter1 = [0u8; 16];
        let mut counter2 = [0u8; 16];

        let original = vec![0x42u8; 7];
        let mut data = original.clone();

        aes_ctr_decrypt(&mut data, &key, &mut counter1);
        assert_ne!(data, original);

        aes_ctr_decrypt(&mut data, &key, &mut counter2);
        assert_eq!(data, original);
    }

    #[test]
    fn test_can_decrypt_ncch() {
        assert!(!can_decrypt_ncch(0x00, 0x04)); // already decrypted
        assert!(!can_decrypt_ncch(0x00, 0x01)); // fixed crypto
        assert!(!can_decrypt_ncch(0x00, 0x20)); // seed crypto
        assert!(!can_decrypt_ncch(0xFF, 0x00)); // unknown method
        assert!(can_decrypt_ncch(0x00, 0x00));  // FW1
        assert!(can_decrypt_ncch(0x01, 0x00));  // FW7
        assert!(can_decrypt_ncch(0x0A, 0x00));  // FW9.3
        assert!(can_decrypt_ncch(0x0B, 0x00));  // FW9.6
    }

    #[test]
    fn test_get_key_x() {
        assert_eq!(get_key_x(0x00), Some(KEYX_SLOT_2C));
        assert_eq!(get_key_x(0x01), Some(KEYX_SLOT_25));
        assert_eq!(get_key_x(0x0A), Some(KEYX_FW93));
        assert_eq!(get_key_x(0x0B), Some(KEYX_FW96));
        assert_eq!(get_key_x(0x02), None);
    }
}
