// SHA256, CRC32, AES title key encryption, XOR utilities

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use sha2::{Digest, Sha256};

pub fn xor_bytes(data: &[u8], xorpad: &[u8]) -> Vec<u8> {
    data.iter().zip(xorpad.iter()).map(|(a, b)| a ^ b).collect()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

pub fn crc32_file(path: &Path) -> io::Result<u32> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

pub fn encrypt_title_key(title_key: &[u8; 16], title_id: &[u8; 8]) -> [u8; 16] {
    // AES-CBC encrypt with common key (all zeros) and IV = titleID + 8 zero bytes
    // For a single 16-byte block: ciphertext = AES_ECB(plaintext XOR IV, key)
    let common_key = [0u8; 16];
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(title_id);

    let mut block = [0u8; 16];
    for i in 0..16 {
        block[i] = title_key[i] ^ iv[i];
    }

    let cipher = Aes128::new((&common_key).into());
    let mut aes_block = aes::Block::default();
    aes_block.copy_from_slice(&block);
    cipher.encrypt_block(&mut aes_block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&aes_block);
    out
}

pub fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) / align * align
}

pub fn round_up(num: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return num;
    }
    let remainder = num % multiple;
    if remainder == 0 {
        num
    } else {
        num + multiple - remainder
    }
}
