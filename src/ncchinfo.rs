// ncchinfo.bin generation

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::ncsd::*;

fn gen_out_name(title_id: &str, crc32: u32, partition_name: &str, section_name: &str) -> Vec<u8> {
    let name = format!(
        "/{}.{:08x}.{}.{}.xorpad",
        title_id, crc32, partition_name, section_name
    );
    let name_bytes = name.as_bytes();
    assert!(name_bytes.len() <= 112, "Output file name too large");
    let mut out = vec![0u8; 112];
    out[..name_bytes.len()].copy_from_slice(name_bytes);
    out
}

pub fn ncchinfo_gen(files: &[(PathBuf, u32)]) -> io::Result<()> {
    println!();
    let mut entries: u32 = 0;
    let mut data = Vec::new();
    for (filename, crc32) in files {
        let mut fh = BufReader::new(File::open(filename)?);
        fh.seek(SeekFrom::Start(0x100))?;
        let mut magic = [0u8; 4];
        fh.read_exact(&mut magic)?;
        if &magic == b"NCSD" {
            let header = read_ncsd_header(&mut fh)?;
            let title_id = reverse_ctype_array(&header.title_id);
            println!("Parsing NCSD in file {:?}:", filename.file_name().unwrap());
            for (i, entry) in header.offset_size_table.iter().enumerate() {
                if entry.offset != 0 {
                    let ncch_offset = entry.offset as u64 * MEDIA_UNIT_SIZE;
                    let ncch_hdr = read_ncch_header(&mut fh, ncch_offset)?;
                    println!("  Parsing {} NCCH", NCSD_PARTITIONS[i]);
                    if ncch_hdr.exhdr_size != 0 {
                        let section_data =
                            parse_ncch_section(&ncch_hdr, NcchSectionType::Exheader);
                        let out_name =
                            gen_out_name(&title_id, *crc32, NCSD_PARTITIONS[i], "exheader");
                        data.extend_from_slice(&section_data);
                        data.extend_from_slice(&out_name);
                        entries += 1;
                    }
                }
            }
            println!();
        } else if &magic == b"NCCH" {
            let ncch_hdr = read_ncch_header(&mut fh, 0)?;
            let title_id = reverse_ctype_array(&ncch_hdr.title_id);
            println!("Parsing NCCH in file {:?}:", filename.file_name().unwrap());
            if ncch_hdr.exhdr_size != 0 {
                let section_data = parse_ncch_section(&ncch_hdr, NcchSectionType::Exheader);
                let out_name = gen_out_name(&title_id, *crc32, "Main", "exheader");
                data.extend_from_slice(&section_data);
                data.extend_from_slice(&out_name);
                entries += 1;
            }
            println!();
        }
    }
    let mut out = File::create("ncchinfo.bin")?;
    out.write_all(&0xFFFFFFFFu32.to_le_bytes())?;
    out.write_all(&0xF0000004u32.to_le_bytes())?;
    out.write_all(&entries.to_le_bytes())?;
    out.write_all(&0u32.to_le_bytes())?;
    out.write_all(&data)?;
    println!("Done!");
    Ok(())
}
