mod cia;
mod constants;
mod crypto;
mod decrypt;
mod ncchinfo;
mod ncsd;
mod rom;
mod xorpad;

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use colored::*;
use rayon::prelude::*;

use crate::crypto::crc32_file;
use crate::ncchinfo::ncchinfo_gen;
use crate::rom::*;
use crate::xorpad::*;

#[derive(Parser)]
#[command(name = "3ds-to-cia", about = "Convert 3DS ROMs to CIA files")]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn discover_roms() -> Vec<PathBuf> {
    let patterns = ["roms/*.[3zZ][dDiI][sSpP]"];
    let mut roms = Vec::new();
    for pattern in &patterns {
        if let Ok(paths) = glob::glob(pattern) {
            for path in paths.flatten() {
                roms.push(path);
            }
        }
    }
    roms
}

fn convert_to_cia(
    filename: &Path,
    crc32: u32,
    tmpdir: &Path,
    verbose: bool,
) -> io::Result<bool> {
    let mut fh = BufReader::new(File::open(filename)?);
    let title_id = get_title_id(&mut fh)?;
    let title_id_bytes = get_title_id_bytes(&mut fh)?;
    let ncch_flag7 = get_ncch_flag7(&mut fh)?;
    let mut decrypted = ncch_flag7 & 0x4 != 0;
    let new_key_y = ncch_flag7 & 0x20 != 0;

    if !decrypted {
        // Try direct decryption first
        drop(fh);
        match decrypt::decrypt_rom(filename) {
            Ok(()) => {
                fh = BufReader::new(File::open(filename)?);
                decrypted = true;
                if verbose {
                    println!("  Decrypted successfully.");
                }
            }
            Err(e) => {
                if verbose {
                    println!("  Direct decryption failed: {}, trying xorpad...", e);
                }
                fh = BufReader::new(File::open(filename)?);
            }
        }
    }

    let xorpad_file = if decrypted {
        None
    } else {
        find_xorpad(&title_id, crc32, tmpdir)
    };

    if !verify_xorpad(&mut fh, xorpad_file.as_deref())? {
        if decrypted {
            println!("Xorpad file is not valid.");
        } else {
            println!("Rom corrupted.");
        }
        return Ok(false);
    }

    extract_rom(&mut fh, tmpdir)?;
    drop(fh);

    let cxi_path = tmpdir.join("0.cxi");
    let save_data_size = fix_cxi(&cxi_path, xorpad_file.as_deref())?;

    let mut contents: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(tmpdir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            if ext_lower == "cxi" || ext_lower == "cfa" {
                contents.push(path);
            }
        }
    }
    contents.sort();

    fs::create_dir_all("cia")?;

    let rom_stem = filename
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let cia_filename = Path::new("cia").join(format!("{}.cia", rom_stem));

    let result = cia::build_cia(
        &contents,
        &cia_filename,
        save_data_size,
        &title_id_bytes,
        verbose,
    )?;

    for content in &contents {
        let _ = fs::remove_file(content);
    }

    if !result {
        println!(
            "{}",
            format!("Error during CIA creation of '{}'", filename.display()).red()
        );
        println!("{}", "[ERROR]".red());
    } else if new_key_y {
        println!("{}", "[WARNING]".yellow());
        println!("This is a 9.6+ game which uses seed encryption and may not work directly!");
        println!();
        println!("If this title is of the same region of your hardware you can decrypt it by visiting the eShop page of this title after the installation.");
        println!("If this title is of a different region than your hardware you need to decrypt the CIA file using Decryp9WIP before the installation.");
    } else {
        println!("{}", "[OK]".green());
    }

    Ok(result)
}

fn main_check(
    filename: &Path,
    crc32: u32,
    tmpdir: &Path,
) -> io::Result<Option<(PathBuf, u32)>> {
    let mut fh = BufReader::new(File::open(filename)?);
    let title_id = get_title_id(&mut fh)?;
    let (flag3, flag7) = get_ncch_flags(&mut fh)?;
    drop(fh);

    if flag7 & 0x4 != 0 {
        print!("{}", " [NOT NEEDED]".yellow());
        return Ok(None);
    }

    // If we can decrypt this ROM directly, try it
    if decrypt::can_decrypt_ncch(flag3, flag7) {
        match decrypt::decrypt_rom(filename) {
            Ok(()) => {
                print!("{}", " [DECRYPTED]".green());
                return Ok(None);
            }
            Err(_) => {
                // Decryption failed (likely a partial file from zip extract),
                // but we know it can be decrypted during conversion
                print!("{}", " [WILL DECRYPT]".cyan());
                return Ok(None);
            }
        }
    }

    // Can't decrypt directly (seed crypto, unknown method), need xorpad
    if find_xorpad(&title_id, crc32, tmpdir).is_none() {
        print!("{}", " [NOT FOUND]".red());
        return Ok(Some((filename.to_path_buf(), crc32)));
    }
    print!("{}", " [FOUND]".green());
    Ok(None)
}

fn main() {
    let cli = Cli::parse();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::env::set_current_dir(dir);
        }
    }

    fs::create_dir_all("cia").ok();
    fs::create_dir_all("xorpads").ok();

    if cfg!(target_pointer_width = "32") {
        println!("{}", "You are using a 32-bit OS.".yellow());
        println!(
            "{}",
            "You won't be able to convert some big roms (2GB+).".yellow()
        );
    }

    let roms = discover_roms();
    if roms.is_empty() {
        println!("No valid files in rom directory found.");
        std::process::exit(1);
    }

    println!("{}", "Work in progress... Please wait...".green());
    println!();

    println!("Computing CRC32 checksums...");
    let non_zip_roms: Vec<&PathBuf> = roms
        .iter()
        .filter(|r| {
            File::open(r)
                .ok()
                .and_then(|f| zip::ZipArchive::new(f).ok())
                .is_none()
        })
        .collect();

    let crc32_map: std::collections::HashMap<PathBuf, u32> = non_zip_roms
        .par_iter()
        .filter_map(|rom| crc32_file(rom).ok().map(|crc| ((*rom).clone(), crc)))
        .collect();
    println!();

    let mut check = true;

    loop {
        let mut missing_xorpads: Vec<(PathBuf, u32)> = Vec::new();

        if check {
            println!("{}", "Checking/Decrypting ROMs...".bold());
        } else {
            println!("{}", "Creating CIA...".bold());
        }
        println!();

        for rom in &roms {
            if let Ok(file) = File::open(rom) {
                if zip::ZipArchive::new(file).is_ok() {
                    println!("{}", rom.display());
                    let file = File::open(rom).unwrap();
                    let mut archive = zip::ZipArchive::new(file).unwrap();

                    for i in 0..archive.len() {
                        let entry = archive.by_index(i).unwrap();
                        let entry_name = entry.name().to_string();
                        let basename = Path::new(&entry_name)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();

                        if basename.is_empty() || !basename.to_lowercase().ends_with(".3ds") {
                            continue;
                        }

                        let crc32_val = entry.crc32();
                        drop(entry);

                        if check || !cli.verbose {
                            print!("\t-> {} ", entry_name);
                        } else {
                            println!("\t-> {}", entry_name);
                            println!();
                        }

                        let tmpdir = tempfile::tempdir().unwrap();

                        if check {
                            let mut entry = archive.by_index(i).unwrap();
                            let tmp_path = tmpdir.path().join(&basename);
                            {
                                let mut out = File::create(&tmp_path).unwrap();
                                let mut buf = vec![0u8; 0x10000];
                                let mut total = 0usize;
                                loop {
                                    let n = entry.read(&mut buf[total..]).unwrap();
                                    if n == 0 || total + n >= 0x10000 {
                                        total += n;
                                        break;
                                    }
                                    total += n;
                                }
                                out.write_all(&buf[..total]).unwrap();
                            }
                            if let Ok(Some(_)) =
                                main_check(&tmp_path, crc32_val, tmpdir.path())
                            {
                                missing_xorpads.push((tmp_path.to_path_buf(), crc32_val));
                            }
                            println!();
                        } else {
                            let mut entry = archive.by_index(i).unwrap();
                            let tmp_path = tmpdir.path().join(&basename);
                            {
                                let mut out = File::create(&tmp_path).unwrap();
                                io::copy(&mut entry, &mut out).unwrap();
                            }
                            if let Err(e) = convert_to_cia(&tmp_path, crc32_val, tmpdir.path(), cli.verbose) {
                                println!("{}", format!("Error: {}", e).red());
                            }
                        }
                    }
                    println!();
                    continue;
                }
            }

            let crc32_val = *crc32_map.get(rom).unwrap();

            if check || !cli.verbose {
                print!("{} ", rom.display());
            } else {
                println!("{}", rom.display());
                println!();
            }

            let tmpdir = tempfile::tempdir().unwrap();

            if check {
                if let Ok(Some(_)) = main_check(rom, crc32_val, tmpdir.path()) {
                    missing_xorpads.push((rom.clone(), crc32_val));
                }
                println!();
            } else {
                if let Err(e) = convert_to_cia(rom, crc32_val, tmpdir.path(), cli.verbose) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }

            println!();
        }

        if check {
            if !missing_xorpads.is_empty() {
                ncchinfo_gen(&missing_xorpads).ok();
                println!(
                    "Copy ncchinfo.bin to your 3DS and make it generates the required xorpads"
                );
                println!("Then copy the generated xorpads in the 'xorpads' directory");
                println!();
                println!("Press Enter to continue...");
                let _ = io::stdin().lock().read_line(&mut String::new());
            } else {
                check = false;
            }
        } else {
            break;
        }
    }

    println!("Press Enter to continue...");
    let _ = io::stdin().lock().read_line(&mut String::new());
}
