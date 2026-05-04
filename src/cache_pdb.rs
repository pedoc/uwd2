use std::fs;
use std::io;
use std::path::PathBuf;

use crate::constants::*;
use crate::fetch_pdb;
use crate::fetch_pdb::fetch;
use crate::parse_pdb::parse_pdb;
use std::fs::File;
use std::io::Write;
use std::io::Read as IoRead;
use std::str;

use windows::core::imp::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use crate::explorer_modinfo::{get_explorer_handle, get_shell32_offset};

// Get RVA for a guid. Returns Result so callers can handle failures (e.g., PDB 404)
pub fn get_rva(guid: String) -> Result<u32, String> {
    let dir = data_dir();
    let pdbpath = dir.join(guid.clone() + ".rva");
    if pdbpath.exists() {
        println!("PDB cached. Reading from: {}", pdbpath.display());
        let file = fs::read(pdbpath).map_err(|e| format!("Failed reading cached rva: {:?}", e))?;
        return Ok(u32::from_be_bytes(file.try_into().map_err(|e| format!("Invalid rva file format: {:?}", e))?));
    }

    println!("PDB not found. Fetching...");
    let url = fetch_pdb::build_url(guid.clone());
    println!("PDB download URL: {} | cache path: {}", url, pdbpath.display());

    let pdbfile = match fetch(url) {
        Ok(b) => b,
        Err(e) => {
            // On network or 404 errors, do NOT delete existing cache. Instead list available cached versions
            eprintln!("Failed to fetch PDB: {e}");
            let mut msg = format!("Failed to fetch PDB for GUID {guid}: {e}\n");
            if dir.exists() {
                msg.push_str("Available cached GUIDs:\n");
                    for entry in fs::read_dir(&dir).map_err(|e| format!("Failed reading cache dir: {:?}", e))? {
                    if let Ok(ent) = entry {
                        if let Some(name) = ent.file_name().to_str() {
                            if name.ends_with(".rva") {
                                msg.push_str(&format!(" - {}\n", name));
                            }
                        }
                    }
                }
                msg.push_str("Use 'list-cache' to see entries or 'inject-cache <name>' to use one.\n");
            }
            return Err(msg);
        }
    };

    println!("Fetched! Parsing...");
    let rva = parse_pdb(pdbfile);
    println!("Parsed! Caching...");

    // create directories if needed and write cache; do NOT remove old caches
    fs::create_dir_all(&dir).map_err(|e| format!("Failed creating cache dir: {e}"))?;
    fs::write(pdbpath, rva.to_be_bytes()).map_err(|e| format!("Failed writing rva cache: {e}"))?;
    // attempt to capture signature bytes at the target address in explorer process
    // to allow later verification or relocation scanning
    let sig_bytes = capture_process_bytes(rva, 16).unwrap_or_default();
    let meta_path = dir.join(guid.clone() + ".meta");
    if let Ok(mut f) = File::create(&meta_path) {
        // write rva as hex on first line, then signature as hex on second line
        let _ = writeln!(f, "0x{rva:08x}");
        let hexsig: String = sig_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let _ = writeln!(f, "{hexsig}");
    }
    println!("Cached!");
    Ok(rva)
}

// List cached rva files (names) in the data dir
pub fn list_cached() -> io::Result<Vec<String>> {
    let dir = data_dir();
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir)? {
        let ent = entry?;
        if let Some(name) = ent.file_name().to_str() {
            if name.ends_with(".rva") {
                out.push(name.to_string());
            }
        }
    }
    Ok(out)
}

// Read a specific cached rva entry by filename
pub fn read_cached(name: &str) -> Result<u32, String> {
    let dir = data_dir();
    let path = PathBuf::from(dir).join(name);
    if !path.exists() {
        return Err(format!("Cache entry not found: {}", name));
    }
    let file = fs::read(path).map_err(|e| format!("Failed reading cache entry: {:?}", e))?;
    Ok(u32::from_be_bytes(file.try_into().map_err(|e| format!("Invalid cache file format: {:?}", e))?))
}

pub fn capture_process_bytes(rva: u32, len: usize) -> Result<Vec<u8>, String> {
    unsafe {
        let explorer = get_explorer_handle();
        let offset = get_shell32_offset();
        let addr = (offset + rva as u64) as *const core::ffi::c_void;
        let mut buf = vec![0u8; len];
        let res = ReadProcessMemory(explorer, addr, buf.as_mut_ptr() as *mut _, len, None);
        CloseHandle(explorer.0);
        if res.is_ok() {
            Ok(buf)
        } else {
            Err(format!("Failed reading process memory: {:?}", res.err()))
        }
    }
}

// read meta for cache entry (expects name like "GUID.rva")
pub fn read_meta(name: &str) -> Result<(u32, Vec<u8>), String> {
    let dir = data_dir();
    let stem = if name.ends_with(".rva") { &name[..name.len()-4] } else { name };
    let path = dir.join(format!("{}.meta", stem));
    if !path.exists() {
        return Err(format!("Meta file not found: {}", path.display()));
    }
    let mut s = String::new();
    File::open(path).map_err(|e| format!("Failed opening meta: {:?}", e))?.read_to_string(&mut s).map_err(|e| format!("Failed reading meta: {:?}", e))?;
    let mut lines = s.lines();
    let rva_line = lines.next().ok_or_else(|| "Meta missing rva line".to_string())?;
    let sig_line = lines.next().unwrap_or("");
    let rva = if rva_line.starts_with("0x") { u32::from_str_radix(&rva_line[2..], 16).map_err(|e| format!("Bad rva in meta: {:?}", e))? } else { rva_line.parse::<u32>().map_err(|e| format!("Bad rva in meta: {:?}", e))? };
    let mut sig = Vec::new();
    let mut i = 0;
    while i + 1 <= sig_line.len() {
        if i+2 > sig_line.len() { break; }
        let byte = u8::from_str_radix(&sig_line[i..i+2], 16).map_err(|e| format!("Bad sig hex: {:?}", e))?;
        sig.push(byte);
        i += 2;
    }
    Ok((rva, sig))
}

// search for signature bytes in the on-disk shell32.dll and report candidate RVAs (using PE section mapping)
pub fn find_signature_in_file(sig: &[u8]) -> Result<Vec<u32>, String> {
    find_signature_in_path(sig, SHELL32_PATH)
}

// search for signature bytes in arbitrary file path. If file is a PE, map offsets to RVAs using section table.
pub fn find_signature_in_path(sig: &[u8], path: &str) -> Result<Vec<u32>, String> {
    let mut f = File::open(path).map_err(|e| format!("Failed opening {}: {:?}", path, e))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| format!("Failed reading {}: {:?}", path, e))?;
    let mut candidates = Vec::new();
    if buf.len() < sig.len() {
        return Ok(candidates);
    }
    // attempt PE detection
    let is_pe = buf.len() >= 0x40 && &buf[0..2] == b"M\x5a";
    let mut sections_info = Vec::new();
    if is_pe {
        let e_lfanew = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap()) as usize;
        if buf.len() >= e_lfanew + 0x18 {
            let number_of_sections = u16::from_le_bytes(buf[e_lfanew+6..e_lfanew+8].try_into().unwrap()) as usize;
            let size_of_optional = u16::from_le_bytes(buf[e_lfanew+20..e_lfanew+22].try_into().unwrap()) as usize;
            let sections_start = e_lfanew + 24 + size_of_optional;
            for sidx in 0..number_of_sections {
                let sh = sections_start + sidx*40;
                if sh + 40 > buf.len() { break; }
                let pointer_to_raw = u32::from_le_bytes(buf[sh+20..sh+24].try_into().unwrap()) as usize;
                let size_of_raw = u32::from_le_bytes(buf[sh+16..sh+20].try_into().unwrap()) as usize;
                let virtual_address = u32::from_le_bytes(buf[sh+12..sh+16].try_into().unwrap());
                sections_info.push((pointer_to_raw, size_of_raw, virtual_address));
            }
        }
    }
    for i in 0..(buf.len() - sig.len() + 1) {
        if &buf[i..i+sig.len()] == sig {
            if sections_info.is_empty() {
                candidates.push(i as u32);
            } else {
                for (ptr_raw, size_raw, virt) in &sections_info {
                    if i >= *ptr_raw && i < (*ptr_raw + *size_raw) {
                        let rva = *virt + ((i - *ptr_raw) as u32);
                        candidates.push(rva);
                    }
                }
            }
        }
    }
    Ok(candidates)
}
