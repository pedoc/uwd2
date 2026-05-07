use std::fs;
<<<<<<< HEAD
use std::io;
use std::path::PathBuf;
=======
use std::path::Path;
>>>>>>> jcnnik/master

use crate::constants::*;
use crate::explorer_modinfo::verify_rva;
use crate::fetch_pdb;
use crate::parse_pdb::parse_pdb;
<<<<<<< HEAD
use std::fs::File;
use std::io::Write;
use std::io::Read as IoRead;
use std::str;

use windows::core::imp::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use crate::explorer_modinfo::{get_explorer_handle, get_shell32_offset};

const SIGNATURE_LEN: usize = 16;
const TAIL_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct CacheMeta {
    pub rva: u32,
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
}

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
    let sig_bytes = capture_process_bytes(rva, SIGNATURE_LEN + TAIL_LEN).unwrap_or_default();
    let meta_path = dir.join(guid.clone() + ".meta");
    if let Ok(mut f) = File::create(&meta_path) {
        // write rva as hex on first line, then head and tail signatures
        let _ = writeln!(f, "0x{rva:08x}");
        let head: String = sig_bytes.iter().take(SIGNATURE_LEN).map(|b| format!("{:02x}", b)).collect();
        let tail: String = sig_bytes.iter().skip(SIGNATURE_LEN).take(TAIL_LEN).map(|b| format!("{:02x}", b)).collect();
        let _ = writeln!(f, "{head}");
        let _ = writeln!(f, "{tail}");
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
=======
use crate::scan_dll;
use crate::structural_scan;

/// Resolve the RVA of `CDesktopWatermark::s_DesktopBuildPaint` for the
/// shell32.dll currently loaded in explorer.exe.
///
/// Fallback chain:
///   1. Local .rva cache hit
///   2. Microsoft symbol server (PDB download)
///   3. Multi-pattern binary scan (patterns.bin from a previous PDB run)
///   4. Structural GDI-call scan (no cached state required)
///   5. Panic with manual-recovery instructions
pub fn get_rva(guid: String) -> u32 {
    let dir = data_dir();
    let rva_path = dir.join(guid.clone() + ".rva");

    // 1. Cache hit
    if rva_path.exists() {
        println!("RVA cached. Reading...");
        let file = fs::read(rva_path).unwrap();
        return u32::from_be_bytes(file.try_into().unwrap());
    }

    // 2. Symbol server
    println!("PDB not cached. Fetching from symbol server...");
    let url = fetch_pdb::build_url(guid.clone());
    if let Some(pdbfile) = fetch_pdb::try_fetch(url) {
        println!("Fetched! Parsing...");
        let rva = parse_pdb(pdbfile);
        println!("Parsed! Caching...");
        save_rva_and_patterns(&dir, &guid, rva);
        println!("Cached!");
        return rva;
    }

    // 3. Multi-pattern binary scan
    println!("PDB unavailable. Trying multi-pattern binary scan...");
    let dll_bytes = scan_dll::read_dll();
    if let Some(rva) = try_multi_pattern_scan(&dir, &guid, &dll_bytes) {
        return rva;
    }

    // 4. Structural GDI-call scan
    println!("Trying structural GDI-call scan...");
    if let Some(rva) = structural_scan::find_by_gdi_calls(&dll_bytes) {
        let anchor = scan_dll::read_at_rva(&dll_bytes, rva, 8).unwrap_or_default();
        let verified = unsafe { verify_rva(rva, &anchor) };
        if verified {
            println!("Structural scan: verified RVA {rva:#x}. Caching...");
            save_rva_and_patterns(&dir, &guid, rva);
            return rva;
        }
        eprintln!("Structural scan returned {rva:#x} but live-process verification failed.");
    }

    // 5. Give up
    panic!(
        "\nAll automatic methods failed to locate CDesktopWatermark::s_DesktopBuildPaint.\n\
         \n\
         Manual recovery:\n\
         1. Open x64dbg and attach to explorer.exe\n\
         2. Search All Modules → String references for \"DesktopBuildPaint\"\n\
            or: set a breakpoint on SetTextColor and look at the call stack when\n\
            the desktop refreshes\n\
         3. Note the RVA  =  function_address - shell32_base\n\
         4. Run:  uwd2.exe patch-rva <hex-rva>\n"
    );
}

/// Try the multi-pattern binary scan using a saved patterns.bin.
fn try_multi_pattern_scan(dir: &Path, guid: &str, dll_bytes: &[u8]) -> Option<u32> {
    let patterns_path = dir.join("patterns.bin");
    if !patterns_path.exists() {
        eprintln!(
            "No cached patterns for binary scan.\n\
             Run UWD2 on a build where the PDB is available, or use patch-rva."
        );
        return None;
    }

    let data = match fs::read(&patterns_path) {
        Ok(d) => d,
        Err(e) => { eprintln!("Could not read patterns.bin: {e}"); return None; }
    };
    let patterns = match scan_dll::load_patterns(&data) {
        Some(p) => p,
        None => { eprintln!("patterns.bin is corrupt or unrecognized version."); return None; }
    };

    println!("Scanning shell32.dll with {} sub-patterns...", patterns.len());
    let hits = scan_dll::scan_for_multi_pattern(dll_bytes, &patterns);

    match hits.len() {
        0 => {
            eprintln!("Multi-pattern scan: no match — function prologue changed too much.");
            None
        }
        1 => {
            let file_offset = hits[0];
            let rva = scan_dll::file_offset_to_rva(dll_bytes, file_offset)?;
            println!("Found candidate at RVA {rva:#x}. Verifying against live process...");

            let anchor = &patterns[0].1;
            let verified = unsafe { verify_rva(rva, anchor) };
            if !verified {
                eprintln!("Live-process verification failed — bytes at {rva:#x} do not match.");
                return None;
            }

            println!("Verified! Caching RVA...");
            cleanup_old_rva_files(dir);
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(guid.to_string() + ".rva"), rva.to_be_bytes()).unwrap();
            println!("Cached!");
            Some(rva)
        }
        n => {
            eprintln!("Multi-pattern scan: {n} matches — ambiguous, cannot safely patch.");
            None
        }
    }
}

/// Persist RVA and refresh patterns.bin for the current build.
///
/// Called whenever a new RVA is resolved by any method (PDB, patch-rva,
/// structural scan).  Overwrites patterns.bin so future binary scans use
/// the most up-to-date function bytes.
fn save_rva_and_patterns(dir: &Path, guid: &str, rva: u32) {
    cleanup_old_rva_files(dir);
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join(guid.to_string() + ".rva"), rva.to_be_bytes()).unwrap();

    let dll_bytes = scan_dll::read_dll();
    match scan_dll::save_patterns(&dll_bytes, rva) {
        Some(data) => {
            fs::write(dir.join("patterns.bin"), &data).unwrap();
            println!(
                "Cached {} sub-patterns from RVA {rva:#x} for future builds.",
                data.get(1).copied().unwrap_or(0)
            );
        }
        None => {
            eprintln!(
                "Warning: could not read function bytes — \
                 binary scan unavailable for future builds."
            );
        }
    }
}

/// Called by `patch-rva`: user supplies an RVA manually, we cache it and
/// update patterns.bin so the next normal run hits the cache.
pub fn seed_rva(rva: u32) {
    let guid = unsafe { crate::explorer_modinfo::get_guid() };
    let dir = data_dir();
    save_rva_and_patterns(&dir, &guid, rva);
}

fn cleanup_old_rva_files(dir: &Path) {
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "rva") {
                let _ = fs::remove_file(path);
            }
        }
>>>>>>> jcnnik/master
    }
}

// read meta for cache entry (expects name like "GUID.rva")
pub fn read_meta(name: &str) -> Result<CacheMeta, String> {
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
    let head_line = lines.next().unwrap_or("");
    let tail_line = lines.next().unwrap_or("");
    let rva = if rva_line.starts_with("0x") { u32::from_str_radix(&rva_line[2..], 16).map_err(|e| format!("Bad rva in meta: {:?}", e))? } else { rva_line.parse::<u32>().map_err(|e| format!("Bad rva in meta: {:?}", e))? };
    Ok(CacheMeta {
        rva,
        head: hex_to_bytes(head_line)?,
        tail: hex_to_bytes(tail_line).unwrap_or_default(),
    })
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

pub fn find_strong_signature_candidates(meta: &CacheMeta, path: &str) -> Result<Vec<u32>, String> {
    let head_matches = find_signature_in_path(&meta.head, path)?;
    if meta.tail.is_empty() {
        return Ok(head_matches);
    }

    let mut confirmed = Vec::new();
    for rva in head_matches {
        let bytes = read_bytes_from_file(path, rva as usize, meta.head.len() + meta.tail.len())?;
        if bytes.len() >= meta.head.len() + meta.tail.len()
            && bytes[..meta.head.len()] == meta.head[..]
            && bytes[meta.head.len()..meta.head.len() + meta.tail.len()] == meta.tail[..]
        {
            confirmed.push(rva);
        }
    }
    Ok(confirmed)
}

pub fn read_bytes_from_file(path: &str, offset: usize, len: usize) -> Result<Vec<u8>, String> {
    let mut f = File::open(path).map_err(|e| format!("Failed opening {}: {:?}", path, e))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| format!("Failed reading {}: {:?}", path, e))?;
    if offset >= buf.len() {
        return Ok(Vec::new());
    }
    let end = offset.saturating_add(len).min(buf.len());
    Ok(buf[offset..end].to_vec())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < hex.len() {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("Bad sig hex: {:?}", e))?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}
