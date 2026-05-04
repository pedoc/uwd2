use std::fs;
use std::io;
use std::path::PathBuf;

use crate::constants::*;
use crate::fetch_pdb;
use crate::fetch_pdb::fetch;
use crate::parse_pdb::parse_pdb;

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
