use std::env;
use std::io::{self, Write};
use std::fs;
use std::path::Path;

use crate::cache_pdb::{get_rva, list_cached, read_cached};
use crate::explorer_modinfo::get_guid;
use crate::constants::data_dir;
use crate::fetch_pdb::{build_url, fetch};

mod cache_pdb;
mod constants;
mod explorer_modinfo;
mod fetch_pdb;
mod inject;
mod parse_pdb;

fn prog() -> String {
    // modified from https://stackoverflow.com/a/58113997/9044183
    env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_os_string()
        .into_string()
        .unwrap()
}

fn help() {
    println!(
        include_str!("../help.txt"),
        env!("CARGO_PKG_VERSION"),
        prog()
    )
}

fn rva() -> u32 {
    let guid;
    unsafe {
        guid = get_guid();
    }
    match get_rva(guid) {
        Ok(rva) => {
            println!("RVA is {rva:#x}");
            rva
        }
        Err(e) => {
            eprintln!("Error obtaining RVA: {e}");
            std::process::exit(1);
        }
    }
}

fn inject() {
    unsafe {
        inject::inject(rva());
        inject::refresh();
    }
}
fn main() {
    let args = env::args().collect::<Vec<String>>();
    match args.get(1).map(|s| s.as_str()) {
        None => inject(),
        Some("inject") => inject(),
        Some("help") => help(),
        Some("about") => println!(include_str!("../about.txt"), env!("CARGO_PKG_VERSION")),
        Some("list-cache") => match list_cached() {
            Ok(list) => {
                if list.is_empty() {
                    println!("No cached entries found.");
                } else {
                    println!("Cached entries:");
                    for n in list {
                        println!(" - {}", n);
                    }
                }
            }
            Err(e) => eprintln!("Failed listing cache: {e}"),
        },
        Some("download-pdb") => match args.get(2) {
            None => eprintln!("Usage: {} download-pdb <cache-file>", prog()),
            Some(name) => {
                let stem = Path::new(name)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(name);
                let url = build_url(stem.to_string());
                let dir = data_dir();
                let _ = fs::create_dir_all(&dir);
                let pdb_path = dir.join(format!("{stem}.pdb"));

                if pdb_path.exists() {
                    println!("PDB already exists: {}", pdb_path.display());
                    return;
                }

                println!("Downloading PDB from: {url}");
                match fetch(url) {
                    Ok(bytes) => match fs::write(&pdb_path, bytes) {
                        Ok(()) => println!("Saved PDB to: {}", pdb_path.display()),
                        Err(e) => eprintln!("Failed writing PDB: {e}"),
                    },
                    Err(e) => eprintln!("Failed downloading PDB: {e}"),
                }
            }
        },
        Some("verify-cache") => match args.get(2) {
            None => eprintln!("Usage: {} verify-cache <cache-file>", prog()),
            Some(name) => match cache_pdb::read_meta(name.as_str()) {
                Ok((rva, sig)) => {
                    // read process bytes at rva and compare
                    match cache_pdb::capture_process_bytes(rva, sig.len()) {
                        Ok(cur) => {
                            if cur == sig {
                                println!("Verification OK: in-memory bytes match cached signature");
                            } else {
                                println!("Verification FAILED: bytes differ");
                            }
                        }
                        Err(e) => eprintln!("Failed to read process memory: {e}"),
                    }
                }
                Err(e) => eprintln!("Failed to read meta: {e}"),
            },
        },
        Some("find-in-file") => match args.get(2) {
            None => eprintln!("Usage: {} find-in-file <cache-file>", prog()),
            Some(name) => match cache_pdb::read_meta(name.as_str()) {
                Ok((_rva, sig)) => match cache_pdb::find_signature_in_file(&sig) {
                    Ok(cands) => {
                        if cands.is_empty() {
                            println!("No candidates found in file");
                        } else {
                            println!("Candidates (RVAs):");
                            for c in cands {
                                println!(" - 0x{c:08x}");
                            }
                        }
                    }
                    Err(e) => eprintln!("Search failed: {e}"),
                },
                Err(e) => eprintln!("Failed to read meta: {e}"),
            },
        },
        Some("inject-cache") => match args.get(2) {
            None => eprintln!("Usage: {} inject-cache <cache-file> [rva-hex]", prog()),
            Some(name) => {
                // if user provided optional rva override, parse it
                match args.get(3) {
                    Some(override_rva) => {
                        let parsed = if override_rva.starts_with("0x") { u32::from_str_radix(&override_rva[2..], 16) } else { override_rva.parse() };
                        match parsed {
                            Ok(rva) => unsafe {
                                inject::inject(rva);
                                inject::refresh();
                            },
                            Err(_) => eprintln!("Invalid RVA value"),
                        }
                    }
                    None => match read_cached(name.as_str()) {
                        Ok(rva) => unsafe {
                            inject::inject(rva);
                            inject::refresh();
                        },
                        Err(e) => eprintln!("Failed to read cache entry: {e}"),
                    },
                }
            }
        },
        Some("scan-and-inject") => match args.get(2) {
            None => eprintln!("Usage: {} scan-and-inject <cache-file>", prog()),
            Some(name) => match cache_pdb::read_meta(name.as_str()) {
                Ok((_old_rva, sig)) => {
                    println!("Searching for signature candidates in {}...", constants::SHELL32_PATH);
                    match cache_pdb::find_signature_in_file(&sig) {
                        Ok(cands) => {
                            if cands.is_empty() {
                                println!("No candidates found in file.");
                                return;
                            }
                            println!("Found {} candidates:", cands.len());
                            for (i, c) in cands.iter().enumerate() {
                                println!("[{}] 0x{c:08x}", i);
                            }
                            print!("Select index to use (q to abort): ");
                            let _ = io::stdout().flush();
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).unwrap();
                            let s = input.trim();
                            if s.eq_ignore_ascii_case("q") { println!("Aborted"); return; }
                            let idx: usize = match s.parse() { Ok(v) => v, Err(_) => { eprintln!("Invalid selection"); return; } };
                            if idx >= cands.len() { eprintln!("Index out of range"); return; }
                            let chosen = cands[idx];
                            println!("Chosen candidate RVA: 0x{chosen:08x}");
                            // verify in-process bytes at chosen
                            match cache_pdb::capture_process_bytes(chosen, sig.len()) {
                                Ok(cur) => {
                                    if cur == sig {
                                        println!("In-memory bytes match signature (OK)");
                                    } else {
                                        println!("In-memory bytes differ from cached signature");
                                        print!("Proceed with injection anyway? (y/N): ");
                                        let _ = io::stdout().flush();
                                        let mut ans = String::new();
                                        io::stdin().read_line(&mut ans).unwrap();
                                        if !ans.trim().eq_ignore_ascii_case("y") { println!("Aborted"); return; }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to read process memory for verification: {e}");
                                    print!("Proceed with injection anyway? (y/N): ");
                                    let _ = io::stdout().flush();
                                    let mut ans = String::new();
                                    io::stdin().read_line(&mut ans).unwrap();
                                    if !ans.trim().eq_ignore_ascii_case("y") { println!("Aborted"); return; }
                                }
                            }
                            // Confirm final injection
                            print!("Confirm inject RVA 0x{chosen:08x}? (y/N): ");
                            let _ = io::stdout().flush();
                            let mut conf = String::new();
                            io::stdin().read_line(&mut conf).unwrap();
                            if !conf.trim().eq_ignore_ascii_case("y") { println!("Aborted"); return; }
                            unsafe {
                                inject::inject(chosen);
                                inject::refresh();
                            }
                            println!("Injection complete.");
                            // ask to save candidate to cache
                            print!("Save this candidate as a cache entry for current GUID? (y/N): ");
                            let _ = io::stdout().flush();
                            let mut sv = String::new();
                            io::stdin().read_line(&mut sv).unwrap();
                            if sv.trim().eq_ignore_ascii_case("y") {
                                // determine GUID for current shell32
                                let guid = unsafe { get_guid() };
                                let dir = data_dir();
                                let _ = fs::create_dir_all(&dir);
                                let rva_path = dir.join(guid.clone() + ".rva");
                                let meta_path = dir.join(guid.clone() + ".meta");
                                if let Err(e) = fs::write(&rva_path, chosen.to_be_bytes()) {
                                    eprintln!("Failed writing cache rva: {:?}", e);
                                } else {
                                    // write meta with chosen signature captured now
                                    let sig_now = cache_pdb::capture_process_bytes(chosen, sig.len()).unwrap_or_default();
                                    if let Ok(mut f) = fs::File::create(&meta_path) {
                                        let _ = writeln!(f, "0x{chosen:08x}");
                                        let hexsig: String = sig_now.iter().map(|b| format!("{:02x}", b)).collect();
                                        let _ = writeln!(f, "{hexsig}");
                                        println!("Saved cache: {}", rva_path.display());
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("Search failed: {e}"),
                    }
                }
                Err(e) => eprintln!("Failed to read meta: {e}"),
            },
        },
        Some(err) => eprintln!("Invalid argument `{err}`. Run `{} help` to see all commands.", prog()),
    }
}
