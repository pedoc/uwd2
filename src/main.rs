use std::env;

use crate::cache_pdb::{get_rva, list_cached, read_cached};
use crate::explorer_modinfo::get_guid;

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
        Some(err) => eprintln!("Invalid argument `{err}`. Run `{} help` to see all commands.", prog()),
    }
}
