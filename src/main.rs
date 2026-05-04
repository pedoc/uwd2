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
        Some("inject-cache") => match args.get(2) {
            None => eprintln!("Usage: {} inject-cache <cache-file>", prog()),
            Some(name) => match read_cached(name.as_str()) {
                Ok(rva) => unsafe {
                    inject::inject(rva);
                    inject::refresh();
                },
                Err(e) => eprintln!("Failed to read cache entry: {e}"),
            },
        },
        Some(err) => eprintln!("Invalid argument `{err}`. Run `{} help` to see all commands.", prog()),
    }
}
