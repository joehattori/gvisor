#![feature(wasi_ext)]

mod api;
mod connection;
mod filter;
mod fs;
mod linux;
mod message;
mod rustfer;
mod seccomp;
mod spec_utils;
mod unix;
mod wasm_mem;

fn main() {
    read_dir("/");
    // read_dir("/dev");
    // read_dir("/etc");
    read_dir("/usr/lib64");
    read_dir("/root");
    // read_dir("/config");
    // read_dir("/proc");
    // read_dir("/proc/self");
    // read_dir("/proc/self/fd");
}

fn read_dir(dir: &str) {
    use std::fs;
    println!("reading dir: {}", dir);
    let read_dir = match fs::read_dir(dir) {
        Ok(d) => d,
        Err(e) => {
            println!("error read_dir: {}", e);
            return;
        }
    };
    for entry in read_dir {
        match entry {
            Ok(entry) => {
                println!(
                    "entry: {:?} filetype: {:?} is_symlink: {:?}",
                    entry.path(),
                    entry.file_type(),
                    entry.file_type().unwrap().is_symlink(),
                );
            }
            Err(e) => println!("error occured while reading directory: {}", e),
        };
    }
}
