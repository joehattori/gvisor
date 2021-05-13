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
    read_dir("/dev");
    read_dir("/etc");
    read_dir("/proc/self/fd");
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
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                println!("entry: {}", e);
                return;
            }
        };
        println!("entry: {:?}", entry.path());
    }
}
