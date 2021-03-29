use crate::connection::ConnState;

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

fn main() {
    match ConnState::init() {
        Ok(_) => (),
        Err(_) => panic!("ConnState initialized multiple times."),
    };
}
