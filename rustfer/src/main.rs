use crate::connection::ConnState;

mod api;
mod connection;
mod fs;
mod message;

fn main() {
    match ConnState::init() {
        Ok(_) => (),
        Err(_) => panic!("ConnState is initialized multiple times."),
    };
}
