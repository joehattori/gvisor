use crate::fs::{OpenFlags, FID};

type QIDType = u8;

pub struct QID {
    typ: QIDType,
    version: u32,
    path: u64,
}

pub trait Message {}

pub struct Tlopen {
    pub fid: FID,
    pub flags: OpenFlags,
}

impl Message for Tlopen {}

pub struct Rlopen {
    qid: QID,
    io_unit: u32,
    fd: i32,
}

impl Rlopen {
    pub fn new(qid: QID, io_unit: u32) -> Self {
        Rlopen {
            qid,
            io_unit,
            fd: 0,
        }
    }

    pub fn set_file_payload(&mut self, fd: i32) {
        self.fd = fd;
    }
}

impl Message for Rlopen {}

pub struct Rlerror {
    pub error: u32,
}

impl Rlerror {
    pub fn new(error: u32) -> Self {
        Rlerror { error }
    }
}

impl Message for Rlerror {}
