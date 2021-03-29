use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::connection::ConnState;
use crate::fs::{OpenFlags, FID};

type QIDType = u8;

#[derive(Serialize, Deserialize)]
pub struct QID {
    typ: QIDType,
    version: u32,
    path: u64,
}

pub trait Request {
    fn handle(&self) -> serde_traitobject::Box<dyn serde_traitobject::Any>;
}

#[derive(Serialize, Deserialize)]
pub struct Tlopen {
    pub fid: FID,
    pub flags: OpenFlags,
}

impl Request for Tlopen {
    fn handle(&self) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        let cs = ConnState::get().lock().unwrap();
        let mut fid_ref = match cs.lookup_fid(&self.fid) {
            Some(r) => r,
            None => return serde_traitobject::Box::new(Rlerror::new(Rlerror::EBADF)),
        };
        // TODO: mutex
        if fid_ref.is_deleted.load(Ordering::Relaxed)
            || fid_ref.is_opened
            || !fid_ref.mode.can_open()
        {
            fid_ref.dec_ref();
            return serde_traitobject::Box::new(Rlerror::new(Rlerror::EINVAL));
        }
        if fid_ref.mode.is_dir() {
            if !self.flags.is_read_only() || self.flags.truncated_flag() != 0 {
                fid_ref.dec_ref();
                return serde_traitobject::Box::new(Rlerror::new(Rlerror::EISDIR));
            }
        }
        match fid_ref.file.open(self.flags) {
            Ok((os_file, qid, io_unit)) => {
                fid_ref.is_opened = true;
                fid_ref.open_flags = self.flags;
                let mut rlopen = Rlopen::new(qid, io_unit);
                rlopen.set_file_payload(os_file);
                fid_ref.dec_ref();
                serde_traitobject::Box::new(rlopen)
            }
            Err(errno) => {
                fid_ref.dec_ref();
                serde_traitobject::Box::new(Rlerror::new(errno))
            }
        }
    }
}

pub trait Response: serde_traitobject::Serialize + serde_traitobject::Deserialize {}

#[derive(Serialize, Deserialize)]
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

impl Response for Rlopen {}

#[derive(Serialize, Deserialize)]
pub struct Rlerror {
    pub error: u32,
}

impl Rlerror {
    pub const EINVAL: u32 = 0x16;
    pub const EISDIR: u32 = 0x15;
    pub const EBADF: u32 = 0x9;

    pub fn new(error: u32) -> Self {
        Rlerror { error }
    }
}

impl Response for Rlerror {}
