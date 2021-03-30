use std::path::Path;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::connection::ConnState;
use crate::fs::{OpenFlags, FID};
use crate::unix;

#[derive(Serialize, Deserialize, Clone)]
pub struct QIDType(pub u8);

impl QIDType {
    pub const DIR: Self = QIDType(0x80);
    pub const APPEND_ONLY: Self = QIDType(0x40);
    pub const EXCLUSIVE: Self = QIDType(0x20);
    pub const MOUNT: Self = QIDType(0x10);
    pub const Auth: Self = QIDType(0x08);
    pub const TEMPORARY: Self = QIDType(0x04);
    pub const SYMLINK: Self = QIDType(0x02);
    pub const LINK: Self = QIDType(0x01);
    pub const REGULAR: Self = QIDType(0x00);
}

type UID = u32;

const NO_FID: u64 = u32::MAX as u64;

#[derive(Serialize, Deserialize, Clone)]
pub struct QID {
    pub typ: QIDType,
    pub version: u32,
    pub path: u64,
}

pub trait Request {
    fn handle(&self, cs: ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any>;
}

#[derive(Serialize, Deserialize)]
pub struct Tlopen {
    pub fid: FID,
    pub flags: OpenFlags,
}

impl Request for Tlopen {
    fn handle(&self, cs: ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        let cs = ConnState::get().lock().unwrap();
        let mut fid_ref = match cs.lookup_fid(&self.fid) {
            Some(r) => r,
            None => return serde_traitobject::Box::new(Rlerror::new(unix::EBADF)),
        };
        // TODO: mutex
        if fid_ref.is_deleted.load(Ordering::Relaxed)
            || fid_ref.is_opened
            || !fid_ref.mode.can_open()
        {
            fid_ref.dec_ref();
            return serde_traitobject::Box::new(Rlerror::new(unix::EINVAL));
        }
        if fid_ref.mode.is_dir() {
            if !self.flags.is_read_only() || self.flags.truncated_flag() != 0 {
                fid_ref.dec_ref();
                return serde_traitobject::Box::new(Rlerror::new(unix::EISDIR));
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

#[derive(Serialize, Deserialize)]
pub struct Tauth {
    authentication_fid: FID,
    user_name: String,
    attach_name: String,
    uid: UID,
}

impl Request for Tauth {
    // We don't support authentication, so this just returns ENOSYS.
    fn handle(&self, cs: ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        serde_traitobject::Box::new(Rlerror::new(unix::ENOSYS))
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tattach {
    fid: FID,
    auth: Tauth,
}

impl Request for Tattach {
    fn handle(&self, cs: ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        if self.auth.authentication_fid != NO_FID {
            return serde_traitobject::Box::new(Rlerror::new(unix::EINVAL));
        }
        if Path::new(&self.auth.attach_name).is_absolute() {
            self.auth.attach_name = self.auth.attach_name[1..].to_string();
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
    pub fn new(error: u32) -> Self {
        Rlerror { error }
    }
}

impl Response for Rlerror {}
