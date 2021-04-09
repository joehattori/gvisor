use std::ffi::CStr;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::os::raw::c_char;
use std::os::wasi::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use serde::{Deserialize, Serialize};

use crate::connection::ConnState;
use crate::fs::{Attr, AttrMask, FIDRef, File, FileMode, OpenFlags, SetAttr, SetAttrMask, FID};
use crate::unix;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct QIDType(pub u8);

impl QIDType {
    pub const DIR: Self = QIDType(0x80);
    pub const APPEND_ONLY: Self = QIDType(0x40);
    pub const EXCLUSIVE: Self = QIDType(0x20);
    pub const MOUNT: Self = QIDType(0x10);
    pub const AUTH: Self = QIDType(0x08);
    pub const TEMPORARY: Self = QIDType(0x04);
    pub const SYMLINK: Self = QIDType(0x02);
    pub const LINK: Self = QIDType(0x01);
    pub const REGULAR: Self = QIDType(0x00);

    pub fn from_file_type(file_type: fs::FileType) -> Self {
        if file_type.is_dir() {
            Self::DIR
        } else if file_type.is_socket_dgram()
            || file_type.is_socket_stream()
            || file_type.is_character_device()
        {
            Self::APPEND_ONLY
        } else if file_type.is_symlink() {
            Self::SYMLINK
        } else if file_type.is_file() {
            Self::REGULAR
        } else {
            panic!("unmatched. maybe named pipe?")
        }
    }
}

pub type UID = u32;
pub type GID = u32;

const NO_FID: u64 = u32::MAX as u64;
pub const NO_UID: u32 = u32::MAX;
// pub const NO_GID: u32 = u32::MAX;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct QID {
    pub typ: QIDType,
    pub version: u32,
    pub path: u64,
}

pub fn handle<T: serde_traitobject::Deserialize + Request>(mut msg: T) -> *const u8 {
    // TODO: get corresponding ConnState
    let cs = &*ConnState::get().lock().unwrap();
    let res = msg.handle(cs);
    serde_json::to_string(&res).unwrap().as_ptr()
}

pub trait Request {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any>;
}

#[derive(Serialize, Deserialize)]
pub struct Tlopen {
    pub fid: FID,
    pub flags: OpenFlags,
}
impl Tlopen {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tlopen {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
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
                let rlopen = Rlopen::new(qid, io_unit);
                // rlopen.set_file_payload(os_file);
                fid_ref.dec_ref();
                serde_traitobject::Box::new(rlopen)
            }
            Err(err) => {
                fid_ref.dec_ref();
                serde_traitobject::Box::new(Rlerror::new(extract_errno(err)))
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
impl Tauth {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tauth {
    // We don't support authentication, so this just returns ENOSYS.
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        serde_traitobject::Box::new(Rlerror::new(unix::ENOSYS))
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tclunk {
    fid: FID,
}
impl Tclunk {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tclunk {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        if !cs.delete_fid(&self.fid) {
            serde_traitobject::Box::new(Rlerror::new(unix::EBADF))
        } else {
            serde_traitobject::Box::new(Rclunk {})
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tsetattrclunk {
    fid: FID,
    valid: SetAttrMask,
    set_attr: SetAttr,
}
impl Tsetattrclunk {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tsetattrclunk {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        match cs.lookup_fid(&self.fid) {
            None => errno_to_serde_traitobject(unix::EBADF),
            Some(mut rf) => {
                // TODO: safetyWrite
                let set_attr_res = if rf.is_deleted() {
                    Err(Rlerror::new(unix::EINVAL))
                } else {
                    rf.file
                        .set_attr(self.valid, self.set_attr)
                        .map_err(|e| Rlerror::new(extract_errno(e)))
                };
                rf.dec_ref();
                if !cs.delete_fid(&self.fid) {
                    errno_to_serde_traitobject(unix::EBADF)
                } else {
                    match set_attr_res {
                        Ok(_) => serde_traitobject::Box::new(Rsetattrclunk {}),
                        Err(e) => serde_traitobject::Box::new(e),
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tremove {
    fid: FID,
}
impl Tremove {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tremove {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        match cs.lookup_fid(&self.fid) {
            None => errno_to_serde_traitobject(unix::EBADF),
            Some(rf) => {
                // TODO: safelyGlobal
                let res = if rf.is_root() || rf.is_deleted() {
                    Err(Rlerror::new(unix::EINVAL))
                } else {
                    let cloned = rf.clone();
                    let parent = rf.parent.unwrap();
                    let name = parent.path_node.name_for(&cloned);
                    match parent.file.unlink_at(&name, 0) {
                        Ok(_) => {
                            parent.mark_child_deleted(&name);
                            Ok(())
                        }
                        Err(e) => Err(Rlerror::new(extract_errno(e))),
                    }
                };
                if !cs.delete_fid(&self.fid) {
                    errno_to_serde_traitobject(unix::EBADF)
                } else {
                    match res {
                        Ok(_) => serde_traitobject::Box::new(Rremove {}),
                        Err(e) => serde_traitobject::Box::new(e),
                    }
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tattach {
    fid: FID,
    auth: Tauth,
}
impl Tattach {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tattach {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        if self.auth.authentication_fid != NO_FID {
            return errno_to_serde_traitobject(unix::EINVAL);
        }
        if Path::new(&self.auth.attach_name).is_absolute() {
            self.auth.attach_name = self.auth.attach_name[1..].to_string();
        }
        let mut file = match cs.server.attacher.attach() {
            Ok(f) => f,
            Err(errno) => return errno_to_serde_traitobject(extract_errno(errno)),
        };
        let (qid, valid, attr) = match file.get_attr(AttrMask::mask_all()) {
            Ok(v) => v,
            Err(errno) => {
                // file.close();
                return errno_to_serde_traitobject(extract_errno(errno));
            }
        };
        if !valid.file_mode {
            file.close();
            return errno_to_serde_traitobject(unix::EINVAL);
        }
        let mut root = FIDRef {
            is_deleted: AtomicBool::new(false),
            is_opened: false,
            open_flags: OpenFlags(0),
            file: file,
            parent: None,
            server: cs.server.clone(),
            refs: AtomicI64::new(1),
            mode: attr.file_mode.file_type(),
            path_node: cs.server.path_tree.clone(),
        };
        if self.auth.attach_name.is_empty() {
            cs.insert_fid(&self.fid, &mut root);
            return serde_traitobject::Box::new(Rattach { qid });
        }
        let (_, mut new_ref, _, _) =
            match do_walk(&cs, root, &Path::new(&self.auth.attach_name), false) {
                Ok(v) => v,
                Err(e) => return errno_to_serde_traitobject(extract_errno(e)),
            };
        cs.insert_fid(&self.fid, &mut new_ref);
        new_ref.dec_ref();
        serde_traitobject::Box::new(Rattach { qid })
    }
}

fn check_safe_name(name: &str) -> io::Result<()> {
    if name.is_empty() && name.contains("/") && name != "." && name != ".." {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            format!("check_safe_name: {}", name),
        ))
    }
}

fn do_walk(
    cs: &ConnState,
    rf: FIDRef,
    path: &Path,
    getattr: bool,
) -> io::Result<(Vec<QID>, FIDRef, AttrMask, Attr)> {
    let mut qids = Vec::new();
    let mut valid = AttrMask::default();
    let mut attr = Attr::default();
    for name in path.iter() {
        check_safe_name(name.to_str().unwrap())?
    }
    // TODO: safelyRead()
    if rf.is_opened {
        return Err(Error::new(ErrorKind::Other, "source busy."));
    }
    if path.iter().collect::<Vec<_>>().len() == 0 {
        // TODO: safelyRead()
        let (_, sf, valid_, attr_) = walk_one(vec![], rf.clone().file, vec![], getattr)?;
        valid = valid_;
        attr = attr_;
        let mut fid_ref = FIDRef {
            is_opened: false,
            open_flags: OpenFlags(0),
            refs: AtomicI64::new(0),
            server: cs.server.clone(),
            parent: rf.parent.clone(),
            file: sf,
            mode: rf.mode.clone(),
            path_node: rf.path_node.clone(),
            is_deleted: AtomicBool::new(rf.is_deleted()),
        };
        if !rf.is_root() {
            if !fid_ref.is_deleted() {
                let name = &rf.clone().parent.unwrap().path_node.name_for(&rf);
                rf.add_child_to_parent(&fid_ref, name);
            }
            rf.parent.unwrap().inc_ref();
        }
        fid_ref.inc_ref();
        return Ok((vec![], fid_ref, valid, attr));
    }
    let mut walk_ref = rf;
    walk_ref.inc_ref();
    for name in path.iter() {
        if !walk_ref.mode.is_dir() {
            walk_ref.dec_ref();
            return Err(Error::new(ErrorKind::InvalidData, "unix::EINVAL"));
        }
        // TODO: safelyRead
        let name = name.to_str().unwrap();
        let (qids_, sf, valid_, attr_) = walk_one(qids, walk_ref.clone().file, vec![name], true)
            .map_err(|e| {
                walk_ref.dec_ref();
                e
            })?;
        qids = qids_;
        valid = valid_;
        attr = attr_;
        let new_ref = FIDRef {
            is_deleted: AtomicBool::new(false),
            is_opened: false,
            open_flags: OpenFlags(0),
            refs: AtomicI64::new(0),
            server: cs.server.clone(),
            parent: Some(Box::new(walk_ref.clone())),
            file: sf,
            mode: attr.file_mode.clone(),
            path_node: walk_ref.path_node.path_node_for(name),
        };
        walk_ref.path_node.add_child(&new_ref, name);
        walk_ref = new_ref;
        walk_ref.inc_ref();
    }
    Ok((qids, walk_ref, valid, attr))
}

fn walk_one(
    mut qids: Vec<QID>,
    from: Box<dyn File>,
    names: Vec<&str>,
    getattr: bool,
) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)> {
    if names.len() > 1 {
        return Err(Error::new(ErrorKind::InvalidData, "unix::EINVAL"));
    }
    let mut local_qids = Vec::new();
    let mut valid = AttrMask::default();
    let mut attr = Attr::default();
    let mut sf = if getattr {
        // TODO: if err != unix::ENOSYS
        match from.walk_get_attr(names) {
            Ok(v) => {
                local_qids = v.0;
                valid = v.2;
                attr = v.3;
                v.1
            }
            Err(e) => return Err(Error::new(ErrorKind::InvalidData, format!("{}", e))),
        }
    } else {
        let res = from.walk(names)?;
        local_qids = res.0;
        let mut sf = res.1;
        if getattr {
            match sf.get_attr(AttrMask::mask_all()) {
                Ok(res) => {
                    valid = res.1;
                    attr = res.2;
                }
                Err(e) => {
                    sf.close();
                    return Err(Error::new(ErrorKind::Other, format!("{}", e)));
                }
            }
        }
        sf
    };
    if local_qids.len() != 1 {
        sf.close();
        Err(Error::new(ErrorKind::InvalidData, "unix::EINVAL"))
    } else {
        qids.append(&mut local_qids);
        Ok((qids, sf, valid, attr))
    }
}

#[derive(Serialize, Deserialize)]
pub struct Tlcreate {
    fid: FID,
    name: String,
    open_flags: OpenFlags,
    permissions: FileMode,
    gid: GID,
}

impl Tlcreate {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }

    fn perform(&self, cs: &ConnState, uid: UID) -> Result<Rlcreate, i32> {
        check_safe_name(&self.name).map_err(|_| unix::EINVAL)?;
        let mut rf = match cs.lookup_fid(&self.fid) {
            Some(rf) => rf,
            None => {
                return Err(unix::EBADF);
            }
        };
        // TODO: safelyWrite
        if rf.is_deleted() || !rf.mode.is_dir() || rf.is_opened {
            rf.dec_ref();
            Err(unix::EINVAL)
        } else {
            match rf
                .file
                .create(&self.name, self.open_flags, self.permissions, uid, self.gid)
            {
                Ok((os_file, nsf, qid, io_unit)) => {
                    let path_node = rf.path_node.path_node_for(&self.name);
                    let mut new_ref = FIDRef {
                        server: cs.server.clone(),
                        parent: Some(Box::new(rf.clone())),
                        file: nsf,
                        is_opened: true,
                        open_flags: self.open_flags,
                        mode: FileMode::regular(),
                        path_node: path_node,
                        is_deleted: AtomicBool::new(false),
                        refs: AtomicI64::new(0),
                    };
                    rf.add_child_to_path_node(&new_ref, &self.name);
                    rf.inc_ref();
                    cs.insert_fid(&self.fid, &mut new_ref);
                    // let file = None;
                    let mut rlcreate = Rlcreate {
                        rlopen: Rlopen { qid, io_unit },
                    };
                    // rlcreate.set_file_payload(os_file);
                    Ok(rlcreate)
                }
                Err(err) => {
                    rf.dec_ref();
                    Err(extract_errno(err))
                }
            }
        }
    }
}

impl Request for Tlcreate {
    fn handle(&mut self, cs: &ConnState) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
        let rlcreate = match self.perform(cs, NO_UID) {
            Ok(rlcreate) => rlcreate,
            Err(e) => return errno_to_serde_traitobject(e),
        };
        serde_traitobject::Box::new(rlcreate)
    }
}

pub trait Response: serde_traitobject::Serialize + serde_traitobject::Deserialize {}

// NEXT: here! do we need StdFile in Rlopen? maybe unneeded in a demo projec?
#[derive(Serialize, Deserialize)]
pub struct Rlopen {
    qid: QID,
    io_unit: u32,
}

impl Rlopen {
    pub fn new(qid: QID, io_unit: u32) -> Self {
        Rlopen { qid, io_unit }
    }

    //  pub fn set_file_payload(&mut self, fd: Option<StdFile>) {
    //      self.file = fd;
    //  }
}

impl Response for Rlopen {}

#[derive(Serialize, Deserialize)]
pub struct Rclunk {}
impl Response for Rclunk {}

#[derive(Serialize, Deserialize)]
pub struct Rsetattrclunk {}
impl Response for Rsetattrclunk {}

#[derive(Serialize, Deserialize)]
pub struct Rremove {}
impl Response for Rremove {}

#[derive(Serialize, Deserialize)]
pub struct Rattach {
    qid: QID,
}
impl Response for Rattach {}

#[derive(Serialize, Deserialize)]
pub struct Rlcreate {
    rlopen: Rlopen,
}
impl Response for Rlcreate {}
impl Rlcreate {
    //fn set_file_payload(&mut self, fd: Option<Fd>) {
    //    self.rlopen.set_file_payload(fd)
    //}
}

#[derive(Serialize, Deserialize)]
pub struct Rlerror {
    pub error: i32,
}

impl Rlerror {
    pub fn new(error: i32) -> Self {
        Rlerror { error }
    }
}

impl Response for Rlerror {}

fn extract_errno(err: Error) -> i32 {
    err.raw_os_error().unwrap_or(unix::EIO)
}

fn errno_to_serde_traitobject(errno: i32) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
    serde_traitobject::Box::new(Rlerror::new(errno))
}
