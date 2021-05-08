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

pub trait Request {
    fn handle(&mut self, io_fd: i32) -> *const u8;
}

#[derive(Debug, Serialize, Deserialize)]
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
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        let mut fid_ref = match cs.lookup_fid(&self.fid) {
            Some(r) => r,
            None => return Rlerror::new(unix::EBADF).to_json_ptr(),
        };
        // TODO: mutex
        if fid_ref.is_deleted.load(Ordering::Relaxed)
            || fid_ref.is_opened
            || !fid_ref.mode.can_open()
        {
            fid_ref.dec_ref();
            return Rlerror::new(unix::EINVAL).to_json_ptr();
        }
        // TODO: mutex
        if fid_ref.mode.is_dir() {
            if !self.flags.is_read_only() || self.flags.truncated_flag() != 0 {
                fid_ref.dec_ref();
                return Rlerror::new(unix::EISDIR).to_json_ptr();
            }
        }
        match fid_ref.file.open(self.flags) {
            Ok((os_file, qid, io_unit)) => {
                fid_ref.is_opened = true;
                fid_ref.open_flags = self.flags;
                let rlopen = Rlopen::new(qid, io_unit);
                // rlopen.set_file_payload(os_file);
                fid_ref.dec_ref();
                rlopen.to_json_ptr()
            }
            Err(err) => {
                fid_ref.dec_ref();
                Rlerror::from_err(err).to_json_ptr()
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
    fn handle(&mut self, _: i32) -> *const u8 {
        Rlerror::new(unix::ENOSYS).to_json_ptr()
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
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        if !cs.delete_fid(&self.fid) {
            Rlerror::new(unix::EBADF).to_json_ptr()
        } else {
            Rclunk {}.to_json_ptr()
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
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        match cs.lookup_fid(&self.fid) {
            None => Rlerror::new(unix::EBADF).to_json_ptr(),
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
                    Rlerror::new(unix::EBADF).to_json_ptr()
                } else {
                    match set_attr_res {
                        Ok(_) => Rsetattrclunk {}.to_json_ptr(),
                        Err(err) => err.to_json_ptr(),
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
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        match cs.lookup_fid(&self.fid) {
            None => Rlerror::new(unix::EBADF).to_json_ptr(),
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
                    Rlerror::new(unix::EBADF).to_json_ptr()
                } else {
                    match res {
                        Ok(_) => Rremove {}.to_json_ptr(),
                        Err(err) => err.to_json_ptr(),
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        println!("Tattach 1");
        if self.auth.authentication_fid != NO_FID {
            return Rlerror::new(unix::EINVAL).to_json_ptr();
        }
        println!("Tattach 2");
        if Path::new(&self.auth.attach_name).is_absolute() {
            self.auth.attach_name = self.auth.attach_name[1..].to_string();
        }
        println!("Tattach 3");
        let mut file = match cs.server.attacher.attach() {
            Ok(f) => f,
            Err(err) => return Rlerror::from_err(err).to_json_ptr(),
        };
        println!("Tattach 4");
        let (qid, valid, attr) = match file.get_attr(AttrMask::mask_all()) {
            Ok(v) => v,
            Err(errno) => {
                // file.close();
                return Rlerror::from_err(errno).to_json_ptr();
            }
        };
        println!("Tattach 5");
        if !valid.file_mode {
            file.close();
            return Rlerror::new(unix::EINVAL).to_json_ptr();
        }
        println!("Tattach 6");
        let mut root = FIDRef {
            is_deleted: AtomicBool::new(false),
            is_opened: false,
            open_flags: OpenFlags(0),
            file,
            parent: None,
            server: cs.server.clone(),
            refs: AtomicI64::new(1),
            mode: attr.file_mode.file_type(),
            path_node: cs.server.path_tree.clone(),
        };
        println!("Tattach 7");
        if self.auth.attach_name.is_empty() {
            cs.insert_fid(&self.fid, &mut root);
            println!("Tattach 8");
            root.dec_ref();
        } else {
            let (_, mut new_ref, _, _) =
                match do_walk(&cs, root.clone(), &Path::new(&self.auth.attach_name), false) {
                    Ok(v) => v,
                    Err(err) => return Rlerror::from_err(err).to_json_ptr(),
                };
            cs.insert_fid(&self.fid, &mut new_ref);
            new_ref.dec_ref();
            root.dec_ref();
            println!("Tattach 9");
        }
        println!("Tattach 10");
        Rattach::from_qid(qid).to_json_ptr()
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
pub struct Tucreate {
    tlcreate: Tlcreate,
    uid: UID,
}
impl Tucreate {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tucreate {
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        let rlcreate = match self.tlcreate.perform(&cs, NO_UID) {
            Ok(rlcreate) => rlcreate,
            Err(errno) => return Rlerror::new(errno).to_json_ptr(),
        };
        Rucreate { rlcreate }.to_json_ptr()
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
            None => return Err(unix::EBADF),
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
                        path_node,
                        is_deleted: AtomicBool::new(false),
                        refs: AtomicI64::new(0),
                    };
                    rf.add_child_to_path_node(&new_ref, &self.name);
                    rf.inc_ref();
                    cs.insert_fid(&self.fid, &mut new_ref);
                    // let file = None;
                    let rlcreate = Rlcreate {
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
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        let rlcreate = match self.perform(&cs, NO_UID) {
            Ok(rlcreate) => rlcreate,
            Err(errno) => return Rlerror::new(errno).to_json_ptr(),
        };
        rlcreate.to_json_ptr()
    }
}

pub trait Response: serde_traitobject::Serialize + serde_traitobject::Deserialize {
    fn to_json_ptr(&self) -> *const u8;
}

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
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

impl Response for Rlopen {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rclunk {}
impl Response for Rclunk {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rsetattrclunk {}
impl Response for Rsetattrclunk {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rremove {}
impl Response for Rremove {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rattach {
    // embedding QID. need this to match Go implementation in pkg/p9.
    pub typ: QIDType,
    pub version: u32,
    pub path: u64,
}
impl Rattach {
    fn from_qid(qid: QID) -> Self {
        Self {
            typ: qid.typ,
            version: qid.version,
            path: qid.path,
        }
    }
}
impl Response for Rattach {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rlcreate {
    rlopen: Rlopen,
}
impl Rlcreate {
    //fn set_file_payload(&mut self, fd: Option<Fd>) {
    //    self.rlopen.set_file_payload(fd)
    //}
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rucreate {
    rlcreate: Rlcreate,
}
impl Response for Rucreate {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Rlerror {
    pub error: i32,
}

impl Rlerror {
    pub fn new(error: i32) -> Self {
        Self { error }
    }

    fn from_err(err: Error) -> Self {
        Self {
            error: extract_errno(err),
        }
    }
}

impl Response for Rlerror {
    fn to_json_ptr(&self) -> *const u8 {
        serde_json::to_string(self)
            .expect("failed to convert to json.")
            .as_ptr()
    }
}

fn extract_errno(err: Error) -> i32 {
    err.raw_os_error().unwrap_or(unix::EIO)
}

fn errno_to_serde_traitobject(errno: i32) -> serde_traitobject::Box<dyn serde_traitobject::Any> {
    serde_traitobject::Box::new(Rlerror::new(errno))
}
