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
use crate::wasm_mem::embed_response_to_string;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct QID {
    pub typ: QIDType,
    pub version: u32,
    pub path: u64,
}

pub trait Request {
    // JOETODO: hold response type as trait type. e.g. Twalk <-> Rwalk
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
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        // TODO: mutex
        if fid_ref.is_deleted.load(Ordering::Relaxed) || fid_ref.is_open || !fid_ref.mode.can_open()
        {
            fid_ref.dec_ref();
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        // TODO: mutex
        if fid_ref.mode.is_dir() {
            if !self.flags.is_read_only() || self.flags.truncated_flag() != 0 {
                fid_ref.dec_ref();
                return embed_response_to_string(Rlerror::new(unix::EISDIR));
            }
        }
        match fid_ref.file.open(self.flags) {
            Ok((os_file, qid, io_unit)) => {
                fid_ref.is_open = true;
                fid_ref.open_flags = self.flags;
                let rlopen = Rlopen::new(qid, io_unit);
                // rlopen.set_file_payload(os_file);
                fid_ref.dec_ref();
                embed_response_to_string(rlopen)
            }
            Err(err) => {
                fid_ref.dec_ref();
                embed_response_to_string(Rlerror::from_err(err))
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
        embed_response_to_string(Rlerror::new(unix::ENOSYS))
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
            embed_response_to_string(Rlerror::new(unix::EBADF))
        } else {
            embed_response_to_string(Rclunk {})
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
            None => embed_response_to_string(Rlerror::new(unix::EBADF)),
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
                    embed_response_to_string(Rlerror::new(unix::EBADF))
                } else {
                    match set_attr_res {
                        Ok(_) => embed_response_to_string(Rsetattrclunk {}),
                        Err(err) => embed_response_to_string(err),
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
            None => embed_response_to_string(Rlerror::new(unix::EBADF)),
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
                    embed_response_to_string(Rlerror::new(unix::EBADF))
                } else {
                    match res {
                        Ok(_) => embed_response_to_string(Rremove {}),
                        Err(err) => embed_response_to_string(err),
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
        if self.auth.authentication_fid != NO_FID {
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        // if Path::new(&self.auth.attach_name).is_absolute() {
        if self.auth.attach_name.chars().next().unwrap() == '/' {
            self.auth.attach_name = self.auth.attach_name[1..].to_string();
        }
        let mut file = match cs.server.attacher.attach() {
            Ok(f) => f,
            Err(err) => return embed_response_to_string(Rlerror::from_err(err)),
        };
        let (qid, valid, attr) = match file.get_attr(AttrMask::mask_all()) {
            Ok(v) => v,
            Err(errno) => {
                // file.close();
                return embed_response_to_string(Rlerror::from_err(errno));
            }
        };
        if !valid.file_mode {
            file.close();
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        let mut root = FIDRef {
            is_deleted: AtomicBool::new(false),
            is_open: false,
            open_flags: OpenFlags(0),
            file,
            parent: None,
            server: cs.server.clone(),
            refs: AtomicI64::new(1),
            mode: attr.file_mode.file_type(),
            path_node: cs.server.path_tree.clone(),
        };
        if self.auth.attach_name.is_empty() {
            cs.insert_fid(&self.fid, &mut root);
            root.dec_ref();
        } else {
            let names: Vec<String> = self
                .auth
                .attach_name
                .split('/')
                .map(|s| s.to_string())
                .collect();
            let (_, mut new_ref, _, _) = match do_walk(&cs, &mut root, names, false) {
                Ok(v) => v,
                Err(err) => return embed_response_to_string(Rlerror::from_err(err)),
            };
            cs.insert_fid(&self.fid, &mut new_ref);
            new_ref.dec_ref();
            root.dec_ref();
        };
        embed_response_to_string(Rattach::from_qid(qid))
    }
}

fn check_safe_name(name: &str) -> io::Result<()> {
    if !name.is_empty() && !name.contains("/") && name != "." && name != ".." {
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
    rf: &mut FIDRef,
    names: Vec<String>,
    getattr: bool,
) -> io::Result<(Vec<QID>, Box<FIDRef>, AttrMask, Attr)> {
    let mut qids = Vec::new();
    let mut valid = AttrMask::default();
    let mut attr = Attr::default();
    for name in &names {
        check_safe_name(name)?
    }
    // TODO: safelyRead()
    if rf.is_open {
        return Err(Error::new(ErrorKind::Other, "source busy."));
    }
    if names.len() == 0 {
        // TODO: safelyRead()
        let (_, sf, valid_, attr_) = walk_one(vec![], rf.clone().file, vec![], getattr)?;
        valid = valid_;
        attr = attr_;
        let mut fid_ref = FIDRef {
            is_open: false,
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
            if let Some(ref mut parent) = rf.parent {
                parent.inc_ref();
            }
        }
        fid_ref.inc_ref();
        return Ok((vec![], Box::new(fid_ref), valid, attr));
    }
    let mut walk_ref = Box::new(rf.clone());
    walk_ref.inc_ref();
    for name in names {
        if !walk_ref.mode.is_dir() {
            walk_ref.dec_ref();
            return Err(Error::new(ErrorKind::InvalidData, "unix::EINVAL"));
        }
        // TODO: safelyRead
        let (qids_, sf, valid_, attr_) = walk_one(qids, walk_ref.clone().file, vec![&name], true)
            .map_err(|e| {
            walk_ref.dec_ref();
            e
        })?;
        qids = qids_;
        valid = valid_;
        attr = attr_;
        let new_ref = FIDRef {
            is_deleted: AtomicBool::new(false),
            is_open: false,
            open_flags: OpenFlags(0),
            refs: AtomicI64::new(0),
            server: cs.server.clone(),
            parent: Some(walk_ref.clone()),
            file: sf,
            mode: attr.file_mode.clone(),
            path_node: walk_ref.path_node.path_node_for(&name),
        };
        walk_ref.path_node.add_child(&new_ref, &name);
        walk_ref = Box::new(new_ref);
        walk_ref.inc_ref();
    }
    Ok((qids, walk_ref, valid, attr))
}

fn walk_one(
    mut qids: Vec<QID>,
    mut from: Box<dyn File>,
    names: Vec<&str>,
    getattr: bool,
) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)> {
    if names.len() > 1 {
        println!("walk_one 0");
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
            Err(e) => {
                println!("walk_one 1 {}", e);
                return Err(Error::new(ErrorKind::InvalidData, format!("{}", e)));
            }
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
                    println!("walk_one 2");
                    return Err(Error::new(ErrorKind::Other, format!("{}", e)));
                }
            }
        }
        sf
    };
    if local_qids.len() != 1 {
        sf.close();
        println!("walk_one 3");
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
            Err(errno) => return embed_response_to_string(Rlerror::new(errno)),
        };
        embed_response_to_string(Rucreate { rlcreate })
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
        if rf.is_deleted() || !rf.mode.is_dir() || rf.is_open {
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
                        is_open: true,
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
            Err(errno) => return embed_response_to_string(Rlerror::new(errno)),
        };
        embed_response_to_string(rlcreate)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Twalk {
    fid: FID,
    new_fid: FID,
    names: Option<Vec<String>>,
}
impl Twalk {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Twalk {
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        let mut fid_ref = match cs.lookup_fid(&self.fid) {
            Some(r) => r,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        let names = self.names.clone().unwrap_or(vec![]);
        match do_walk(&cs, &mut fid_ref, names, false) {
            Ok((qids, mut new_ref, _, _)) => {
                cs.insert_fid(&self.new_fid, &mut new_ref);
                fid_ref.dec_ref();
                new_ref.dec_ref();
                embed_response_to_string(Rwalk { qids })
            }
            Err(err) => {
                fid_ref.dec_ref();
                embed_response_to_string(Rlerror::from_err(err))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Twalkgetattr {
    fid: FID,
    new_fid: FID,
    names: Vec<String>,
}
impl Twalkgetattr {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Twalkgetattr {
    fn handle(&mut self, io_fd: i32) -> *const u8 {
        let cs = ConnState::get_conn_state(io_fd);
        let mut fid_ref = match cs.lookup_fid(&self.fid) {
            Some(r) => r,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        match do_walk(&cs, &mut fid_ref, self.names.clone(), true) {
            Ok((qids, mut new_ref, valid, attr)) => {
                cs.insert_fid(&self.new_fid, &mut new_ref);
                fid_ref.dec_ref();
                new_ref.dec_ref();
                embed_response_to_string(Rwalkgetattr { qids, valid, attr })
            }
            Err(err) => {
                println!("Twalkgetattr failed");
                fid_ref.dec_ref();
                embed_response_to_string(Rlerror::from_err(err))
            }
        }
    }
}

pub trait Response: serde_traitobject::Serialize + serde_traitobject::Deserialize {}

// NEXT: here! do we need OsFile in Rlopen? maybe unneeded in a demo projec?
#[derive(Serialize, Deserialize)]
pub struct Rlopen {
    qid: QID,
    io_unit: u32,
}

impl Rlopen {
    pub fn new(qid: QID, io_unit: u32) -> Self {
        Rlopen { qid, io_unit }
    }

    //  pub fn set_file_payload(&mut self, fd: Option<OsFile>) {
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
impl Response for Rattach {}

#[derive(Serialize, Deserialize)]
pub struct Rlcreate {
    rlopen: Rlopen,
}
impl Rlcreate {
    //fn set_file_payload(&mut self, fd: Option<Fd>) {
    //    self.rlopen.set_file_payload(fd)
    //}
}
impl Response for Rlcreate {}

#[derive(Serialize, Deserialize)]
pub struct Rucreate {
    rlcreate: Rlcreate,
}
impl Response for Rucreate {}

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

impl Response for Rlerror {}

#[derive(Serialize, Deserialize)]
pub struct Rwalk {
    qids: Vec<QID>,
}
impl Response for Rwalk {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rwalkgetattr {
    valid: AttrMask,
    attr: Attr,
    qids: Vec<QID>,
}
impl Response for Rwalkgetattr {}

fn extract_errno(err: Error) -> i32 {
    err.raw_os_error().unwrap_or(unix::EIO)
}
