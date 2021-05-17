use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::os::raw::c_char;
use std::os::wasi::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use serde::{Deserialize, Serialize};

use crate::connection::{ConnState, Server, CONNECTIONS};
use crate::fs::{
    Attr, AttrMask, FIDRef, FileMode, LocalFile, OpenFlags, SetAttr, SetAttrMask, FID,
};
use crate::unix;
use crate::wasm_mem::embed_response_to_string;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let mut fid_ref = match cs.fids.get_mut(&self.fid) {
            Some(rf) => rf.inc_ref(),
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
            Ok((_, qid, io_unit)) => {
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let fids = &mut cs.fids;
        match fids.get_mut(&self.fid) {
            None => embed_response_to_string(Rlerror::new(unix::EBADF)),
            Some(rf) => {
                rf.inc_ref();
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let fids = &mut cs.fids;
        match fids.get_mut(&self.fid) {
            None => embed_response_to_string(Rlerror::new(unix::EBADF)),
            Some(rf) => {
                rf.inc_ref();
                // TODO: safelyGlobal
                let res = if rf.is_root() || rf.is_deleted() {
                    Err(Rlerror::new(unix::EINVAL))
                } else {
                    let cloned = rf.clone();
                    match rf.parent {
                        Some(ref parent) => {
                            let name = parent.path_node.name_for(&cloned);
                            match parent.file.unlink_at(&name, 0) {
                                Ok(_) => {
                                    parent.mark_child_deleted(&name);
                                    Ok(())
                                }
                                Err(e) => Err(Rlerror::new(extract_errno(e))),
                            }
                        }
                        None => panic!("no parent in Tremove"),
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let server = cs.server.clone();
        if self.auth.authentication_fid != NO_FID {
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        // if Path::new(&self.auth.attach_name).is_absolute() {
        if self.auth.attach_name.chars().next().unwrap() == '/' {
            self.auth.attach_name = self.auth.attach_name[1..].to_string();
        }
        let mut file = match server.attacher.attach() {
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
            file.close().expect("failed closing file");
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        let mut root = FIDRef {
            is_deleted: AtomicBool::new(false),
            is_open: false,
            open_flags: OpenFlags(0),
            file,
            parent: None,
            server: server.clone(),
            refs: AtomicI64::new(1),
            mode: attr.file_mode.file_type(),
            path_node: server.path_tree.clone(),
        };
        if self.auth.attach_name.is_empty() {
            insert_fid(&mut cs.fids, &self.fid, &mut root);
            root.dec_ref();
        } else {
            let names: Vec<String> = self
                .auth
                .attach_name
                .split('/')
                .map(|s| s.to_string())
                .collect();
            let (_, mut new_ref, _, _) = match do_walk(server, &mut root, names, false) {
                Ok(v) => v,
                Err(err) => return embed_response_to_string(Rlerror::from_err(err)),
            };
            insert_fid(&mut cs.fids, &self.fid, &mut new_ref);
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
    server: Server,
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
        println!("do_walk 0");
        let (_, sf, valid_, attr_) = walk_one(vec![], &mut rf.file, vec![], getattr)?;
        valid = valid_;
        attr = attr_;
        let mut new_ref = FIDRef {
            is_open: false,
            open_flags: OpenFlags(0),
            refs: AtomicI64::new(0),
            server,
            parent: rf.parent.clone(),
            file: sf,
            mode: rf.mode.clone(),
            path_node: rf.path_node.clone(),
            is_deleted: AtomicBool::new(rf.is_deleted()),
        };
        println!("do_walk 1");
        if !rf.is_root() {
            if !new_ref.is_deleted() {
                println!("do_walk 2");
                match rf.parent {
                    Some(ref parent) => {
                        println!("do_walk 3");
                        let name = parent.path_node.name_for(&rf);
                        println!("do_walk 4");
                        parent.path_node.add_child(&new_ref, &name);
                        println!("do_walk 5");
                    }
                    None => panic!("parent should exist"),
                }
            }
            println!("do_walk done");
            if let Some(ref mut parent) = rf.parent {
                parent.inc_ref();
            }
        }
        new_ref.inc_ref();
        println!("do_walk done");
        return Ok((vec![], Box::new(new_ref), valid, attr));
    }
    let mut walk_ref = Box::new(rf.clone());
    walk_ref.inc_ref();
    for name in names {
        if !walk_ref.mode.is_dir() {
            walk_ref.dec_ref();
            return Err(Error::new(ErrorKind::InvalidData, "unix::EINVAL"));
        }
        println!("do_walk 11");
        // TODO: safelyRead
        let (qids_, sf, valid_, attr_) = walk_one(qids, &mut walk_ref.file, vec![&name], true)
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
            server: server.clone(),
            // parent: Some(walk_ref.clone()),
            parent: Some(Box::new(*walk_ref.clone())),
            file: sf,
            mode: attr.file_mode.clone(),
            path_node: walk_ref.path_node.path_node_for(&name),
        };
        println!("do_walk 12");
        walk_ref.path_node.add_child(&new_ref, &name);
        walk_ref = Box::new(new_ref);
        walk_ref.inc_ref();
    }
    Ok((qids, walk_ref, valid, attr))
}

fn walk_one(
    mut qids: Vec<QID>,
    from: &mut LocalFile,
    names: Vec<&str>,
    getattr: bool,
) -> io::Result<(Vec<QID>, LocalFile, AttrMask, Attr)> {
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
                    sf.close().expect("failed closing file");
                    return Err(Error::new(ErrorKind::Other, format!("{}", e)));
                }
            }
        }
        sf
    };
    if local_qids.len() != 1 {
        sf.close().expect("failed closing file");
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let rlcreate = match self.tlcreate.perform(cs, NO_UID) {
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

    fn perform(&self, cs: &mut ConnState, uid: UID) -> Result<Rlcreate, i32> {
        check_safe_name(&self.name).map_err(|_| unix::EINVAL)?;
        let rf = match cs.fids.get_mut(&self.fid) {
            Some(rf) => rf.inc_ref(),
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
                    insert_fid(&mut cs.fids, &self.fid, &mut new_ref);
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let rlcreate = match self.perform(cs, NO_UID) {
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
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let server = cs.server.clone();
        let fids = &mut cs.fids;
        let mut fid_ref = match fids.get_mut(&self.fid) {
            Some(r) => r.inc_ref(),
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        let names = self.names.clone().unwrap_or(vec![]);
        println!("Twalk 1");
        match do_walk(server, &mut fid_ref, names, false) {
            Ok((qids, ref mut new_ref, _, _)) => {
                fid_ref.dec_ref();
                println!(
                    "Twalk: qid {:?}, host_path: {:?}",
                    fid_ref.file.qid, fid_ref.file.host_path
                );
                drop(fids);
                insert_fid(&mut cs.fids, &self.new_fid, new_ref);
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
        println!("Twalkgetattr 1");
        let mut c = CONNECTIONS.lock().unwrap();
        let cs = c
            .get_mut(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd));
        let server = cs.server.clone();
        let fids = &mut cs.fids;
        let mut fid_ref = match fids.get_mut(&self.fid) {
            Some(r) => r.inc_ref(),
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        println!("Twalkgetattr 2");
        match do_walk(server, &mut fid_ref, self.names.clone(), true) {
            Ok((qids, ref mut new_ref, valid, attr)) => {
                fid_ref.dec_ref();
                drop(fids);
                let fids = &mut cs.fids;
                insert_fid(fids, &self.new_fid, new_ref);
                new_ref.dec_ref();
                embed_response_to_string(Rwalkgetattr { qids, valid, attr })
            }
            Err(err) => {
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

pub fn insert_fid(fids: &mut HashMap<FID, FIDRef>, fid: &FID, new_ref: &mut FIDRef) {
    let parent_path = match new_ref.parent.clone() {
        Some(p) => p.file.host_path,
        None => "NONE".to_string(),
    };
    println!(
        "inserting fid: {}, path: {}, qid: {:?}, parent_path: {}",
        fid, new_ref.file.host_path, new_ref.file.qid, parent_path,
    );
    new_ref.inc_ref();
    if let Some(mut orig) = fids.insert(*fid, new_ref.clone()) {
        orig.dec_ref();
    }
}
