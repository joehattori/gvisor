use std::ffi::CStr;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::os::{raw::c_char, wasi::prelude::*};
use std::sync::{
    atomic::{AtomicBool, AtomicI64},
    Arc, Mutex,
};

use serde::{Deserialize, Serialize};

use crate::connection::{ConnState, Server};
use crate::fs::{
    Attr, AttrMask, FIDEntry, FIDRef, FileMode, LocalFile, OpenFlags, SetAttr, SetAttrMask, FID,
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
pub const NO_GID: u32 = u32::MAX;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QID {
    pub typ: QIDType,
    pub version: u32,
    pub path: u64,
}

pub trait Request {
    // JOETODO: hold response type as trait type. e.g. Twalk <-> Rwalk
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tlopen {
    pub fid: FID,
    pub flags: OpenFlags,
}
impl Tlopen {
    // JOETODO: put this method outside and delete other from_ptr() s to make it DRY.
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(&msg).unwrap()
    }
}

impl Request for Tlopen {
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tlopen requested");
        let mut fid_ref = match cs.lock().unwrap().lookup_fid(self.fid) {
            Some(v) => v,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        // TODO: mutex
        let mut entry = fid_ref.0.lock().unwrap();
        if *entry.is_deleted.get_mut() || entry.is_open || !entry.mode.can_open() {
            drop(entry);
            fid_ref.dec_ref();
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        // TODO: mutex
        if entry.mode.is_dir() {
            if !self.flags.is_read_only() || self.flags.truncated_flag() != 0 {
                drop(entry);
                fid_ref.dec_ref();
                return embed_response_to_string(Rlerror::new(unix::EISDIR));
            }
        }
        match entry.file.open(self.flags) {
            Ok((_, qid, io_unit)) => {
                entry.is_open = true;
                entry.open_flags = self.flags;
                drop(entry);
                fid_ref.dec_ref();
                let rlopen = Rlopen::new(qid, io_unit);
                // rlopen.set_file_payload(os_file);
                embed_response_to_string(rlopen)
            }
            Err(err) => {
                drop(entry);
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
    fn handle(&mut self, _: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tauth requested");
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
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tclunk requested");
        if !cs.lock().unwrap().delete_fid(&self.fid) {
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
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tsetattrclunk requested");
        let mut cs = cs.lock().unwrap();
        match cs.lookup_fid(self.fid) {
            None => embed_response_to_string(Rlerror::new(unix::EBADF)),
            Some(mut rf) => {
                rf.inc_ref();
                // TODO: safetyWrite
                let mut entry = rf.0.lock().unwrap();
                let set_attr_res = if entry.is_deleted() {
                    Err(Rlerror::new(unix::EINVAL))
                } else {
                    entry
                        .file
                        .set_attr(self.valid, self.set_attr)
                        .map_err(|e| Rlerror::new(extract_errno(e)))
                };
                drop(entry);
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
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tremove requested");
        let mut cs = cs.lock().unwrap();
        match cs.lookup_fid(self.fid) {
            None => embed_response_to_string(Rlerror::new(unix::EBADF)),
            Some(mut rf) => {
                rf.inc_ref();
                // TODO: safelyGlobal
                let entry = rf.0.lock().unwrap();
                let res = if entry.is_root() || entry.is_deleted() {
                    Err(Rlerror::new(unix::EINVAL))
                } else {
                    match entry.parent.clone() {
                        Some(parent) => {
                            let parent_entry = parent.0.lock().unwrap();
                            let name = parent_entry.path_node.name_for(rf.clone());
                            match parent_entry.file.unlink_at(&name, 0) {
                                Ok(_) => {
                                    parent_entry.mark_child_deleted(&name);
                                    Ok(())
                                }
                                Err(e) => Err(Rlerror::new(extract_errno(e))),
                            }
                        }
                        None => panic!("no parent in Tremove"),
                    }
                };
                drop(entry);
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
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tattach requested");
        let mut cs = cs.lock().unwrap();
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
                file.close().expect("failed closing file");
                return embed_response_to_string(Rlerror::from_err(errno));
            }
        };
        if !valid.file_mode {
            file.close().expect("failed closing file");
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        let entry = FIDEntry {
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
        let mut root = FIDRef::from_entry(entry);
        if self.auth.attach_name.is_empty() {
            cs.insert_fid(self.fid, root.clone());
        } else {
            let names: Vec<String> = self
                .auth
                .attach_name
                .split('/')
                .map(|s| s.to_string())
                .collect();
            let (_, new_ref, _, _) = match do_walk(server, root.clone(), names, false) {
                Ok(v) => v,
                Err(err) => return embed_response_to_string(Rlerror::from_err(err)),
            };
            cs.insert_fid(self.fid, new_ref);
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
    rf: FIDRef,
    names: Vec<String>,
    getattr: bool,
) -> io::Result<(Vec<QID>, FIDRef, AttrMask, Attr)> {
    let mut qids = Vec::new();
    let mut valid = AttrMask::default();
    let mut attr = Attr::default();
    for name in &names {
        check_safe_name(name)?
    }
    // TODO: safelyRead()
    let mut entry = rf.0.lock().unwrap();
    if entry.is_open {
        return Err(Error::new(ErrorKind::Other, "source busy."));
    }
    if names.len() == 0 {
        // TODO: safelyRead()
        println!("do_walk name len 0");
        let (_, sf, valid_, attr_) = walk_one(vec![], &mut entry.file, vec![], getattr)?;
        valid = valid_;
        attr = attr_;
        let mut new_ref = FIDRef::from_entry(FIDEntry {
            is_open: false,
            open_flags: OpenFlags(0),
            refs: AtomicI64::new(0),
            server,
            parent: entry.parent.clone().map(|p| p.clone()),
            file: sf,
            mode: entry.mode.clone(),
            path_node: entry.path_node.clone(),
            is_deleted: AtomicBool::new(entry.is_deleted()),
        });
        if !entry.is_root() {
            let mut parent = entry.parent.clone().expect("parent should exist");
            let is_deleted = {
                let e = new_ref.0.lock().unwrap();
                e.is_deleted()
            };
            if !is_deleted {
                let parent_entry = parent.0.lock().unwrap();
                let name = parent_entry.path_node.name_for(rf.clone());
                parent_entry.path_node.add_child(new_ref.clone(), &name);
            }
            parent.inc_ref();
        }
        new_ref.inc_ref();
        return Ok((vec![], new_ref, valid, attr));
    }
    println!("do_walk name len not 0");
    drop(entry);
    let mut walk_ref = rf;
    walk_ref.inc_ref();
    for name in names {
        let mut walk_ref_entry = walk_ref.0.lock().unwrap();
        if !walk_ref_entry.mode.is_dir() {
            drop(walk_ref_entry);
            walk_ref.dec_ref();
            return Err(Error::new(ErrorKind::InvalidData, "unix::EINVAL"));
        }
        // TODO: safelyRead
        let (qids_, sf, valid_, attr_) =
            match walk_one(qids, &mut walk_ref_entry.file, vec![&name], true) {
                Ok(v) => v,
                Err(e) => {
                    drop(walk_ref_entry);
                    walk_ref.dec_ref();
                    return Err(e);
                }
            };
        qids = qids_;
        valid = valid_;
        attr = attr_;
        let new_ref = FIDRef::from_entry(FIDEntry {
            is_deleted: AtomicBool::new(false),
            is_open: false,
            open_flags: OpenFlags(0),
            refs: AtomicI64::new(0),
            server: server.clone(),
            parent: Some(walk_ref.clone()),
            file: sf,
            mode: attr.file_mode.clone(),
            path_node: walk_ref_entry.path_node.path_node_for(&name),
        });
        walk_ref_entry.path_node.add_child(new_ref.clone(), &name);
        drop(walk_ref_entry);
        walk_ref = new_ref;
        walk_ref.inc_ref();
    }
    println!("do_walk done: {:?}", walk_ref);
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
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tucreate requested");
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

    fn perform(&self, cs: Arc<Mutex<ConnState>>, uid: UID) -> Result<Rlcreate, i32> {
        check_safe_name(&self.name).map_err(|_| unix::EINVAL)?;
        let mut cs = cs.lock().unwrap();
        let mut rf = match cs.lookup_fid(self.fid) {
            Some(v) => v,
            None => return Err(unix::EBADF),
        };
        // TODO: safelyWrite
        let mut entry = rf.0.lock().unwrap();
        if entry.is_deleted() || !entry.mode.is_dir() || entry.is_open {
            drop(entry);
            rf.dec_ref();
            Err(unix::EINVAL)
        } else {
            match entry
                .file
                .create(&self.name, self.open_flags, self.permissions, uid, self.gid)
            {
                Ok((os_file, nsf, qid, io_unit)) => {
                    let path_node = entry.path_node.path_node_for(&self.name);
                    let new_ref_entry = FIDEntry {
                        server: cs.server.clone(),
                        parent: Some(rf.clone()),
                        file: nsf,
                        is_open: true,
                        open_flags: self.open_flags,
                        mode: FileMode::regular(),
                        path_node,
                        is_deleted: AtomicBool::new(false),
                        refs: AtomicI64::new(0),
                    };
                    let new_ref = FIDRef::from_entry(new_ref_entry);
                    entry.path_node.add_child(new_ref.clone(), &self.name);
                    drop(entry);
                    rf.inc_ref();
                    cs.insert_fid(self.fid, new_ref);
                    // let file = None;
                    let rlcreate = Rlcreate {
                        rlopen: Rlopen { qid, io_unit },
                    };
                    // rlcreate.set_file_payload(os_file);
                    Ok(rlcreate)
                }
                Err(err) => {
                    drop(entry);
                    rf.dec_ref();
                    Err(extract_errno(err))
                }
            }
        }
    }
}

impl Request for Tlcreate {
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tlcreate requested");
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
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Twalk requested");
        let mut cs = cs.lock().unwrap();
        let server = cs.server.clone();
        let mut fid_ref = match cs.lookup_fid(self.fid) {
            Some(v) => v,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        let names = self.names.clone().unwrap_or(vec![]);
        match do_walk(server, fid_ref.clone(), names, false) {
            Ok((qids, new_ref, _, _)) => {
                fid_ref.dec_ref();
                cs.insert_fid(self.new_fid, new_ref);
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
        serde_json::from_str(msg).unwrap()
    }
}

impl Request for Twalkgetattr {
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Twalkgetattr requested");
        let mut cs = cs.lock().unwrap();
        let server = cs.server.clone();
        let mut fid_ref = match cs.lookup_fid(self.fid) {
            Some(v) => v,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        match do_walk(server, fid_ref.clone(), self.names.clone(), true) {
            Ok((qids, mut new_ref, valid, attr)) => {
                cs.insert_fid(self.new_fid, new_ref.clone());
                new_ref.dec_ref();
                fid_ref.dec_ref();
                embed_response_to_string(Rwalkgetattr { qids, valid, attr })
            }
            Err(err) => {
                fid_ref.dec_ref();
                embed_response_to_string(Rlerror::from_err(err))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tgetattr {
    fid: FID,
    attr_mask: AttrMask,
}
impl Tgetattr {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(msg).unwrap()
    }
}

impl Request for Tgetattr {
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tgetattr requested");
        let mut fid_ref = match cs.lock().unwrap().lookup_fid(self.fid) {
            Some(v) => v,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };

        // JOETODO: safelyRead
        let mut entry = fid_ref.0.lock().unwrap();
        match entry.file.get_attr(self.attr_mask) {
            Ok((qid, valid, attr)) => {
                drop(entry);
                fid_ref.dec_ref();
                embed_response_to_string(Rgetattr { qid, valid, attr })
            }
            Err(e) => {
                drop(entry);
                fid_ref.dec_ref();
                embed_response_to_string(Rlerror::from_err(e))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tgetxattr {
    fid: FID,
    name: String,
    size: u64,
}
impl Tgetxattr {
    pub fn from_ptr(msg: *mut c_char) -> Box<Self> {
        let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
        serde_json::from_str(msg).unwrap()
    }
}

impl Request for Tgetxattr {
    fn handle(&mut self, cs: Arc<Mutex<ConnState>>) -> *const u8 {
        println!("Tgetxattr requested");
        let mut fid_ref = match cs.lock().unwrap().lookup_fid(self.fid) {
            Some(v) => v,
            None => return embed_response_to_string(Rlerror::new(unix::EBADF)),
        };
        let entry = fid_ref.0.lock().unwrap();
        if entry.is_deleted() {
            return embed_response_to_string(Rlerror::new(unix::EINVAL));
        }
        match entry.file.get_xattr(&self.name, self.size) {
            Ok(val) => embed_response_to_string(Rgetxattr::new(val)),
            Err(err) => embed_response_to_string(Rlerror::from_err(err)),
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Rgetattr {
    valid: AttrMask,
    qid: QID,
    attr: Attr,
}
impl Rgetattr {
    pub fn new(valid: AttrMask, qid: QID, attr: Attr) -> Self {
        Self { valid, qid, attr }
    }
}
impl Response for Rgetattr {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rgetxattr {
    value: String,
}
impl Rgetxattr {
    pub fn new(value: String) -> Self {
        Self { value }
    }
}
impl Response for Rgetxattr {}

fn extract_errno(err: Error) -> i32 {
    err.raw_os_error().unwrap_or(unix::EIO)
}
