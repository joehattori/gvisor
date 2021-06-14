use std::cmp;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self as stdfs, File as OsFile, Metadata};
use std::hash::{Hash, Hasher};
use std::io;
use std::os::wasi::prelude::*;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, Mutex, RwLock,
};

use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};

use crate::connection::Server;
use crate::message::{QIDType, GID, QID, UID};
use crate::rustfer::{open_any_file_from_parent, AttachPoint};
use crate::unix;

pub type FID = u64;

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Hash)]
pub struct OpenFlags(pub i32);

impl OpenFlags {
    const READ_ONLY: i32 = 0;
    const WRITE_ONLY: i32 = 1;
    const READ_WRITE: i32 = 2;
    const MASK: i32 = 3;

    const ALLOWED_OPEN_FLAGS: i32 = unix::O_TRUNC;

    pub const OPEN_TRUNCATE: i32 = 0o1000;

    fn masked(&self) -> Self {
        OpenFlags(self.masked_flag())
    }

    fn masked_flag(&self) -> i32 {
        let OpenFlags(flags) = self;
        *flags & Self::MASK
    }

    pub fn truncated_flag(&self) -> i32 {
        let OpenFlags(flags) = self;
        *flags & Self::OPEN_TRUNCATE
    }

    pub fn is_read_only(&self) -> bool {
        self.masked_flag() == Self::READ_ONLY
    }

    fn is_write_only(&self) -> bool {
        self.masked_flag() == Self::WRITE_ONLY
    }

    fn is_read_write(&self) -> bool {
        self.masked_flag() == Self::READ_WRITE
    }

    fn invalid_mode() -> Self {
        OpenFlags(i32::MAX)
    }

    fn os_flags(&self) -> i32 {
        let OpenFlags(flags) = self;
        *flags
    }
}

#[derive(
    Copy, Clone, Default, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct FileMode(pub u32);

impl FileMode {
    const MASK: u32 = 0o170000;

    pub const REGULAR: u32 = 0o100000;
    const DIRECTORY: u32 = 0o40000;
    const NAMED_PIPE: u32 = 0o10000;
    const BLOCK_DEVICE: u32 = 0o60000;
    const CHARACTER_DEVICE: u32 = 0o20000;
    const SOCKET: u32 = 0o140000;
    const SYMLINK: u32 = 0o120000;

    fn masked_mode(&self) -> u32 {
        let FileMode(mode) = self;
        *mode & FileMode::MASK
    }

    pub fn qid_type(&self) -> QIDType {
        if self.is_dir() {
            QIDType::DIR
        } else if self.is_socket() || self.is_named_pipe() || self.is_char_dev() {
            QIDType::APPEND_ONLY
        } else if self.is_symlink() {
            QIDType::SYMLINK
        } else {
            QIDType::REGULAR
        }
    }

    pub fn file_type(&self) -> Self {
        FileMode(self.masked_mode())
    }

    pub fn is_regular(&self) -> bool {
        self.masked_mode() == FileMode::REGULAR
    }

    pub fn is_dir(&self) -> bool {
        self.masked_mode() == FileMode::DIRECTORY
    }

    pub fn is_named_pipe(&self) -> bool {
        self.masked_mode() == FileMode::NAMED_PIPE
    }

    pub fn is_block_dev(&self) -> bool {
        self.masked_mode() == FileMode::BLOCK_DEVICE
    }

    pub fn is_char_dev(&self) -> bool {
        self.masked_mode() == FileMode::CHARACTER_DEVICE
    }

    pub fn is_socket(&self) -> bool {
        self.masked_mode() == FileMode::SOCKET
    }

    pub fn is_symlink(&self) -> bool {
        self.masked_mode() == FileMode::SYMLINK
    }

    pub fn can_open(&self) -> bool {
        self.is_regular()
            || self.is_dir()
            || self.is_named_pipe()
            || self.is_block_dev()
            || self.is_char_dev()
    }

    pub fn regular() -> Self {
        FileMode(Self::REGULAR)
    }

    fn from_metadata(metadata: &stdfs::Metadata) -> Self {
        let file_type = metadata.file_type();
        let file_type = if file_type.is_dir() {
            Self::DIRECTORY
        } else if file_type.is_file() {
            Self::REGULAR
        } else if file_type.is_symlink() {
            Self::SYMLINK
        } else {
            panic!("invalid file_type: {:?}", file_type);
        };
        // JOETODO: handle write and execution.
        let permissions = metadata.permissions();
        let permission = if permissions.readonly() { 0o744 } else { 0o755 } as u32;
        FileMode(file_type | permission)
    }
}

#[derive(Clone, Debug)]
pub struct PathNode {
    child_nodes: Arc<RwLock<HashMap<String, PathNode>>>,
    child_refs: Arc<RwLock<HashMap<String, HashSet<FIDRef>>>>,
    child_ref_names: Arc<RwLock<HashMap<FIDRef, String>>>,
}

impl PathNode {
    pub fn new() -> Self {
        Self {
            child_nodes: Arc::new(RwLock::new(HashMap::new())),
            child_refs: Arc::new(RwLock::new(HashMap::new())),
            child_ref_names: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn remove_child(&mut self, fid_ref: FIDRef) {
        println!("remove_child");
        // TODO: mutex
        let mut child_ref_names = self.child_ref_names.write().unwrap();
        if let Some(name) = child_ref_names.remove(&fid_ref) {
            let mut child_refs = self.child_refs.write().unwrap();
            let mut m = child_refs
                .get_mut(&name)
                .expect(&format!("name {} missing from child_fid_refs", name));
            m.remove(&fid_ref);
            if m.len() == 0 {
                child_refs.remove(&name);
            }
        }
    }

    pub fn add_child(&self, rf: FIDRef, name: &str) {
        {
            println!("addChild: {}, {:?}", name, rf.0.lock().unwrap());
        }
        let mut child_ref_names = self.child_ref_names.write().unwrap();
        if let Some(n) = child_ref_names.insert(rf.clone(), name.to_string()) {
            println!("unexpected FIDRef with path {}, wanted {}", n, name);
            panic!("unexpected FIDRef with path {}, wanted {}", n, name);
        }
        let mut child_refs = self.child_refs.write().unwrap();
        match child_refs.get_mut(name) {
            Some(m) => {
                for f in m.iter() {
                    println!("HashSet Some: {:?}", f);
                }
                if !m.insert(rf) {
                    println!("unexpected FIDRef with path wanted {}", name);
                    panic!("unexpected FIDRef with path wanted {}", name);
                }
            }
            None => {
                println!("HashSet None: {:?}", rf.clone());
                let mut m = HashSet::new();
                m.insert(rf);
                child_refs.insert(name.to_string(), m);
            }
        }
    }

    pub fn name_for(&self, rf: FIDRef) -> String {
        println!("namefor {:?}", rf);
        let child_ref_names = self.child_ref_names.read().unwrap();
        println!("namefor {:?}", child_ref_names);
        // NEXT: Here is None.
        println!("namefor got: {:?}", child_ref_names.get(&rf));
        child_ref_names
            .get(&rf)
            .expect(&format!("expected name for {:?}, none found", rf))
            .clone()
    }

    pub fn path_node_for(&self, name: &str) -> Self {
        if let Some(pn) = self.child_nodes.read().unwrap().get(name) {
            return pn.clone();
        }

        // Slow path, create a new pathNode for shared use.
        let mut child_nodes = self.child_nodes.write().unwrap();

        if let Some(pn) = child_nodes.get(name) {
            return pn.clone();
        }
        let pn = Self::new();
        child_nodes.insert(name.to_string(), pn.clone());
        pn
    }

    pub fn remove_with_name(&self, name: &str, f: Box<dyn Fn(&FIDRef)>) -> Option<Self> {
        let mut child_refs = self.child_refs.write().unwrap();
        let mut child_ref_names = self.child_ref_names.write().unwrap();
        if let Some(m) = child_refs.get_mut(name) {
            for rf in m.clone().iter() {
                m.remove(&rf.clone());
                child_ref_names.remove(&rf.clone());
                f(rf)
            }
        }
        let mut child_nodes = self.child_nodes.write().unwrap();
        child_nodes.remove(name)
    }

    fn for_each_child_ref(&self, f: Box<dyn Fn(&FIDRef, &str)>) {
        let child_refs = self.child_refs.read().unwrap();
        for (name, m) in child_refs.iter() {
            for rf in m.iter() {
                f(rf, name)
            }
        }
    }

    fn for_each_child_node(&self, f: Box<dyn Fn(&Self)>) {
        let child_nodes = self.child_nodes.read().unwrap();
        for pn in child_nodes.values() {
            f(pn)
        }
    }
}

impl PartialEq for PathNode {
    fn eq(&self, other: &Self) -> bool {
        *self.child_nodes.read().unwrap() == *other.child_nodes.read().unwrap()
            && *self.child_refs.read().unwrap() == *other.child_refs.read().unwrap()
        // && *self.child_ref_names.read().unwrap() == *other.child_ref_names.read().unwrap()
    }
}

impl Eq for PathNode {}

impl Hash for PathNode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let child_nodes = self.child_nodes.read().unwrap();
        // let child_refs = self.child_refs.read().unwrap();
        // let child_ref_names = self.child_ref_names.read().unwrap();
        child_nodes.keys().collect::<Vec<_>>().hash(state);
        child_nodes.values().collect::<Vec<_>>().hash(state);
        // child_refs.keys().collect::<Vec<_>>().hash(state);
        // child_ref_names.keys().collect::<Vec<_>>().hash(state);
    }
}

pub trait Attacher: DynClone + Send + Sync {
    fn attach(&self) -> io::Result<LocalFile>;
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Attr {
    pub file_mode: FileMode,
    pub uid: u32,
    pub gid: u32,
    pub n_link: u64,
    pub r_dev: u64,
    pub size: u64,
    pub block_size: u64,
    pub blocks: u64,
    pub a_time_seconds: u64,
    pub a_time_nanoseconds: u64,
    pub m_time_seconds: u64,
    pub m_time_nanoseconds: u64,
    pub c_time_seconds: u64,
    pub c_time_nanoseconds: u64,
    pub b_time_seconds: u64,
    pub b_time_nanoseconds: u64,
    pub gen: u64,
    pub data_version: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct AttrMask {
    pub file_mode: bool,
    pub n_link: bool,
    pub uid: bool,
    pub gid: bool,
    pub r_dev: bool,
    pub a_time: bool,
    pub m_time: bool,
    pub c_time: bool,
    pub i_no: bool,
    pub size: bool,
    pub blocks: bool,
    pub b_time: bool,
    pub gen: bool,
    pub data_version: bool,
}

impl AttrMask {
    pub fn mask_all() -> Self {
        AttrMask {
            file_mode: true,
            n_link: true,
            uid: true,
            gid: true,
            r_dev: true,
            a_time: true,
            m_time: true,
            c_time: true,
            i_no: true,
            size: true,
            blocks: true,
            b_time: true,
            gen: true,
            data_version: true,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct SetAttrMask {
    permissions: bool,
    uid: bool,
    gid: bool,
    size: bool,
    a_time: bool,
    m_time: bool,
    c_time: bool,
    a_time_not_system_time: bool,
    m_time_not_system_time: bool,
}

impl SetAttrMask {
    fn is_empty(&self) -> bool {
        !self.permissions
            && !self.uid
            && !self.gid
            && !self.size
            && !self.a_time
            && !self.m_time
            && !self.c_time
            && !self.a_time_not_system_time
            && !self.m_time_not_system_time
    }

    fn is_subset_of(&self, m: SetAttrMask) -> bool {
        let self_bm = self.bitmask();
        let m_bm = m.bitmask();
        m_bm | self_bm == m_bm
    }

    fn bitmask(&self) -> u32 {
        let mut mask = 0;
        if self.permissions {
            mask |= 0x00000001
        }
        if self.uid {
            mask |= 0x00000002
        }
        if self.gid {
            mask |= 0x00000004
        }
        if self.size {
            mask |= 0x00000008
        }
        if self.a_time {
            mask |= 0x00000010
        }
        if self.m_time {
            mask |= 0x00000020
        }
        if self.c_time {
            mask |= 0x00000040
        }
        if self.a_time_not_system_time {
            mask |= 0x00000080
        }
        if self.m_time_not_system_time {
            mask |= 0x00000100
        }
        mask
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct SetAttr {
    permissions: FileMode,
    uid: UID,
    gid: GID,
    size: u64,
    a_time_seconds: u64,
    a_time_nanoseconds: u64,
    m_time_seconds: u64,
    m_time_nanoseconds: u64,
}

// pub trait File: DynClone + Send + Sync {
//     fn walk(&mut self, names: Vec<&str>) -> io::Result<(Vec<QID>, Box<dyn File>)>;
//     fn open(&mut self, flags: OpenFlags) -> io::Result<(Option<OsFile>, QID, u32)>;
//     fn close(&mut self) -> io::Result<()>;
//     fn create(
//         &self,
//         name: &str,
//         flags: OpenFlags,
//         perm: FileMode,
//         uid: UID,
//         gid: GID,
//     ) -> io::Result<(Option<OsFile>, Box<dyn File>, QID, u32)>;
//     fn get_attr(&self, mask: AttrMask) -> io::Result<(QID, AttrMask, Attr)>;
//     fn set_attr(&self, valid: SetAttrMask, attr: SetAttr) -> io::Result<()>;
//     fn walk_get_attr(
//         &mut self,
//         names: Vec<&str>,
//     ) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)>;
//     fn unlink_at(&self, name: &str, flag: i32) -> io::Result<()>;

//     fn qid(&self) -> QID;
//     fn host_path(&self) -> String;
// }

// dyn_clone::clone_trait_object!(File);

// #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct Fd(pub RawFd);
// impl Fd {
//     pub fn fd(&self) -> u32 {
//         let Fd(fd) = self;
//         *fd
//     }
//
//     pub fn into_file(&self) -> OsFile {
//         unsafe { OsFile::from_raw_fd(self.fd()) }
//     }
// }

pub struct LocalFile {
    is_open: AtomicBool,
    attach_point: AttachPoint,
    pub host_path: String,
    control_readable: bool,
    mode: OpenFlags,
    file_type: stdfs::FileType,
    pub qid: QID,
    last_dir_offset: u64,
}

impl LocalFile {
    pub fn new(
        a: &AttachPoint,
        metadata: &stdfs::Metadata,
        path: &str,
        readable: bool,
    ) -> io::Result<Self> {
        // TODO: checkSupportedFileType
        Ok(LocalFile {
            is_open: AtomicBool::new(true),
            attach_point: a.clone(),
            host_path: path.to_string(),
            mode: OpenFlags::invalid_mode(),
            file_type: metadata.file_type(),
            qid: a.make_qid(&metadata),
            control_readable: readable,
            last_dir_offset: 0,
        })
    }

    fn is_open(&self) -> bool {
        self.mode != OpenFlags::invalid_mode()
    }

    fn check_ro_mount(&self) -> io::Result<()> {
        if self.attach_point.config.ro_mount {
            Err(io::Error::from_raw_os_error(unix::EROFS as i32))
        } else {
            Ok(())
        }
    }

    fn fill_attr(&self, metadata: &stdfs::Metadata) -> (AttrMask, Attr) {
        let valid = AttrMask {
            file_mode: true,
            uid: true,
            gid: true,
            n_link: true,
            r_dev: true,
            size: true,
            blocks: true,
            a_time: true,
            m_time: true,
            c_time: true,
            b_time: false,
            data_version: false,
            gen: false,
            i_no: false,
        };
        let btime = metadata.created().unwrap().elapsed().unwrap();
        let atim = metadata.atim();
        let mtim = metadata.mtim();
        let ctim = metadata.ctim();
        const BASE: u64 = 1e9 as u64;
        let attr = Attr {
            // file_mode: FileMode(metadata.st_mode),
            file_mode: FileMode::from_metadata(metadata),
            // uid: metadata.st_uid,
            // gid: metadata.st_gid,
            uid: 0, // JOETODO: get appropriate UID
            gid: 0, // JOETODO: get appropriate GID
            n_link: metadata.nlink(),
            r_dev: metadata.dev(),
            size: metadata.size(),
            block_size: 0u64,
            blocks: 0u64,
            a_time_seconds: atim / BASE,
            a_time_nanoseconds: atim % BASE,
            m_time_seconds: mtim / BASE,
            m_time_nanoseconds: mtim % BASE,
            c_time_seconds: ctim / BASE,
            c_time_nanoseconds: ctim % BASE,
            b_time_seconds: btime.as_secs(),
            b_time_nanoseconds: btime.subsec_nanos() as u64,
            gen: 0,
            data_version: 0,
        };
        (valid, attr)
    }

    pub fn walk(&mut self, names: Vec<&str>) -> io::Result<(Vec<QID>, Self, stdfs::Metadata)> {
        if names.is_empty() {
            // let file = self.host_file().unwrap();
            // JOETODO: open_any_file
            // let path = self.host_path.clone();
            // let (file, readable) = open_any_file(Box::new(move |option: &stdfs::OpenOptions| {
            //     println!("open any file: {}", path);
            //     reopen_proc_fd(&file, option)
            // }))?;
            let metadata = stdfs::metadata(self.host_path.clone())?;
            let readable = false;
            let qid = self.attach_point.make_qid(&metadata);
            let c = LocalFile {
                is_open: AtomicBool::new(true),
                attach_point: self.attach_point.clone(),
                host_path: self.host_path.clone(),
                mode: OpenFlags::invalid_mode(),
                file_type: self.file_type,
                qid: qid.clone(),
                control_readable: readable,
                last_dir_offset: 0,
            };
            return Ok((vec![qid], c, metadata));
        }
        let mut last = self.clone();
        let mut last_stat = None;
        let mut qids = Vec::new();
        for name in names {
            let (metadata, path, readable) = open_any_file_from_parent(&last, name)?;
            if &last != self {
                last.close().expect("failed closing");
            }
            last_stat = match self.metadata() {
                Ok(v) => Some(v),
                Err(e) => {
                    self.close().expect("failed closing");
                    return Err(e);
                }
            };
            let c = LocalFile::new(&last.attach_point, &metadata, &path, readable)?;
            last = c.clone();
            qids.push(c.qid.clone());
        }
        Ok((qids, last, last_stat.unwrap()))
    }

    fn host_file(&self) -> Option<OsFile> {
        if self.is_open.load(Ordering::Relaxed) {
            Some(OsFile::open(&self.host_path).unwrap())
        } else {
            None
        }
    }

    // fn fstat(&self) -> io::Result<libc::stat> {
    //     let file = self.host_file().unwrap();
    //     let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    //     let res = unsafe { libc::fstat(file.as_raw_fd() as i32, &mut stat) };
    //     if res < 0 {
    //         // TODO: return appropriate error
    //         Err(io::Error::from_raw_os_error(unix::EBADF))
    //     } else {
    //         Ok(stat)
    //     }
    // }

    fn metadata(&self) -> io::Result<stdfs::Metadata> {
        stdfs::metadata(self.host_path.clone())
    }

    // File operations here.

    pub fn open(&mut self, flags: OpenFlags) -> io::Result<(Option<OsFile>, QID, u32)> {
        println!("LocalFile opening: {}", self.host_path);
        if self.is_open() {
            panic!("attempting to open already opened file: {}", self.host_path);
        }
        let mode = flags.masked();
        if mode.is_write_only() || mode.is_read_write() || mode.truncated_flag() != 0 {
            self.check_ro_mount()?;
        }
        self.is_open.store(true, Ordering::Relaxed);
        let new_file = if mode.is_read_only()
            && self.control_readable
            && flags.os_flags() & OpenFlags::ALLOWED_OPEN_FLAGS == 0
        {
            println!(
                "Open reusing control file, flags: {:?}, {}",
                flags, self.host_path
            );
            self.host_file()
        } else {
            println!(
                "Open reopening file, flags: {:?}, {}",
                flags, self.host_path
            );
            // JOETODO
            // let option = stdfs::OpenOptions::new();
            // let file = self.host_file().unwrap();
            // reopen_proc_fd(&file, &option)?
            None
        };

        let fd = if self.file_type.is_file() {
            // TODO: new_fd_maybe
            new_file
        } else {
            None
        };

        self.mode = mode;
        Ok((fd, self.qid, 0))
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.mode = OpenFlags::invalid_mode();
        self.is_open.store(false, Ordering::Relaxed);
        Ok(())
    }

    pub fn create(
        &self,
        name: &str,
        flags: OpenFlags,
        perm: FileMode,
        uid: UID,
        gid: GID,
    ) -> io::Result<(Option<OsFile>, Self, QID, u32)> {
        self.check_ro_mount()?;
        let mode = OpenFlags(flags.os_flags() & OpenFlags::MASK);
        let path = Path::new(&self.host_path).join(name);
        // TODO: handle permisson with OpenOption.
        let metadata = OsFile::create(path.to_str().unwrap())?.metadata()?;
        // TODO: setOwnerIfNeeded()
        let c = LocalFile {
            is_open: AtomicBool::new(true),
            attach_point: self.attach_point.clone(),
            host_path: path.to_str().unwrap().to_string(),
            mode,
            file_type: metadata.file_type(),
            qid: self.attach_point.make_qid(&metadata),
            control_readable: false,
            last_dir_offset: 0,
        };
        let qid = c.qid;
        // TODO: newFDMaybe
        Ok((c.host_file(), c, qid, 0))
    }

    pub fn get_attr(&self, _: AttrMask) -> io::Result<(QID, AttrMask, Attr)> {
        // let stat = self.fstat()?;
        let metadata = self
            .host_file()
            .unwrap()
            .metadata()
            .expect("failed to retrive metadata");
        let (mask, attr) = self.fill_attr(&metadata);
        Ok((self.qid, mask, attr))
    }

    pub fn get_xattr(&self, name: &str, size: u64) -> io::Result<String> {
        if !self.attach_point.config.enable_x_attr {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("operation not supported"),
            ));
        }
        panic!("get_xattr unsupported");
    }

    pub fn set_attr(&self, valid: SetAttrMask, attr: SetAttr) -> io::Result<()> {
        self.check_ro_mount()?;
        let allowed = SetAttrMask {
            permissions: true,
            uid: true,
            gid: true,
            size: true,
            a_time: true,
            m_time: true,
            c_time: false,
            a_time_not_system_time: true,
            m_time_not_system_time: true,
        };
        if valid.is_empty() {
            return Ok(());
        }
        if !valid.is_subset_of(allowed) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SetAttr() failed for {}, mask: {:?}", self.host_path, valid),
            ));
        }
        let perform_close =
            self.file_type.is_file() && !self.mode.is_write_only() && !self.mode.is_read_write();
        let (mut file, file_raw_fd) = if perform_close {
            // let file = self.host_file().unwrap();
            // let std_file = reopen_proc_fd(&file, stdfs::OpenOptions::new().write(true))?;
            // let fd = std_file.as_raw_fd();
            // (Some(std_file), Some(fd))
            // JOETODO
            (None, None)
        } else {
            match self.host_file() {
                Some(file) => {
                    let fd = file.as_raw_fd();
                    (Some(file), Some(fd))
                }
                None => (None, None),
            }
        };
        let mut ret = Ok(());
        if valid.permissions {
            panic!("SetAttr fchmod is currently not supported.");
        }
        if valid.size {
            file.unwrap().set_len(attr.size)?;
        }

        if valid.a_time || valid.m_time {
            let mut utimes = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: unix::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: unix::UTIME_OMIT,
                },
            ];
            if valid.a_time {
                if valid.a_time_not_system_time {
                    utimes[0].tv_sec = attr.a_time_seconds as i64;
                    utimes[0].tv_nsec = attr.a_time_nanoseconds as i32;
                } else {
                    utimes[0].tv_nsec = unix::UTIME_NOW;
                }
            }
            if valid.m_time {
                if valid.m_time_not_system_time {
                    utimes[1].tv_sec = attr.m_time_seconds as i64;
                    utimes[1].tv_nsec = attr.m_time_nanoseconds as i32;
                } else {
                    utimes[1].tv_nsec = unix::UTIME_NOW;
                }
            }

            if self.file_type.is_symlink() {
                let std_file = OsFile::open(self.host_path.clone())?;
                let fd = std_file.as_raw_fd();
                let res = unsafe { libc::futimens(fd as i32, utimes.as_ptr()) };
                if res < 0 {
                    ret = Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("SetAttr utimens failed {}", self.host_path),
                    ));
                }
            } else {
                let res = unsafe { libc::futimens(file_raw_fd.unwrap() as i32, utimes.as_ptr()) };
                if res < 0 {
                    ret = Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("SetAttr utimens failed {}", self.host_path),
                    ));
                }
            }
        }

        if valid.uid || valid.gid {
            // let uid = if valid.uid {
            //     attr.uid
            // } else {
            //     NO_UID
            // };
            // let gid = if valid.gid {
            //     attr.gid
            // } else {
            //     NO_GID
            // };
            panic!("SetAttr fchown not supported yet.");
        }

        ret
    }

    pub fn walk_get_attr(
        &mut self,
        names: Vec<&str>,
    ) -> io::Result<(Vec<QID>, Self, AttrMask, Attr)> {
        println!("walk_get_attr 0");
        let (qids, file, stat) = self.walk(names)?;
        println!("walk_get_attr 1");
        let (mask, attr) = self.fill_attr(&self.metadata()?);
        println!("walk_get_attr 2");
        Ok((qids, file, mask, attr))
    }

    pub fn unlink_at(&self, name: &str, flag: i32) -> io::Result<()> {
        self.check_ro_mount()?;
        let file = self.host_file().unwrap();
        let res =
            unsafe { libc::unlinkat(file.as_raw_fd() as i32, name.as_ptr() as *const i8, flag) };
        if res < 0 {
            Err(io::Error::new(io::ErrorKind::Other, "unlink_at failed"))
        } else {
            Ok(())
        }
    }
}

impl PartialEq for LocalFile {
    fn eq(&self, other: &Self) -> bool {
        self.attach_point == other.attach_point
            && self.host_path == other.host_path
            && self.control_readable == other.control_readable
            && self.mode == other.mode
            && self.file_type == other.file_type
            && self.qid == other.qid
            && self.last_dir_offset == other.last_dir_offset
    }
}
impl Eq for LocalFile {}
impl Clone for LocalFile {
    fn clone(&self) -> Self {
        Self {
            is_open: AtomicBool::new(self.is_open.load(Ordering::Relaxed)),
            attach_point: self.attach_point.clone(),
            host_path: self.host_path.clone(),
            control_readable: self.control_readable,
            mode: self.mode,
            file_type: self.file_type,
            qid: self.qid,
            last_dir_offset: self.last_dir_offset,
        }
    }
}

impl Hash for LocalFile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.attach_point.hash(state);
        self.host_path.hash(state);
        self.control_readable.hash(state);
        self.mode.hash(state);
        self.file_type.hash(state);
        self.qid.hash(state);
        self.last_dir_offset.hash(state);
    }
}

pub struct FIDEntry {
    pub file: LocalFile,
    pub refs: AtomicI64,
    pub is_open: bool,
    pub mode: FileMode,
    pub open_flags: OpenFlags,
    pub path_node: PathNode,
    pub parent: Option<FIDRef>,
    pub is_deleted: AtomicBool,
    pub server: Server,
}
impl FIDEntry {
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted.load(Ordering::Relaxed)
    }

    pub fn mark_child_deleted(&self, name: &str) {
        let orig_path_node = self.path_node.remove_with_name(
            name,
            Box::new(|rf: &FIDRef| {
                *rf.0.lock().unwrap().is_deleted.get_mut() = true;
            }),
        );
        if let Some(ref orig_path_node) = orig_path_node {
            notify_delete(orig_path_node)
        }
    }
}
impl Hash for FIDEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.refs.load(Ordering::Relaxed).hash(state);
        self.file.hash(state);
        self.is_open.hash(state);
        self.mode.hash(state);
        self.open_flags.hash(state);
        self.path_node.hash(state);
    }
}
impl std::fmt::Debug for FIDEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FIDEntry")
            // .field("file", &self.file)
            .field("refs", &self.refs)
            .field("is_open", &self.is_open)
            .field("is_deleted", &self.is_deleted)
            .field("mode", &self.mode)
            .field("open_flags", &self.open_flags)
            .field("path_node", &self.path_node)
            .finish()
    }
}
impl PartialEq for FIDEntry {
    fn eq(&self, other: &Self) -> bool {
        self.file == other.file
            && self.is_open == other.is_open
            && self.mode == other.mode
            && self.open_flags == other.open_flags
            && self.parent == other.parent
            && self.refs.load(Ordering::Relaxed) == other.refs.load(Ordering::Relaxed)
            && self.is_deleted.load(Ordering::Relaxed) == other.is_deleted.load(Ordering::Relaxed)
        // && self.path_node == other.path_node // JOETODO: PathNode contains FIDRef, and comparing this leads to infinite recursive call on this function.
    }
}
impl Eq for FIDEntry {}
impl PartialOrd for FIDEntry {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.file.host_path.cmp(&other.file.host_path))
    }
}
impl Ord for FIDEntry {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.file.qid.cmp(&other.file.qid)
    }
}

#[derive(Debug)]
pub struct FIDRef(pub Arc<Mutex<FIDEntry>>);
impl FIDRef {
    pub fn from_entry(entry: FIDEntry) -> Self {
        Self(Arc::new(Mutex::new(entry)))
    }

    pub fn inc_ref(&mut self) {
        let mut entry = self.0.lock().unwrap();
        *entry.refs.get_mut() += 1;
    }

    pub fn dec_ref(&mut self) {
        let mut entry = self.0.lock().unwrap();
        let val = entry.refs.get_mut();
        *val -= 1;
        if *val == 0 {
            entry.file.close().expect("failed closing file.");
            if let Some(mut parent) = entry.parent.clone() {
                let mut parent_entry = parent.0.lock().unwrap();
                drop(entry);
                parent_entry.path_node.remove_child(self.clone());
                drop(parent_entry);
                parent.dec_ref();
            }
        }
    }
}
impl Hash for FIDRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // self.0.lock().unwrap().hash(state);
        Arc::as_ptr(&self.0).hash(state);
    }
}
impl Clone for FIDRef {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl PartialEq for FIDRef {
    fn eq(&self, other: &Self) -> bool {
        // *self.0.lock().unwrap() == *other.0.lock().unwrap()
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for FIDRef {}
impl PartialOrd for FIDRef {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        // Some(self.0.lock().unwrap().cmp(&*other.0.lock().unwrap()))
        Some(Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0)))
    }
}
impl Ord for FIDRef {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // self.0.lock().unwrap().cmp(&*other.0.lock().unwrap())
        Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
    }
}

fn notify_delete(pn: &PathNode) {
    pn.for_each_child_ref(Box::new(|rf: &FIDRef, _: &str| {
        *rf.0.lock().unwrap().is_deleted.get_mut() = true;
    }));
    pn.for_each_child_node(Box::new(|pn: &PathNode| notify_delete(pn)));
}

// impl Clone for FIDRef {
//     fn clone(&self) -> Self {
//         FIDRef {
//             file: self.file.clone(),
//             refs: AtomicI64::new(self.refs.load(Ordering::Relaxed)),
//             is_open: self.is_open,
//             mode: self.mode.clone(),
//             open_flags: self.open_flags,
//             path_node: self.path_node.clone(),
//             parent: self.parent.clone(),
//             is_deleted: AtomicBool::new(self.is_deleted.load(Ordering::Relaxed)),
//             server: self.server.clone(),
//         }
//     }
// }

fn reopen_proc_fd(file: &OsFile) -> io::Result<Metadata> {
    stdfs::symlink_metadata(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
