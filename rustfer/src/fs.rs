use std::cmp;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self as stdfs, File as StdFile};
use std::io;
use std::os::wasi::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};

use crate::connection::Server;
use crate::message::{QIDType, GID, QID, UID};
use crate::rustfer::{
    fstat, open_any_file, open_any_file_from_parent, reopen_proc_fd, AttachPoint,
};
use crate::unix;

pub type FID = u64;

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct OpenFlags(pub i32);

impl OpenFlags {
    const READ_ONLY: i32 = 0;
    const WRITE_ONLY: i32 = 1;
    const READ_WRITE: i32 = 2;
    const MASK: i32 = 3;

    const ALLOWED_OPEN_FLAGS: i32 = unix::O_TRUNC;

    pub const OPEN_TRUNCATE: i32 = 01000;

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

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileMode(pub u32);

impl FileMode {
    const MASK: u32 = 0170000;

    pub const REGULAR: u32 = 0100000;
    const DIRECTORY: u32 = 040000;
    const NAMED_PIPE: u32 = 010000;
    const BLOCK_DEVICE: u32 = 060000;
    const CHARACTER_DEVICE: u32 = 020000;
    const SOCKET: u32 = 0140000;
    const SYMLINK: u32 = 0120000;

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
}

#[derive(Clone)]
pub struct PathNode {
    child_nodes: Arc<Mutex<HashMap<String, PathNode>>>,
    child_refs: Arc<Mutex<HashMap<String, BTreeSet<FIDRef>>>>,
}

impl PathNode {
    pub fn new() -> Self {
        PathNode {
            child_nodes: Arc::new(Mutex::new(HashMap::new())),
            child_refs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_child_name_from_fid_ref(&self, fid_ref: &FIDRef) -> Option<String> {
        self.child_refs
            .lock()
            .unwrap()
            .iter()
            .find_map(|(k, v)| v.get(fid_ref).map(|_| k.clone()))
    }

    fn remove_child(&mut self, fid_ref: &FIDRef) {
        // TODO: mutex
        if let Some(name) = self.get_child_name_from_fid_ref(fid_ref) {
            self.child_refs
                .lock()
                .unwrap()
                .remove(&name)
                .expect(&format!("name {} missing from child_fid_refs", name));
            let mut child_refs = self.child_refs.lock().unwrap();
            if child_refs.len() == 0 {
                child_refs.remove(&name);
            }
        }
    }

    pub fn add_child(&self, rf: &FIDRef, name: &str) {
        if let Some(n) = self.get_child_name_from_fid_ref(rf) {
            panic!("unexpected FIDRef with path {}, wanted {}", n, name);
        }
        let mut bt = BTreeSet::new();
        bt.insert(rf.clone());
        self.child_refs.lock().unwrap().insert(name.to_string(), bt);
    }

    pub fn name_for(&self, rf: &FIDRef) -> String {
        self.get_child_name_from_fid_ref(rf)
            .unwrap_or_else(|| panic!("expected name, none found"))
    }

    pub fn path_node_for(&self, name: &str) -> Self {
        {
            if let Some(pn) = self.child_nodes.lock().unwrap().get(name) {
                return pn.clone();
            }
        }

        // Slow path, create a new pathNode for shared use.
        let mut child_nodes = self.child_nodes.lock().unwrap();

        if let Some(pn) = child_nodes.get(name) {
            return pn.clone();
        }
        let pn = PathNode::new();
        child_nodes.insert(name.to_string(), pn.clone());
        pn
    }

    pub fn remove_with_name(&self, name: &str, f: Box<dyn Fn(&FIDRef)>) -> Option<PathNode> {
        let mut child_refs = self.child_refs.lock().unwrap();
        if let Some(m) = child_refs.get_mut(name) {
            for rf in m.clone().iter() {
                m.remove(rf);
                f(rf)
            }
        }
        let mut child_nodes = self.child_nodes.lock().unwrap();
        child_nodes.remove(name)
    }

    fn for_each_child_ref(&self, f: Box<dyn Fn(&FIDRef, &str)>) {
        let child_refs = self.child_refs.lock().unwrap();
        for (name, m) in child_refs.iter() {
            for rf in m.iter() {
                f(rf, name)
            }
        }
    }

    fn for_each_child_node(&self, f: Box<dyn Fn(&PathNode)>) {
        let child_nodes = self.child_nodes.lock().unwrap();
        for pn in child_nodes.values() {
            f(pn)
        }
    }
}

impl PartialEq for PathNode {
    fn eq(&self, other: &Self) -> bool {
        *self.child_nodes.lock().unwrap() == *other.child_nodes.lock().unwrap()
            && *self.child_refs.lock().unwrap() == *other.child_refs.lock().unwrap()
    }
}

impl Eq for PathNode {}

pub trait Attacher: DynClone + Send {
    fn attach(&self) -> io::Result<Box<dyn File>>;
}

#[derive(Default)]
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

#[derive(Default)]
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

pub trait File: DynClone + Send {
    fn walk(&self, names: Vec<&str>) -> io::Result<(Vec<QID>, Box<dyn File>)>;
    fn open(&mut self, flags: OpenFlags) -> io::Result<(Option<StdFile>, QID, u32)>;
    fn close(&mut self) -> io::Result<()>;
    fn create(
        &self,
        name: &str,
        flags: OpenFlags,
        perm: FileMode,
        uid: UID,
        gid: GID,
    ) -> io::Result<(Option<StdFile>, Box<dyn File>, QID, u32)>;
    fn get_attr(&self, mask: AttrMask) -> io::Result<(QID, AttrMask, Attr)>;
    fn set_attr(&self, valid: SetAttrMask, attr: SetAttr) -> io::Result<()>;
    fn walk_get_attr(
        &self,
        names: Vec<&str>,
    ) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)>;
    fn unlink_at(&self, name: &str, flag: i32) -> io::Result<()>;
}

// #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
// pub struct Fd(pub RawFd);
// impl Fd {
//     pub fn fd(&self) -> u32 {
//         let Fd(fd) = self;
//         *fd
//     }
//
//     pub fn into_file(&self) -> StdFile {
//         unsafe { StdFile::from_raw_fd(self.fd()) }
//     }
// }

pub struct LocalFile {
    attach_point: AttachPoint,
    pub host_path: String,
    file: Option<StdFile>,
    control_readable: bool,
    mode: OpenFlags,
    file_type: stdfs::FileType,
    qid: QID,
    last_dir_offset: u64,
}

impl LocalFile {
    pub fn new(a: &AttachPoint, file: StdFile, path: &str, readable: bool) -> io::Result<Self> {
        // TODO: checkSupportedFileType
        let metadata = file.metadata().unwrap();
        Ok(LocalFile {
            attach_point: a.clone(),
            host_path: path.to_string(),
            file: Some(file),
            mode: OpenFlags::invalid_mode(),
            file_type: metadata.file_type(),
            qid: a.make_qid(metadata),
            control_readable: readable,
            last_dir_offset: 0,
        })
    }

    fn is_open(&self) -> bool {
        self.mode == OpenFlags::invalid_mode()
    }

    fn check_ro_mount(&self) -> io::Result<()> {
        if self.attach_point.config.ro_mount {
            Err(io::Error::from_raw_os_error(unix::EROFS as i32))
        } else {
            Ok(())
        }
    }

    fn fill_attr(&self, stat: &libc::stat) -> (AttrMask, Attr) {
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
        let attr = Attr {
            file_mode: FileMode(stat.st_mode),
            uid: stat.st_uid,
            gid: stat.st_gid,
            n_link: stat.st_nlink,
            r_dev: stat.st_rdev,
            size: stat.st_size as u64,
            block_size: stat.st_blksize as u64,
            blocks: stat.st_blocks as u64,
            a_time_seconds: stat.st_atim.tv_sec as u64,
            a_time_nanoseconds: stat.st_atim.tv_nsec as u64,
            m_time_seconds: stat.st_mtim.tv_sec as u64,
            m_time_nanoseconds: stat.st_mtim.tv_nsec as u64,
            c_time_seconds: stat.st_ctim.tv_sec as u64,
            c_time_nanoseconds: stat.st_ctim.tv_nsec as u64,
            b_time_seconds: 0,
            b_time_nanoseconds: 0,
            gen: 0,
            data_version: 0,
        };
        (valid, attr)
    }

    fn walk(&self, names: Vec<&str>) -> io::Result<(Vec<QID>, Box<dyn File>, libc::stat)> {
        if names.is_empty() {
            let fd = self.to_raw_fd();
            let (file, readable) = open_any_file(Box::new(move |option: &stdfs::OpenOptions| {
                reopen_proc_fd(fd, option)
            }))?;
            let metadata = file.metadata();
            let stat = fstat(file.as_raw_fd())?;
            let c = LocalFile {
                attach_point: self.attach_point.clone(),
                host_path: self.host_path.clone(),
                file: Some(file),
                mode: OpenFlags::invalid_mode(),
                file_type: self.file_type,
                qid: self.attach_point.make_qid(metadata.unwrap()),
                control_readable: readable,
                last_dir_offset: 0,
            };
            let qid = c.qid.clone();
            return Ok((vec![qid], Box::new(c), stat));
        }
        let mut last = self.clone();
        let mut last_stat: libc::stat = unsafe { std::mem::zeroed() };
        let mut qids = Vec::new();
        for name in names {
            let (file, path, readable) = open_any_file_from_parent(&last, name)?;
            if &last != self {
                last.close();
            }
            last_stat = fstat(file.as_raw_fd()).map_err(|e| {
                // f.close();
                e
            })?;
            let ap = &last.attach_point;
            let c = LocalFile::new(ap, file, &path, readable).map_err(|e| {
                // f.close();
                e
            })?;
            last = c.clone();
            qids.push(c.qid.clone());
        }
        Ok((qids, Box::new(last), last_stat))
    }

    fn to_raw_fd(&self) -> RawFd {
        self.file.as_ref().unwrap().as_raw_fd()
    }
}

impl File for LocalFile {
    fn walk(&self, names: Vec<&str>) -> io::Result<(Vec<QID>, Box<dyn File>)> {
        match self.walk(names) {
            Ok((qids, file, _)) => Ok((qids, file)),
            Err(e) => Err(e),
        }
    }

    fn open(&mut self, flags: OpenFlags) -> io::Result<(Option<StdFile>, QID, u32)> {
        if self.is_open() {
            panic!("attempting to open already opened file: {}", self.host_path);
        }
        let mode = flags.masked();
        if mode.is_write_only() || mode.is_read_write() || mode.truncated_flag() != 0 {
            self.check_ro_mount()?;
        }
        let new_file = if mode.is_read_only()
            && self.control_readable
            && flags.os_flags() & OpenFlags::ALLOWED_OPEN_FLAGS == 0
        {
            println!(
                "Open reusing control file, flags: {:?}, {}",
                flags, self.host_path
            );
            self.file.as_ref().unwrap().try_clone().unwrap()
        } else {
            println!(
                "Open reopening file, flags: {:?}, {}",
                flags, self.host_path
            );
            let option = stdfs::OpenOptions::new();
            reopen_proc_fd(self.to_raw_fd(), &option)?
        };

        let fd = if self.file_type.is_file() {
            // TODO: new_fd_maybe
            Some(new_file.try_clone().unwrap())
        } else {
            None
        };

        // if new_file != self.file {
        // self.file.close();
        self.file = Some(new_file);
        //}
        self.mode = mode;
        Ok((fd, self.qid, 0))
    }

    fn close(&mut self) -> io::Result<()> {
        self.mode = OpenFlags::invalid_mode();
        self.file = None;
        Ok(())
    }

    fn create(
        &self,
        name: &str,
        flags: OpenFlags,
        perm: FileMode,
        uid: UID,
        gid: GID,
    ) -> io::Result<(Option<StdFile>, Box<dyn File>, QID, u32)> {
        self.check_ro_mount()?;
        let mode = OpenFlags(flags.os_flags() & OpenFlags::MASK);
        let path = Path::new(&self.host_path).join(name);
        // TODO: handle permisson with OpenOption.
        let child = StdFile::create(path.to_str().unwrap())?;
        let metadata = child.metadata()?;
        // TODO: setOwnerIfNeeded()
        let c = LocalFile {
            attach_point: self.attach_point.clone(),
            host_path: path.to_str().unwrap().to_string(),
            file: Some(child),
            mode,
            file_type: metadata.file_type(),
            qid: self.attach_point.make_qid(metadata),
            control_readable: false,
            last_dir_offset: 0,
        };
        let qid = c.qid;
        let file = match c.file {
            Some(ref file) => Some(file.try_clone().unwrap()),
            None => None,
        };
        // TODO: newFDMaybe
        Ok((file, Box::new(c), qid, 0))
    }

    fn get_attr(&self, _mask: AttrMask) -> io::Result<(QID, AttrMask, Attr)> {
        let stat = fstat(self.to_raw_fd())?;
        let (mask, attr) = self.fill_attr(&stat);
        Ok((self.qid, mask, attr))
    }

    fn set_attr(&self, valid: SetAttrMask, attr: SetAttr) -> io::Result<()> {
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
            let std_file = reopen_proc_fd(self.to_raw_fd(), stdfs::OpenOptions::new().write(true))?;
            let fd = std_file.as_raw_fd();
            (Some(std_file), Some(fd))
        } else {
            match self.file {
                Some(ref file) => {
                    let cloned = file.try_clone().unwrap();
                    let fd = cloned.as_raw_fd();
                    (Some(cloned), Some(fd))
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
                let std_file = StdFile::open(self.host_path.clone())?;
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

    fn walk_get_attr(
        &self,
        names: Vec<&str>,
    ) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)> {
        let (qids, file, stat) = self.walk(names)?;
        let (mask, attr) = self.fill_attr(&stat);
        Ok((qids, file, mask, attr))
    }

    fn unlink_at(&self, name: &str, flag: i32) -> io::Result<()> {
        self.check_ro_mount()?;
        let res =
            unsafe { libc::unlinkat(self.to_raw_fd() as i32, name.as_ptr() as *const i8, flag) };
        if res < 0 {
            Err(io::Error::new(io::ErrorKind::Other, "unlink_at failed"))
        } else {
            Ok(())
        }
    }
}

impl PartialEq for LocalFile {
    fn eq(&self, other: &Self) -> bool {
        // TODO: consider self.file as well
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
            attach_point: self.attach_point.clone(),
            host_path: self.host_path.clone(),
            file: self.file.as_ref().unwrap().try_clone().ok(),
            control_readable: self.control_readable,
            mode: self.mode,
            file_type: self.file_type,
            qid: self.qid,
            last_dir_offset: self.last_dir_offset,
        }
    }
}

pub struct FIDRef {
    pub file: Box<dyn File>,
    pub refs: AtomicI64,
    pub is_opened: bool,
    pub mode: FileMode,
    pub open_flags: OpenFlags,
    pub path_node: PathNode,
    pub parent: Option<Box<FIDRef>>,
    pub is_deleted: AtomicBool,
    pub server: Server,
}

impl FIDRef {
    pub fn inc_ref(&mut self) {
        self.refs
            .store(self.refs.load(Ordering::Relaxed) + 1, Ordering::Relaxed)
    }

    pub fn dec_ref(&mut self) {
        self.refs
            .store(self.refs.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
        if self.refs.load(Ordering::Relaxed) == 0 {
            self.file.close();
            if let Some(mut parent) = self.parent.clone() {
                parent.path_node.remove_child(self);
                parent.dec_ref();
            }
        }
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted.load(Ordering::Relaxed)
    }

    pub fn add_child_to_parent(&self, rf: &FIDRef, name: &str) {
        match self.parent {
            Some(ref parent) => parent.path_node.add_child(rf, name),
            None => eprintln!("no parent node when add_child_to_parent."),
        }
    }

    pub fn mark_child_deleted(&self, name: &str) {
        let orig_path_node = self.path_node.remove_with_name(
            name,
            Box::new(|rf: &FIDRef| rf.is_deleted.store(true, Ordering::Relaxed)),
        );
        if let Some(orig_path_node) = orig_path_node {
            notify_delete(&orig_path_node)
        }
    }

    pub fn add_child_to_path_node(&self, r: &Self, name: &str) {
        self.path_node.add_child(r, name)
    }
}

fn notify_delete(pn: &PathNode) {
    pn.for_each_child_ref(Box::new(|rf: &FIDRef, _: &str| {
        rf.is_deleted.store(true, Ordering::Relaxed)
    }));
    pn.for_each_child_node(Box::new(|pn: &PathNode| notify_delete(pn)));
}

impl Clone for FIDRef {
    fn clone(&self) -> Self {
        FIDRef {
            file: dyn_clone::clone_box(&*self.file),
            refs: AtomicI64::new(self.refs.load(Ordering::Relaxed)),
            is_opened: self.is_opened,
            mode: self.mode.clone(),
            open_flags: self.open_flags,
            path_node: self.path_node.clone(),
            parent: self.parent.clone(),
            is_deleted: AtomicBool::new(self.is_deleted.load(Ordering::Relaxed)),
            server: self.server.clone(),
        }
    }
}

impl PartialEq for FIDRef {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.file.as_ref(), other.file.as_ref()) // TODO: check
            && self.refs.load(Ordering::Relaxed) == other.refs.load(Ordering::Relaxed)
            && self.is_opened == other.is_opened
            && self.mode == other.mode
            && self.open_flags == other.open_flags
            && self.path_node == other.path_node
            && self.parent == other.parent
            && self.is_deleted.load(Ordering::Relaxed) == other.is_deleted.load(Ordering::Relaxed)
    }
}

impl Eq for FIDRef {}

impl PartialOrd for FIDRef {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.mode.cmp(&other.mode))
    }
}

impl Ord for FIDRef {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.mode.cmp(&other.mode)
    }
}
