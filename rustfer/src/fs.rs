use std::collections::HashMap;
use std::fs::{self, File as StdFile};
use std::io;
use std::os::wasi::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};

use crate::connection::Server;
use crate::message::{QIDType, QID};
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

#[derive(Clone, Eq, PartialEq, Default)]
pub struct FileMode(pub u32);

impl FileMode {
    const MASK: u32 = 0170000;

    const REGULAR: u32 = 0100000;
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
}

#[derive(Clone)]
pub struct PathNode {
    child_nodes: Arc<Mutex<HashMap<String, PathNode>>>,
    child_refs: Arc<Mutex<HashMap<String, FIDRef>>>,
}

impl PathNode {
    pub fn new() -> Self {
        PathNode {
            child_nodes: Arc::new(Mutex::new(HashMap::new())),
            child_refs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_child_name_from_fid_ref(&self, fid_ref: &FIDRef) -> Option<String> {
        self.child_refs.lock().unwrap().iter().find_map(|(k, v)| {
            if v == fid_ref {
                Some(k.clone())
            } else {
                None
            }
        })
    }

    fn remove_child(&mut self, fid_ref: &FIDRef) {
        // TODO: mutex
        if let Some(name) = self.get_child_name_from_fid_ref(fid_ref) {
            match self.child_refs.lock().unwrap().remove(&name) {
                Some(_) => {
                    let child_refs = self.child_refs.lock().unwrap();
                    if child_refs.len() == 0 {
                        child_refs.remove(&name);
                    }
                }
                None => panic!("name {} missing from child_fid_refs", name),
            }
        }
    }

    pub fn add_child(&self, rf: &FIDRef, name: &str) {
        if let Some(n) = self.get_child_name_from_fid_ref(rf) {
            panic!("unexpected FIDRef with path {}, wanted {}", n, name);
        }
        self.child_refs
            .lock()
            .unwrap()
            .insert(name.to_string(), *rf);
    }

    pub fn name_for(&self, rf: &FIDRef) -> String {
        self.get_child_name_from_fid_ref(rf)
            .unwrap_or_else(|| panic!("expected name, none found"))
    }

    pub fn path_node_for(&self, name: &str) -> Self {
        {
            if let Some(pn) = self.child_nodes.lock().unwrap().get(name) {
                return *pn;
            }
        }

        // Slow path, create a new pathNode for shared use.
        let child_nodes = self.child_nodes.lock().unwrap();

        if let Some(pn) = child_nodes.get(name) {
            return *pn;
        }
        let pn = PathNode::new();
        child_nodes.insert(name.to_string(), pn);
        pn
    }
}

impl PartialEq for PathNode {
    fn eq(&self, other: &Self) -> bool {
        *self.child_nodes.lock().unwrap() == *other.child_nodes.lock().unwrap()
            && *self.child_refs.lock().unwrap() == *other.child_refs.lock().unwrap()
    }
}

impl Eq for PathNode {}

pub trait Attacher: DynClone {
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

pub trait File: DynClone + Send {
    fn walk(&self, names: Vec<&str>) -> io::Result<(Vec<QID>, Box<dyn File>)>;
    fn open(&self, flags: OpenFlags) -> io::Result<(Option<Fd>, QID, u32)>;
    fn close(&self) -> io::Result<()>;
    fn get_attr(&self, mask: AttrMask) -> io::Result<(QID, AttrMask, Attr)>;
    fn walk_get_attr(
        &self,
        names: Vec<&str>,
    ) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)>;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fd(pub RawFd);
impl Fd {
    pub fn fd(&self) -> u32 {
        let Fd(fd) = self;
        *fd
    }

    pub fn into_file(&self) -> StdFile {
        unsafe { StdFile::from_raw_fd(self.fd()) }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LocalFile {
    attach_point: AttachPoint,
    pub host_path: String,
    file: Option<Fd>,
    control_readable: bool,
    mode: OpenFlags,
    file_type: fs::FileType,
    qid: QID,
    last_dir_offset: u64,
}

impl LocalFile {
    pub fn new(a: &AttachPoint, fd: Fd, path: &str, readable: bool) -> Result<Self, u32> {
        // TODO: checkSupportedFileType
        let std_file = unsafe { StdFile::from_raw_fd(fd.fd()) };
        let file = fd.into_file();
        let metadata = file.metadata().unwrap();
        Ok(LocalFile {
            attach_point: *a,
            host_path: path.to_string(),
            file: Some(fd),
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
            let file = self.file.unwrap();
            let (raw_fd, readable) = open_any_file(
                &self.host_path,
                Box::new(|option: &fs::OpenOptions| reopen_proc_fd(file, option)),
            )?;
            let fd = Fd(raw_fd);
            let file = fd.into_file();
            let stat =
                fstat(fd).map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to fstat"))?;
            let c = LocalFile {
                attach_point: self.attach_point,
                host_path: self.host_path,
                file: Some(fd),
                mode: OpenFlags::invalid_mode(),
                file_type: self.file_type,
                qid: self.attach_point.make_qid(file.metadata().unwrap()),
                control_readable: readable,
                last_dir_offset: 0,
            };
            return Ok((vec![c.qid], Box::new(c), stat));
        }
        let mut last = self;
        let mut last_stat: libc::stat = std::mem::zeroed();
        let mut qids = Vec::new();
        for name in names {
            let (raw_fd, path, readable) = open_any_file_from_parent(last, name)?;
            if last != self {
                last.close();
            }
            let fd = Fd(raw_fd);
            let file = fd.into_file();
            last_stat = fstat(fd).map_err(|e| {
                // f.close();
                // TODO: extractErrno
                io::Error::new(io::ErrorKind::Other, "unix::EINVAL")
            })?;
            // NEXT
            let c = LocalFile::new(&last.attach_point, fd, &path, readable).map_err(|e| {
                // f.close();
                // TODO: extractErrno
                io::Error::new(io::ErrorKind::Other, "unix::EINVAL")
            })?;
            qids.push(c.qid);
            last = &c;
        }
        Ok((qids, Box::new(*last), last_stat))
    }
}

impl File for LocalFile {
    fn walk(&self, names: Vec<&str>) -> io::Result<(Vec<QID>, Box<dyn File>)> {
        match self.walk(names) {
            Ok((qids, file, _)) => Ok((qids, file)),
            Err(e) => Err(e),
        }
    }

    fn open(&self, flags: OpenFlags) -> io::Result<(Option<Fd>, QID, u32)> {
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
            self.file
        } else {
            println!(
                "Open reopening file, flags: {:?}, {}",
                flags, self.host_path
            );
            let option = fs::OpenOptions::new();
            let std_file = reopen_proc_fd(self.file.unwrap(), &option)?;
            Some(Fd(std_file.as_raw_fd()))
        };

        let fd = if self.file_type.is_file() {
            // TODO: new_fd_maybe
            new_file
        } else {
            None
        };

        if new_file != self.file {
            // self.file.close();
            self.file = new_file;
        }
        self.mode = mode;
        Ok((fd, self.qid, 0))
    }

    fn close(&self) -> io::Result<()> {
        self.mode = OpenFlags::invalid_mode();
        self.file = None;
        Ok(())
    }

    fn get_attr(&self, mask: AttrMask) -> io::Result<(QID, AttrMask, Attr)> {
        let file = self.file.unwrap();
        let stat = fstat(file)?;
        let (mask, attr) = self.fill_attr(&stat);
        Ok((self.qid, mask, attr))
    }

    fn walk_get_attr(
        &self,
        names: Vec<&str>,
    ) -> io::Result<(Vec<QID>, Box<dyn File>, AttrMask, Attr)> {
        let (qids, file, stat) = self.walk(names)?;
        let (mask, attr) = self.fill_attr(&stat);
        Ok((qids, file, mask, attr))
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

    pub fn dec_ref(&self) {
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

    pub fn maybe_parent(&self) -> Self {
        *self.parent.unwrap_or_else(|| Box::new(*self))
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted.load(Ordering::Relaxed)
    }
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
