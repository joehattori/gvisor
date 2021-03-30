use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicI64, Ordering};

use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};

use crate::message::{QIDType, QID};
use crate::rustfer::{reopen_proc_fd, AttachPoint, ALLOWED_OPEN_FLAGS, INVALID_MODE, OPEN_FLAGS};
use crate::unix;

pub type FID = u64;

#[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct OpenFlags(u32);

impl OpenFlags {
    const MASK: u32 = 3;

    const READ_ONLY: u32 = 0;
    const WRITE_ONLY: u32 = 1;
    const READ_WRITE: u32 = 2;
    const MODE_MASK: u32 = 3;
    pub const OPEN_TRUNCATE: u32 = 01000;

    fn masked_flag(&self) -> u32 {
        let OpenFlags(flags) = self;
        *flags & OpenFlags::MASK
    }

    pub fn truncated_flag(&self) -> u32 {
        let OpenFlags(flags) = self;
        *flags & OpenFlags::OPEN_TRUNCATE
    }

    pub fn is_read_only(&self) -> bool {
        self.masked_flag() == OpenFlags::READ_ONLY
    }
}

#[derive(Clone, Eq, PartialEq)]
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

#[derive(Clone, Eq, PartialEq)]
pub struct PathNode {
    child_nodes: HashMap<String, PathNode>,
    child_refs: HashMap<String, FIDRef>,
}

impl PathNode {
    pub fn new() -> Self {
        PathNode {
            child_nodes: HashMap::new(),
            child_refs: HashMap::new(),
        }
    }

    fn get_child_name_from_fid_ref(&self, fid_ref: &FIDRef) -> Option<String> {
        self.child_refs
            .iter()
            .find_map(|(k, v)| if v == fid_ref { Some(k.clone()) } else { None })
    }

    fn remove_child(&mut self, fid_ref: &FIDRef) {
        // TODO: mutex
        if let Some(name) = self.get_child_name_from_fid_ref(fid_ref) {
            match self.child_refs.remove(&name) {
                Some(_) => {
                    if self.child_refs.len() == 0 {
                        self.child_refs.remove(&name);
                    }
                }
                None => panic!("name {} missing from child_fid_refs", name),
            }
        }
    }
}

pub trait Attacher {
    fn attach<'a>(&self) -> Result<Box<dyn File>, &'a str>;
}

pub trait File: DynClone + Send {
    fn walk(&self, names: Vec<&str>) -> Result<Box<(Box<[QID]>, dyn File)>, u32>;
    fn open(&self, flags: OpenFlags) -> Result<(i32, QID, u32), u32>;
    fn close(&self) -> Result<(), u32>;
}

#[derive(Clone)]
pub struct Fd(pub i32);

#[derive(Clone)]
pub struct LocalFile {
    attach_point: AttachPoint,
    host_path: String,
    file: Fd,
    control_readable: bool,
    mode: OpenFlags,
    file_type: u32,
    qid: QID,
    last_dir_offset: u64,
}

impl LocalFile {
    pub fn new(
        a: &AttachPoint,
        file: Fd,
        path: &str,
        readable: bool,
        stat: &libc::stat,
    ) -> Result<Self, u32> {
        // TODO: checkSupportedFileType
        Ok(LocalFile {
            attach_point: *a,
            host_path: path.to_string(),
            file: file,
            mode: OpenFlags(INVALID_MODE),
            file_type: stat.st_mode & unix::S_IFMT,
            qid: a.make_qid(stat),
            control_readable: readable,
            last_dir_offset: 0,
        })
    }

    fn is_open(&self) -> bool {
        let OpenFlags(flag) = self.mode;
        flag != INVALID_MODE
    }

    fn check_ro_mount(&self) -> Result<(), u32> {
        if self.attach_point.config.ro_mount {
            Err(unix::EROFS)
        } else {
            Ok(())
        }
    }
}

impl File for LocalFile {
    fn walk(&self, names: Vec<&str>) -> Result<Box<(Box<[QID]>, dyn File)>, u32> {
        Err(23)
    }

    fn open(&self, flags: OpenFlags) -> Result<(i32, QID, u32), u32> {
        if self.is_open() {
            panic!("attempting to open already opened file: {}", self.host_path);
        }
        let OpenFlags(flags) = flags;
        let mode = flags & OpenFlags::MODE_MASK;
        if mode == OpenFlags::WRITE_ONLY
            || mode == OpenFlags::READ_WRITE
            || flags & OpenFlags::OPEN_TRUNCATE != 0
        {
            self.check_ro_mount()?;
        }

        let new_file = if mode == OpenFlags::READ_ONLY
            && self.control_readable
            && flags & ALLOWED_OPEN_FLAGS == 0
        {
            println!(
                "open reusing control file, flags: {}, {}",
                flags, self.host_path
            );
            self.file
        } else {
            println!("open reopening file, flags: {}, {}", flags, self.host_path);
            let os_flags = flags & (unix::O_ACCMODE | ALLOWED_OPEN_FLAGS);
            reopen_proc_fd(self.file, OPEN_FLAGS | os_flags)?;
        };

        let fd = if self.file_type == unix::S_IFREG {
        }
    }

    fn close(&self) -> Result<(), u32> {
        Err(23)
    }
}

fn new_fd_maybe(file: Fd)->Option<Fd> {
    // NEXT
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
}
