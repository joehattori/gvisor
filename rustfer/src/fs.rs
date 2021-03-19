use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicI64, Ordering};

use dyn_clone::DynClone;

use crate::message::QID;

pub type FID = u64;

#[derive(Copy, Clone)]
pub struct OpenFlags(u32);

impl OpenFlags {
    const MASK: u32 = 3;

    const READY_ONLY: u32 = 0;
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
        self.masked_flag() == OpenFlags::READY_ONLY
    }
}

#[derive(Clone)]
pub struct FileMode(u32);

impl FileMode {
    const MASK: u32 = 0170000;

    const MODE_REGULAR: u32 = 0100000;
    const MODE_DIRECTORY: u32 = 040000;
    const MODE_NAMED_PIPE: u32 = 010000;
    const MODE_BLOCK_DEVICE: u32 = 060000;
    const MODE_CHARACTER_DEVICE: u32 = 020000;

    fn masked_mode(&self) -> u32 {
        let FileMode(mode) = self;
        *mode & FileMode::MASK
    }

    pub fn is_regular(&self) -> bool {
        self.masked_mode() == FileMode::MODE_REGULAR
    }

    pub fn is_dir(&self) -> bool {
        self.masked_mode() == FileMode::MODE_DIRECTORY
    }

    pub fn is_name_pipe(&self) -> bool {
        self.masked_mode() == FileMode::MODE_NAMED_PIPE
    }

    pub fn is_block_dev(&self) -> bool {
        self.masked_mode() == FileMode::MODE_BLOCK_DEVICE
    }

    pub fn is_char_dev(&self) -> bool {
        self.masked_mode() == FileMode::MODE_CHARACTER_DEVICE
    }

    pub fn can_open(&self) -> bool {
        self.is_regular()
            || self.is_dir()
            || self.is_name_pipe()
            || self.is_block_dev()
            || self.is_char_dev()
    }
}

#[derive(Clone)]
pub struct PathNode {
    child_nodes: HashMap<String, PathNode>,
    child_refs: HashMap<String, FIDRef>,
    child_ref_names: HashMap<FIDRef, String>,
}

pub trait File: DynClone {
    fn walk(&self, names: [String]) -> Result<Box<(Box<[QID]>, dyn File)>, u32>;
    fn open(&self, flags: OpenFlags) -> Result<(i32, QID, u32), u32>;
}

pub struct FIDRef {
    pub file: Box<dyn File>,
    pub refs: AtomicI64,
    pub is_opened: bool,
    pub mode: FileMode,
    pub open_flags: OpenFlags,
    pub path_node: PathNode,
    pub parent: Box<FIDRef>,
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

impl FIDRef {
    pub fn inc_ref(&mut self) {
        self.refs
            .store(self.refs.load(Ordering::Relaxed) + 1, Ordering::Relaxed)
    }
}
