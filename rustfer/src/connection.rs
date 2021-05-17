use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::fs::{Attacher, FIDRef, PathNode, FID};

pub static CONNECTIONS: Lazy<Mutex<HashMap<i32, ConnState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub struct ConnState {
    // JOTODO: wrap with Arc, Mutex
    pub fids: HashMap<FID, FIDRef>,
    pub server: Server,
}

impl ConnState {
    pub fn new(server: Server) -> Self {
        Self {
            fids: HashMap::new(),
            server,
        }
    }

    pub fn insert_conn_state(fd: i32, cs: Self) {
        CONNECTIONS.lock().unwrap().insert(fd, cs);
    }

    pub fn delete_fid(&mut self, fid: &FID) -> bool {
        let fids = &mut self.fids;
        match fids.remove(fid) {
            Some(ref mut rf) => {
                rf.dec_ref();
                true
            }
            None => false,
        }
    }
}

pub struct Server {
    pub attacher: Box<dyn Attacher>,
    pub path_tree: PathNode,
}

impl Server {
    pub fn new(attacher: Box<dyn Attacher>) -> Self {
        Self {
            attacher,
            path_tree: PathNode::new(),
        }
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            attacher: dyn_clone::clone_box(&*self.attacher),
            path_tree: self.path_tree.clone(),
        }
    }
}

impl Hash for Server {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // JOETODO: implement Hash for Attacher.
        self.path_tree.hash(state);
    }
}
