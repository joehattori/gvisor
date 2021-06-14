use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use crate::fs::{Attacher, FIDRef, PathNode, FID};

static CONNECTIONS: Lazy<Mutex<HashMap<i32, Arc<Mutex<ConnState>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn lookup_conn_state(io_fd: i32) -> Arc<Mutex<ConnState>> {
    // NEXT: change Rc RefCell to Arc Mutex?
    let c = CONNECTIONS.lock().unwrap();
    Arc::clone(
        c.get(&io_fd)
            .expect(&format!("No ConnState corresponding to fd: {}", io_fd)),
    )
}

pub struct ConnState {
    // JOTODO: wrap with Arc, Mutex
    pub fids: Arc<Mutex<HashMap<FID, FIDRef>>>,
    pub server: Server,
}

impl ConnState {
    pub fn new(server: Server) -> Self {
        Self {
            fids: Arc::new(Mutex::new(HashMap::new())),
            server,
        }
    }

    pub fn insert_conn_state(fd: i32, cs: Self) {
        CONNECTIONS
            .lock()
            .unwrap()
            .insert(fd, Arc::new(Mutex::new(cs)));
    }

    pub fn lookup_fid(&mut self, fid: u64) -> Option<FIDRef> {
        let fids = &mut self.fids.lock().unwrap();
        match fids.get_mut(&fid) {
            Some(rf) => {
                rf.inc_ref();
                Some(rf.clone())
            }
            None => None,
        }
    }

    pub fn delete_fid(&mut self, fid: &FID) -> bool {
        let fids = &mut self.fids.lock().unwrap();
        match fids.remove(fid) {
            Some(mut rf) => {
                rf.dec_ref();
                true
            }
            None => false,
        }
    }
    pub fn insert_fid(&mut self, fid: FID, mut new_ref: FIDRef) {
        let fids = &mut self.fids.lock().unwrap();
        new_ref.inc_ref();
        if let Some(mut orig) = fids.insert(fid, new_ref) {
            orig.dec_ref();
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
