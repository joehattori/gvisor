use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use crate::fs::{Attacher, FIDRef, PathNode, FID};

static CONNECTIONS: Lazy<Mutex<HashMap<i32, ConnState>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub struct ConnState {
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
        CONNECTIONS.lock().unwrap().insert(fd, cs);
    }

    pub fn get_conn_state(fd: i32) -> Self {
        let cs = CONNECTIONS.lock().unwrap();
        // JOETODO: debug code
        match cs.get(&fd) {
            None => println!("get_conn_state: No ConnState correspodint to fd: {}", fd),
            _ => (),
        };
        cs.get(&fd)
            .expect(&format!("No ConnState corresponding to fd: {}", fd))
            .clone()
    }

    pub fn lookup_fid(&self, fid: &FID) -> Option<FIDRef> {
        let mut fids = self.fids.lock().unwrap();
        fids.get_mut(&fid).map(|fid_ref| {
            fid_ref.inc_ref();
            fid_ref.clone()
        })
    }

    pub fn insert_fid(&self, fid: &FID, new_ref: &mut FIDRef) {
        println!("inserting fid: {}, mode: {:?}", fid, new_ref.mode);
        new_ref.inc_ref();
        let mut fids = self.fids.lock().unwrap();
        if let Some(mut orig) = fids.insert(*fid, new_ref.clone()) {
            orig.dec_ref();
        }
    }

    pub fn delete_fid(&self, fid: &FID) -> bool {
        let mut fids = self.fids.lock().unwrap();
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
