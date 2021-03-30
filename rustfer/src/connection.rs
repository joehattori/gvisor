use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use once_cell::sync::OnceCell;

use crate::fs::{Attacher, FIDRef, PathNode, FID};

static CONN_STATE: OnceCell<Mutex<ConnState>> = OnceCell::new();

pub struct ConnState {
    pub fids: Arc<Mutex<HashMap<FID, FIDRef>>>,
    pub server: Server,
}

impl ConnState {
    pub fn new(server: Server) -> ConnState {
        ConnState {
            server: server,
            fids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get() -> &'static Mutex<ConnState> {
        &*CONN_STATE.get().unwrap()
    }

    pub fn lookup_fid(&self, fid: &FID) -> Option<FIDRef> {
        let mut fids = self.fids.lock().unwrap();
        fids.get_mut(&fid).map(|fid_ref| {
            fid_ref.inc_ref();
            fid_ref.clone()
        })
    }
}

pub struct Server {
    attacher: Box<dyn Attacher>,
    path_tree: PathNode,
}

impl Server {
    pub fn new(attacher: Box<dyn Attacher>) -> Self {
        Server {
            attacher: attacher,
            path_tree: PathNode::new(),
        }
    }
}
