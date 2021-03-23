use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use once_cell::sync::OnceCell;

use crate::fs::{FIDRef, FID};

static CONN_STATE: OnceCell<Mutex<ConnState>> = OnceCell::new();

pub struct ConnState {
    pub fids: Arc<Mutex<HashMap<FID, FIDRef>>>,
}

impl ConnState {
    pub fn new() -> ConnState {
        ConnState {
            fids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn init() -> Result<(), Mutex<ConnState>> {
        CONN_STATE.set(Mutex::new(ConnState::new()))
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
