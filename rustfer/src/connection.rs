use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::fs::{FIDRef, FID};

pub struct ConnState {
    pub fids: Arc<Mutex<HashMap<FID, FIDRef>>>,
}

impl ConnState {
    fn new() -> ConnState {
        ConnState {
            fids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn lookup_fid(&self, fid: FID) -> Option<FIDRef> {
        let mut fids = self.fids.lock().unwrap();
        fids.get_mut(&fid).map(|fidRef| {
            fidRef.inc_ref();
            fidRef.clone()
        })
    }
}
