use std::sync::atomic::Ordering;

use crate::connection::ConnState;
use crate::message::{Message, Rlerror, Rlopen, Tlopen};

trait Handler {
    fn handle(&self, cs: &ConnState) -> Box<dyn Message>;
}

impl Handler for Tlopen {
    fn handle(&self, cs: &ConnState) -> Box<dyn Message> {
        let mut fids = cs.fids.lock().unwrap();
        match fids.get_mut(&self.fid) {
            None => Box::new(Rlerror::new(0x9)),
            Some(ref mut fidRef) => {
                // TODO: mutex
                if fidRef.is_deleted.load(Ordering::Relaxed)
                    || fidRef.is_opened
                    || !fidRef.mode.can_open()
                {
                    return Box::new(Rlerror::new(0x16));
                }
                if fidRef.mode.is_dir() {
                    if !self.flags.is_read_only() || self.flags.truncated_flag() != 0 {
                        return Box::new(Rlerror::new(0x15));
                    }
                }
                match fidRef.file.open(self.flags) {
                    Err(errno) => Box::new(Rlerror::new(errno)),
                    Ok((os_file, qid, io_unit)) => {
                        fidRef.is_opened = true;
                        fidRef.open_flags = self.flags;
                        let mut rlopen = Rlopen::new(qid, io_unit);
                        rlopen.set_file_payload(os_file);
                        Box::new(rlopen)
                    }
                }
            }
        }
    }
}
