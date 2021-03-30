use libc;

use crate::fs::Fd;
use crate::unix;

pub fn open(path: &str, openmode: i32, perm: i32) -> Result<Fd, u32> {
    let fd = libc::open(
        path.as_ptr() as *mut i8,
        openmode | unix::O_LARGEFILE as i32,
        perm,
    );
    if fd < 0 {
        // TODO: return appropriate error
        Err(0)
    } else {
        Ok(Fd(fd))
    }
}
