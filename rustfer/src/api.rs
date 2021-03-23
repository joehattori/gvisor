use std::ffi::CStr;
use std::mem;
use std::os::raw::{c_char, c_void};

use crate::message::{Request, Tlopen};

#[no_mangle]
fn rustfer_allocate(size: usize) -> *mut c_void {
    let mut buffer = Vec::with_capacity(size);
    let pointer = buffer.as_mut_ptr();
    mem::forget(buffer);

    pointer as *mut c_void
}

#[no_mangle]
fn rustfer_deallocate(pointer: *mut c_void, capacity: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(pointer, 0, capacity);
    }
}

#[no_mangle]
fn rustfer_open(tlopen: *mut c_char) -> *const u8 {
    handle::<Tlopen>(tlopen)
}

fn handle<T: serde_traitobject::Deserialize>(msg: *mut c_char) -> *const u8 {
    let msg = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
    let msg: Tlopen = serde_json::from_str(&msg).unwrap();
    let res = msg.handle();
    serde_json::to_string(&res).unwrap().as_ptr()
}
