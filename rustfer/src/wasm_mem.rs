use std::os::raw::c_void;

use crate::message::Response;

pub fn alloc(size: usize) -> *mut c_void {
    let mut buffer = Vec::with_capacity(size);
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);

    ptr as *mut c_void
}

pub fn embed_response_to_string<T: Response + serde_traitobject::Any>(response: T) -> *const u8 {
    let response = serde_traitobject::Box::new(response);
    let s = serde_json::to_string(&response).unwrap();
    let ptr = alloc(s.len());
    unsafe {
        std::ptr::copy(s.as_ptr() as *mut c_void, ptr, s.len());
    }
    ptr as *const u8
}
