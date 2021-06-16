use std::os::raw::c_void;

use crate::message::Response;

#[inline]
pub fn alloc(size: usize) -> *const c_void {
    let mut buffer = Vec::with_capacity(size);
    let ptr = buffer.as_ptr();
    std::mem::forget(buffer);
    ptr
}

pub fn embed_response_to_string<T: Response + serde_traitobject::Any>(response: T) -> *const u8 {
    let response = serde_traitobject::Box::new(response);
    let mut s = serde_json::to_string(&response).unwrap();
    s = format!("{:0>4}", (s.len() + 4).to_string()) + &s;
    println!("request done {}\n", s);
    let ptr = alloc(s.len()) as *mut c_void;
    unsafe {
        std::ptr::copy(s.as_ptr() as *mut c_void, ptr, s.len());
    }
    ptr as *const u8
}
