extern crate libc;
use self::libc::{uint8_t, size_t};

use std::ptr;
use std::slice;
use keys::TPK;
use openpgp;

#[no_mangle]
pub extern "system" fn sq_tpk_from_bytes(b: *const uint8_t, len: size_t) -> *mut TPK {
    assert!(!b.is_null());
    let bytes = unsafe {
        slice::from_raw_parts(b, len as usize)
    };
    let m = openpgp::Message::from_bytes(bytes);

    if let Some(tpk) = m.ok().and_then(|m| TPK::from_message(m)) {
        Box::into_raw(Box::new(tpk))
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "system" fn sq_tpk_dump(tpk: *mut TPK) {
    assert!(!tpk.is_null());
    unsafe {
        println!("{:?}", *tpk);
    }
}

#[no_mangle]
pub extern "system" fn sq_tpk_free(tpk: *mut TPK) {
    if tpk.is_null() {
        return
    }
    unsafe {
        drop(Box::from_raw(tpk));
    }
}
