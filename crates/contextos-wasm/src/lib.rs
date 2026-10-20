//! WebAssembly exports for the ContextOS kernel.
//!
//! The host allocates input buffers inside the module, calls `ctx_call`, reads the
//! JSON response and frees every buffer:
//!
//! ```text
//! op  = ctx_alloc(op_len);  write op bytes
//! in  = ctx_alloc(in_len);  write input JSON bytes
//! r   = ctx_call(op, op_len, in, in_len)      // u64: (ptr << 32) | len
//! read response at (r >> 32) for (r & 0xffff_ffff) bytes
//! ctx_free(op, op_len); ctx_free(in, in_len); ctx_free(r >> 32, r & 0xffff_ffff)
//! ```
//!
//! The module imports nothing: no WASI, no clock, no randomness, no network.

#![allow(unsafe_code)]

/// Allocates `len` bytes for the host to write into.
#[unsafe(no_mangle)]
pub extern "C" fn ctx_alloc(len: u32) -> *mut u8 {
    let mut buffer = vec![0u8; len as usize].into_boxed_slice();
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr
}

/// Frees a buffer returned by [`ctx_alloc`] or [`ctx_call`].
///
/// # Safety
/// `ptr` and `len` must describe exactly one live buffer produced by this module,
/// freed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctx_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the caller guarantees (ptr, len) is a boxed slice we leaked.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len as usize)) });
}

/// Runs one facade operation. Returns `(ptr << 32) | len` of a JSON response buffer.
///
/// # Safety
/// `op_ptr`/`op_len` and `in_ptr`/`in_len` must describe readable buffers obtained
/// from [`ctx_alloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ctx_call(op_ptr: *const u8, op_len: u32, in_ptr: *const u8, in_len: u32) -> u64 {
    // SAFETY: the caller guarantees both buffers are valid for the given lengths.
    let (op, input) = unsafe {
        (
            std::slice::from_raw_parts(op_ptr, op_len as usize),
            std::slice::from_raw_parts(in_ptr, in_len as usize),
        )
    };
    let response = match std::str::from_utf8(op) {
        Ok(op) => contextos_embed::call(op, input),
        Err(_) => r#"{"error":{"code":"operation_unknown","message":"operation must be UTF-8"}}"#.to_owned(),
    };
    let mut bytes = response.into_bytes().into_boxed_slice();
    let len = bytes.len() as u64;
    let ptr = bytes.as_mut_ptr() as usize as u64;
    std::mem::forget(bytes);
    (ptr << 32) | len
}
