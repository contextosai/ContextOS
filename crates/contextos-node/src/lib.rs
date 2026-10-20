//! `@contextos/kernel` native module.
//!
//! `callSync(operation, inputJson)` runs on the calling thread; `call(...)` runs on the
//! libuv thread pool and returns a Promise so the event loop never blocks on a large
//! compilation.

#![deny(clippy::all)]

use napi::bindgen_prelude::AsyncTask;
use napi::{Env, Task};
use napi_derive::napi;

/// Runs one kernel operation synchronously; returns the JSON response envelope.
#[napi(js_name = "callSync")]
pub fn call_sync(operation: String, input: String) -> String {
    contextos_embed::call(&operation, input.as_bytes())
}

pub struct KernelCall {
    operation: String,
    input: String,
}

impl Task for KernelCall {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        Ok(contextos_embed::call(&self.operation, self.input.as_bytes()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Runs one kernel operation on the thread pool.
#[napi(js_name = "call")]
pub fn call(operation: String, input: String) -> AsyncTask<KernelCall> {
    AsyncTask::new(KernelCall { operation, input })
}
