//! `contextos._native`: the ContextOS kernel in-process for Python.
//!
//! One function, `call(operation, input_json) -> output_json`, mirrors the embed
//! facade. The GIL is released while the kernel runs, so concurrent Python threads
//! evaluate in parallel.

use pyo3::prelude::*;

/// Runs one kernel operation on JSON text and returns the JSON response envelope.
#[pyfunction]
fn call(py: Python<'_>, operation: &str, input: &str) -> String {
    let (operation, input) = (operation.to_owned(), input.to_owned());
    py.allow_threads(move || contextos_embed::call(&operation, input.as_bytes()))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(call, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
