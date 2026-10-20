//! Hot-path latency of the pure kernel: what every governed effect pays in-process.

#![allow(clippy::pedantic)]

use std::hint::black_box;
use std::io::Read;

use contextos_contract::canonical::canonicalize;
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_kernel::authorization::{digest_action_binding, evaluate_authorization};
use contextos_kernel::{CompileDeps, ContextPackCompiler, STANDARD_PROFILE_REGISTRY, negotiate_execution_contract};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

fn load(name: &str) -> Value {
    let path = format!("{}/../../conformance/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap();
    let text = if name.ends_with(".gz") {
        let mut text = String::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_string(&mut text)
            .unwrap();
        text
    } else {
        String::from_utf8(bytes).unwrap()
    };
    serde_json::from_str(&text).unwrap()
}

fn benches(c: &mut Criterion) {
    let compiler_vectors = load("compiler.json");
    let case = compiler_vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap();
    let pack: ContextPack = serde_json::from_value(case["pack"].clone()).unwrap();
    let request: InvokeRequest = serde_json::from_value(case["request"].clone()).unwrap();
    let run: RunContext = serde_json::from_value(case["run_context"].clone()).unwrap();
    let deps = CompileDeps {
        evidence: case["deps"]["evidence"].as_array().unwrap().clone(),
        promoted_memory: case["deps"]["promoted_memory"].as_array().unwrap().clone(),
        ..CompileDeps::default()
    };
    let compiler = ContextPackCompiler::new(pack).unwrap();
    c.bench_function("compile_context_pack", |b| {
        b.iter(|| {
            compiler
                .compile(black_box(&request), black_box(&run), black_box(&deps))
                .unwrap()
        })
    });

    let auth = load("authorization.json.gz");
    let authorization_input = auth["authorization"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "base")
        .unwrap()["input"]
        .clone();
    c.bench_function("evaluate_authorization", |b| {
        b.iter(|| evaluate_authorization(black_box(&authorization_input)))
    });
    let binding = auth["digest"][0]["input"].clone();
    c.bench_function("digest_action_binding", |b| {
        b.iter(|| digest_action_binding(black_box(&binding)).unwrap())
    });
    c.bench_function("canonicalize_compiled_context", |b| {
        let value = serde_json::to_value(compiler.compile(&request, &run, &deps).unwrap()).unwrap();
        b.iter(|| canonicalize(black_box(&value)).unwrap());
    });
    let logic = json!({"and": [{"==": [{"var": "user.role"}, "support_agent"]}, {">": [{"var": "request.context.refund_amount"}, 3000]}]});
    let data = json!({"user": {"role": "support_agent"}, "request": {"context": {"refund_amount": 4200}}});
    c.bench_function("jsonlogic_predicate", |b| {
        b.iter(|| contextos_policy::predicate(black_box(&logic), black_box(&data)).unwrap())
    });

    let negotiation = load("negotiation.json.gz");
    let input = &negotiation["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["name"]
                .as_str()
                .unwrap()
                .starts_with("standard:contextos.high-assurance")
        })
        .unwrap()["input"];
    let registry = serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap();
    c.bench_function("negotiate_high_assurance", |b| {
        b.iter(|| {
            negotiate_execution_contract(
                black_box(&input["contract"]),
                black_box(&input["support"]),
                black_box(&registry),
                black_box(&input["features"]),
            )
        })
    });
}

criterion_group!(kernel, benches);
criterion_main!(kernel);
