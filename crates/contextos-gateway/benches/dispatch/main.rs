//! Full governed dispatch latency (memory store, signed audit, instant fake
//! providers): what the gateway adds on top of the provider call.

#![allow(clippy::all, clippy::pedantic, dead_code)]

mod fakes;
mod setup;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use contextos_store::{AppendLog, DocumentStore, MemoryLog, MemoryStore};
use criterion::{Criterion, criterion_group, criterion_main};

use fakes::Counting;
use setup::{Setup, admit, call, setup};

/// Sequential effects within fresh runs: per-effect latency.
async fn sequential<S: DocumentStore + 'static, L: AppendLog + 'static>(s: &Setup<S, L>, iterations: u64) -> Duration {
    let mut total = Duration::ZERO;
    let mut done = 0;
    while done < iterations {
        let admission = admit(s.store.as_ref()).await;
        let batch = (iterations - done).min(50);
        for i in 0..batch {
            let envelope = call(&admission.run_id, &format!("tc_{i}"), &format!("op_{i}"), i);
            let started = Instant::now();
            let out = s.gateway.dispatch(&admission, &envelope).await.unwrap();
            total += started.elapsed();
            assert_eq!(out.result["status"], "completed");
        }
        done += batch;
    }
    total
}

/// `RUNS_IN_PARALLEL` runs of one tenant, `EFFECTS_PER_RUN` effects each, dispatching
/// at once through one gateway, store and audit writer. Reported time per effect is
/// wall time / effects, so its inverse is single-tenant throughput.
const RUNS_IN_PARALLEL: u64 = 32;
const EFFECTS_PER_RUN: u64 = 50;

async fn concurrent<S: DocumentStore + 'static, L: AppendLog + 'static>(s: &Setup<S, L>, iterations: u64) -> Duration {
    let mut admissions = Vec::new();
    for _ in 0..RUNS_IN_PARALLEL {
        admissions.push(admit(s.store.as_ref()).await);
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for admission in admissions {
        let gateway = s.gateway.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..EFFECTS_PER_RUN {
                let envelope = call(&admission.run_id, &format!("tc_{i}"), &format!("op_{i}"), i);
                let out = gateway.dispatch(&admission, &envelope).await.unwrap();
                assert_eq!(out.result["status"], "completed");
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let effects = EFFECTS_PER_RUN * RUNS_IN_PARALLEL;
    // Scale to the requested iteration count.
    started.elapsed().mul_f64(iterations as f64 / effects as f64)
}

/// `CONTEXTOS_BENCH_COUNT=1`: store reads and writes per sequential effect (round trips
/// on PostgreSQL, besides the audit batch), instead of timings.
fn count_round_trips(runtime: &tokio::runtime::Runtime) {
    let store = Arc::new(Counting {
        inner: MemoryStore::new(),
        reads: AtomicU64::new(0),
        writes: AtomicU64::new(0),
    });
    let s = setup(store.clone(), MemoryLog::new());
    runtime.block_on(async {
        let admission = admit(s.store.as_ref()).await;
        // The first effect creates the run's ledgers; count the steady state.
        let first = call(&admission.run_id, "tc_first", "op_first", 100);
        s.gateway.dispatch(&admission, &first).await.unwrap();
        let (reads, writes) = (
            store.reads.load(Ordering::Relaxed),
            store.writes.load(Ordering::Relaxed),
        );
        for i in 0..10 {
            let envelope = call(&admission.run_id, &format!("tc_{i}"), &format!("op_{i}"), i);
            assert_eq!(
                s.gateway.dispatch(&admission, &envelope).await.unwrap().result["status"],
                "completed"
            );
        }
        let per = |now: u64, then: u64| (now - then) as f64 / 10.0;
        println!(
            "store operations per effect: {:.1} reads, {:.1} writes",
            per(store.reads.load(Ordering::Relaxed), reads),
            per(store.writes.load(Ordering::Relaxed), writes)
        );
    });
}

fn bench(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    if std::env::var("CONTEXTOS_BENCH_COUNT").is_ok() {
        count_round_trips(&runtime);
        return;
    }
    let memory = setup(Arc::new(MemoryStore::new()), MemoryLog::new());
    c.bench_function("gateway_dispatch_completed", |b| {
        b.to_async(&runtime).iter_custom(|n| sequential(&memory, n))
    });
    c.bench_function("gateway_dispatch_concurrent_32_runs", |b| {
        b.to_async(&runtime).iter_custom(|n| concurrent(&memory, n))
    });

    // PostgreSQL: set CONTEXTOS_BENCH_DATABASE_URL to a disposable database.
    if let Ok(url) = std::env::var("CONTEXTOS_BENCH_DATABASE_URL") {
        let store = runtime.block_on(async {
            let store = contextos_store::postgres::PostgresStore::connect(&url, 64)
                .await
                .unwrap();
            store.migrate().await.unwrap();
            store
        });
        let postgres = setup(Arc::new(store.clone()), store);
        let mut group = c.benchmark_group("postgres");
        group.sample_size(20);
        group.bench_function("gateway_dispatch_completed", |b| {
            b.to_async(&runtime).iter_custom(|n| sequential(&postgres, n))
        });
        group.bench_function("gateway_dispatch_concurrent_32_runs", |b| {
            b.to_async(&runtime).iter_custom(|n| concurrent(&postgres, n))
        });
        group.finish();
    }
}

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

criterion_group!(dispatch, bench);
criterion_main!(dispatch);
