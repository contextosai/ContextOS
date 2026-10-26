//! Load across replicas (opt-in).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextosd::router;
use serde_json::Value;

use crate::harness::*;

/// Load across replicas sharing one store and audit log. Opt-in:
/// `cargo test --release -p contextosd --test dispatch load -- --ignored --nocapture`
/// (`CONTEXTOS_LOAD_REPLICAS`, `CONTEXTOS_LOAD_AGENTS`, `CONTEXTOS_LOAD_RUNS`).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load test; run explicitly"]
#[allow(clippy::cast_precision_loss)]
async fn load_across_replicas() {
    let env = |name: &str, default: usize| std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default);
    let (replicas, agents, runs) = (
        env("CONTEXTOS_LOAD_REPLICAS", 3),
        env("CONTEXTOS_LOAD_AGENTS", 64),
        env("CONTEXTOS_LOAD_RUNS", 20),
    );
    // PostgreSQL when CONTEXTOS_TEST_DATABASE_URL is set (replicas share the database),
    // otherwise one shared in-memory store.
    let (bases, provider_calls, backend) = if let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") {
        {
            let (config, provider_calls) = world_setup(&ALL_CONTROLS).await;
            let store = Arc::new(
                contextos_store::postgres::PostgresStore::connect(&url, 64)
                    .await
                    .unwrap(),
            );
            store.migrate().await.unwrap();
            let mut bases = Vec::new();
            for _ in 0..replicas.max(1) {
                let state = replica_state(&config, store.clone(), (*store).clone());
                bases.push(serve(router(state, Duration::from_secs(10))).await);
            }
            (bases, provider_calls, "postgres")
        }
    } else {
        let w = world_n(&ALL_CONTROLS, replicas).await;
        (w.bases, w.provider_calls, "memory")
    };
    // Run ids unique to this execution (a database keeps earlier runs).
    let prefix = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(agents)
        .build()
        .unwrap();
    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for agent in 0..agents {
        let (http, bases, prefix) = (http.clone(), bases.clone(), prefix.clone());
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(runs * 2);
            let mut admissions = Vec::with_capacity(runs);
            for i in 0..runs {
                let run = format!("run_load_{prefix}_{agent}_{i}");
                // Admit on one replica, act on another: ownership and audit are shared.
                let (admit_at, act_at) = (&bases[(agent + i) % bases.len()], &bases[(agent + i + 1) % bases.len()]);
                let t = std::time::Instant::now();
                let admitted: Value = http
                    .post(format!("{admit_at}/v1/runs"))
                    .bearer_auth("acme-key")
                    .json(&run_body(&run, 1200))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                latencies.push(t.elapsed());
                admissions.push(t.elapsed());
                let generation = admitted["executor_generation"].as_u64().unwrap();
                let t = std::time::Instant::now();
                let out: Value = http
                    .post(format!("{act_at}/v1/runs/{run}/tool-calls"))
                    .bearer_auth("acme-key")
                    .header("contextos-executor-generation", generation.to_string())
                    .json(&tool_call(&run, "tc_1", 120_000))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                latencies.push(t.elapsed());
                assert_eq!(out["result"]["status"], "completed", "{out}");
            }
            (latencies, admissions)
        }));
    }
    let (mut latencies, mut admissions): (Vec<Duration>, Vec<Duration>) = (Vec::new(), Vec::new());
    for task in tasks {
        let (all, admitted) = task.await.unwrap();
        latencies.extend(all);
        admissions.extend(admitted);
    }
    admissions.sort();
    println!(
        "admission latency p50 {:.2?} p99 {:.2?}",
        admissions[admissions.len() / 2],
        admissions[admissions.len() * 99 / 100]
    );
    let elapsed = started.elapsed();
    latencies.sort();
    let pct = |per_mille: usize| latencies[(latencies.len() - 1) * per_mille / 1000];
    let effects = agents * runs;
    println!(
        "{backend}: {replicas} replicas, {agents} agents x {runs} runs: {effects} admitted runs + governed effects in {elapsed:.2?} \
         ({:.0} effects/s, {:.0} requests/s); request latency p50 {:.2?} p99 {:.2?} max {:.2?}",
        effects as f64 / elapsed.as_secs_f64(),
        (effects * 2) as f64 / elapsed.as_secs_f64(),
        pct(500),
        pct(990),
        latencies.last().unwrap()
    );
    // Every replica appended to one tenant chain. It must verify: here, this execution's
    // segment, continuing the entry before it (a shared database also holds entries other
    // suites signed with other keys), exactly as `ctx audit-verify --continues` does.
    let mut entries: Vec<contextos_audit::AuditEntry> = Vec::new();
    let mut cursor = Some(1_u64);
    while let Some(from) = cursor {
        let page: Value = http
            .get(format!("{}/v1/audit/entries?from={from}&limit=1000", bases[0]))
            .bearer_auth("acme-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        entries.extend(serde_json::from_value::<Vec<contextos_audit::AuditEntry>>(page["entries"].clone()).unwrap());
        cursor = page["next"].as_u64();
    }
    let marker = format!("run_load_{prefix}_");
    let start = entries
        .iter()
        .position(|e| e.payload.to_string().contains(&marker))
        .expect("this run's entries");
    let mut ring = contextos_audit::KeyRing::new();
    let signer = AuditSigner::from_seed("audit-test", [5; 32]);
    ring.insert(signer.kid(), signer.verifying_key());
    let anchor = start.checked_sub(1).map(|i| &entries[i]);
    contextos_audit::verify_chain(&entries[start..], anchor, &ring)
        .expect("every replica's entries verify as one chain");
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        effects,
        "exactly one provider call per effect"
    );
}
