//! Replicas sharing a PostgreSQL store see each other (runs when
//! `CONTEXTOS_TEST_DATABASE_URL` is set).

use std::time::Duration;

use contextosd::membership::heartbeat;

#[tokio::test]
async fn replicas_sharing_postgres_count_each_other() {
    let Ok(url) = std::env::var("CONTEXTOS_TEST_DATABASE_URL") else {
        eprintln!("skipped: CONTEXTOS_TEST_DATABASE_URL not set");
        return;
    };
    let store = contextos_store::postgres::PostgresStore::connect(&url, 4)
        .await
        .unwrap();
    // Far-future clock so rows from earlier runs have aged out.
    let now = 4_000_000_000_000_u64 + u64::from(std::process::id());
    let ttl = Duration::from_secs(15);
    let first = heartbeat(&store, "replica-a", now, ttl).await.unwrap();
    let second = heartbeat(&store, "replica-b", now + 1, ttl).await.unwrap();
    assert_eq!(second, first + 1, "the second replica sees the first");
    assert_eq!(
        heartbeat(&store, "replica-a", now + 20_000, ttl).await.unwrap(),
        1,
        "b aged out"
    );
}
