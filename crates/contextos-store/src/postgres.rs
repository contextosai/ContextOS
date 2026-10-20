//! PostgreSQL store. Each operation is a single statement, so compare-and-swap is
//! atomic under any isolation level; no explicit transaction or lock is held across
//! a kernel decision.

use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::{DocKey, DocumentStore, StoreError, Versioned, decode, encode};

const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_documents.sql"),
    include_str!("../migrations/0002_audit_log.sql"),
];

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

fn backend(error: &sqlx::Error) -> StoreError {
    StoreError::Backend(error.to_string())
}

fn revision_of(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Integrity)
}

impl PostgresStore {
    /// Connects with a bounded pool.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        // No ping before every acquire: that doubles round trips. Broken connections
        // surface as errors on use, and idle/lifetime limits recycle them.
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .test_before_acquire(false)
            .idle_timeout(std::time::Duration::from_secs(300))
            .max_lifetime(std::time::Duration::from_secs(1800))
            .connect(url)
            .await
            .map_err(|e| backend(&e))?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies idempotent schema migrations.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        for statement in MIGRATIONS {
            sqlx::raw_sql(statement)
                .execute(&self.pool)
                .await
                .map_err(|e| backend(&e))?;
        }
        Ok(())
    }

    async fn current_revision(&self, key: &DocKey) -> Result<Option<u64>, StoreError> {
        let row =
            sqlx::query("SELECT revision FROM contextos_documents WHERE tenant_id = $1 AND kind = $2 AND id = $3")
                .bind(&key.tenant_id)
                .bind(key.kind.as_str())
                .bind(&key.id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| backend(&e))?;
        row.map(|r| revision_of(r.get::<i64, _>(0))).transpose()
    }
}

impl DocumentStore for PostgresStore {
    async fn get(&self, key: &DocKey) -> Result<Option<Versioned>, StoreError> {
        let row = sqlx::query(
            "SELECT revision, body, digest FROM contextos_documents WHERE tenant_id = $1 AND kind = $2 AND id = $3",
        )
        .bind(&key.tenant_id)
        .bind(key.kind.as_str())
        .bind(&key.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| backend(&e))?;
        row.map(|r| {
            decode(
                revision_of(r.get::<i64, _>(0))?,
                r.get::<&str, _>(1),
                r.get::<&str, _>(2),
            )
        })
        .transpose()
    }

    async fn create(&self, key: &DocKey, body: &Value) -> Result<Versioned, StoreError> {
        let (text, digest) = encode(body)?;
        let inserted = sqlx::query(
            "INSERT INTO contextos_documents (tenant_id, kind, id, revision, body, digest) VALUES ($1, $2, $3, 1, $4, $5) \
             ON CONFLICT (tenant_id, kind, id) DO NOTHING RETURNING revision",
        )
        .bind(&key.tenant_id)
        .bind(key.kind.as_str())
        .bind(&key.id)
        .bind(&text)
        .bind(&digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| backend(&e))?;
        match inserted {
            Some(_) => Ok(Versioned {
                revision: 1,
                body: body.clone(),
                digest,
            }),
            None => Err(StoreError::Conflict {
                expected: None,
                actual: self.current_revision(key).await?,
            }),
        }
    }

    async fn compare_and_swap(
        &self,
        key: &DocKey,
        expected_revision: u64,
        body: &Value,
    ) -> Result<Versioned, StoreError> {
        let encoded = crate::Encoded::of(body)?;
        let digest = encoded.digest.clone();
        let revision = self
            .compare_and_swap_encoded(key, expected_revision, body.clone(), encoded)
            .await?;
        Ok(Versioned {
            revision,
            body: body.clone(),
            digest,
        })
    }

    async fn compare_and_swap_encoded(
        &self,
        key: &DocKey,
        expected_revision: u64,
        _body: Value,
        encoded: crate::Encoded,
    ) -> Result<u64, StoreError> {
        let expected = i64::try_from(expected_revision).map_err(|_| StoreError::Integrity)?;
        let updated = sqlx::query(
            "UPDATE contextos_documents SET revision = revision + 1, body = $5, digest = $6, updated_at = now() \
             WHERE tenant_id = $1 AND kind = $2 AND id = $3 AND revision = $4 RETURNING revision",
        )
        .bind(&key.tenant_id)
        .bind(key.kind.as_str())
        .bind(&key.id)
        .bind(expected)
        .bind(&encoded.text)
        .bind(&encoded.digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| backend(&e))?;
        match updated {
            Some(row) => revision_of(row.get::<i64, _>(0)),
            None => match self.current_revision(key).await? {
                None => Err(StoreError::NotFound),
                actual => Err(StoreError::Conflict {
                    expected: Some(expected_revision),
                    actual,
                }),
            },
        }
    }
}

impl crate::AppendLog for PostgresStore {
    async fn head(&self, tenant_id: &str) -> Result<Option<crate::LogRow>, StoreError> {
        let row = sqlx::query(
            "SELECT sequence, record_hash, body FROM contextos_audit_log WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| backend(&e))?;
        row.map(|r| log_row(&r)).transpose()
    }

    async fn append_batch(&self, tenant_id: &str, batch: &[crate::AppendRow]) -> Result<(), StoreError> {
        let Some(first) = batch.first() else {
            return Ok(());
        };
        if batch.windows(2).any(|w| w[1].sequence != w[0].sequence + 1) {
            return Err(StoreError::Integrity);
        }
        let sequences = batch
            .iter()
            .map(|r| i64::try_from(r.sequence).map_err(|_| StoreError::Integrity))
            .collect::<Result<Vec<_>, _>>()?;
        let hashes: Vec<&str> = batch.iter().map(|r| r.record_hash.as_str()).collect();
        let texts: Vec<&str> = batch.iter().map(|r| r.text.as_str()).collect();
        // One statement: the batch must start right after the current head, and the
        // primary key rejects a concurrent writer for any of its sequences, which
        // aborts the whole statement.
        let inserted = sqlx::query(
            "INSERT INTO contextos_audit_log (tenant_id, sequence, record_hash, body) \
             SELECT $1, r.sequence, r.record_hash, r.body FROM unnest($2::bigint[], $3::text[], $4::text[]) \
               AS r(sequence, record_hash, body) \
             WHERE $5 = COALESCE((SELECT max(sequence) FROM contextos_audit_log WHERE tenant_id = $1), 0) + 1",
        )
        .bind(tenant_id)
        .bind(&sequences)
        .bind(&hashes)
        .bind(&texts)
        .bind(sequences[0])
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(done) if done.rows_affected() == batch.len() as u64 => Ok(()),
            Ok(_) => Err(StoreError::Conflict {
                expected: Some(first.sequence.saturating_sub(1)),
                actual: crate::AppendLog::head(self, tenant_id).await?.map(|h| h.sequence),
            }),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(StoreError::Conflict {
                expected: Some(first.sequence.saturating_sub(1)),
                actual: None,
            }),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn range(&self, tenant_id: &str, from: u64, limit: usize) -> Result<Vec<crate::LogRow>, StoreError> {
        let from = i64::try_from(from).map_err(|_| StoreError::Integrity)?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = sqlx::query(
            "SELECT sequence, record_hash, body FROM contextos_audit_log WHERE tenant_id = $1 AND sequence >= $2 \
             ORDER BY sequence ASC LIMIT $3",
        )
        .bind(tenant_id)
        .bind(from)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| backend(&e))?;
        rows.iter().map(log_row).collect()
    }
}

fn log_row(row: &sqlx::postgres::PgRow) -> Result<crate::LogRow, StoreError> {
    let body = serde_json::from_str(row.get::<&str, _>(2)).map_err(|_| StoreError::Integrity)?;
    Ok(crate::LogRow {
        sequence: revision_of(row.get::<i64, _>(0))?,
        record_hash: row.get::<String, _>(1),
        body,
    })
}
