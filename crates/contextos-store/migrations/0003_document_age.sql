-- Retention scans documents of one kind by age.
CREATE INDEX IF NOT EXISTS contextos_documents_kind_created ON contextos_documents (kind, created_at, tenant_id, id);
