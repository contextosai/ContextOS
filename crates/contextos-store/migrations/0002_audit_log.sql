-- Append-only, per-tenant hash-chained audit log. The primary key forbids forks:
-- two writers racing for the same sequence cannot both succeed. The application
-- role should be granted INSERT and SELECT only (no UPDATE/DELETE).
CREATE TABLE IF NOT EXISTS contextos_audit_log (
    tenant_id   TEXT        NOT NULL,
    sequence    BIGINT      NOT NULL CHECK (sequence > 0),
    record_hash TEXT        NOT NULL CHECK (record_hash ~ '^sha256:[0-9a-f]{64}$'),
    body        TEXT        NOT NULL,
    stored_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sequence)
);

CREATE OR REPLACE FUNCTION contextos_audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'contextos_audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS contextos_audit_log_no_update ON contextos_audit_log;
CREATE TRIGGER contextos_audit_log_no_update
    BEFORE UPDATE OR DELETE ON contextos_audit_log
    FOR EACH ROW EXECUTE FUNCTION contextos_audit_log_immutable();
