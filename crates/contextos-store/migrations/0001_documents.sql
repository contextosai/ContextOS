-- Protected ContextOS documents. Bodies are RFC 8785 canonical JSON text, verified
-- against `digest` on every read. Writes are compare-and-swap on `revision`.
CREATE TABLE IF NOT EXISTS contextos_documents (
    tenant_id  TEXT        NOT NULL,
    kind       TEXT        NOT NULL,
    id         TEXT        NOT NULL,
    revision   BIGINT      NOT NULL CHECK (revision > 0),
    body       TEXT        NOT NULL,
    digest     TEXT        NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, id)
);
