-- How far the schema is migrated, so a runtime role without DDL rights can confirm the
-- schema is current instead of re-running the migrations.
CREATE TABLE IF NOT EXISTS contextos_schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version   INTEGER NOT NULL
);
