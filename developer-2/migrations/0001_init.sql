-- SkillSentry Schema Migration 0001: Initial Schema
-- Source: docs/03-database.md §3.4
-- Applied by: Dev 1 orchestrator or manual CLI invocation
-- Dev 2 provides this DDL; Dev 1 owns the migration runner.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Metadata table for schema versioning
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Core scan cache table
CREATE TABLE IF NOT EXISTS scan_cache (
    content_hash        TEXT PRIMARY KEY,
    skill_name          TEXT NOT NULL,
    verdict             TEXT NOT NULL CHECK (verdict IN ('SAFE','SUSPICIOUS','MALICIOUS')),
    risk_score          INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    confidence          REAL,
    verdict_json        TEXT NOT NULL,
    sarif_json          TEXT NOT NULL,
    active_defense_json TEXT,
    engine_version      TEXT NOT NULL,
    model_backend       TEXT NOT NULL,
    model_version       TEXT NOT NULL,
    scan_duration_ms    INTEGER,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Set initial schema version
INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '1');

