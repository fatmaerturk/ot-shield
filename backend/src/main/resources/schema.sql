-- Drop existing tables to start fresh
DROP TABLE IF EXISTS user_groups CASCADE;
DROP TABLE IF EXISTS audit_records CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS asset_tags CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS anomaly_tags CASCADE;
DROP TABLE IF EXISTS anomaly_indicators CASCADE;
DROP TABLE IF EXISTS anomalies CASCADE;
-- NOTE: honeypot_logs is intentionally NOT dropped — attack telemetry
-- accumulates across restarts. The CREATE statement below uses IF NOT EXISTS
-- and any new columns are added via ALTER TABLE IF EXISTS at the end of the file.
DROP TABLE IF EXISTS alert_comments CASCADE;
DROP TABLE IF EXISTS alert_escalations CASCADE;
DROP TABLE IF EXISTS alert_rules CASCADE;
DROP TABLE IF EXISTS alert_notifications CASCADE;
DROP TABLE IF EXISTS nis2_requirements CASCADE;
DROP TABLE IF EXISTS nis2_email_notifications CASCADE;
DROP TABLE IF EXISTS nis2_compliance_reports CASCADE;
DROP TABLE IF EXISTS blocking_rules CASCADE;

-- Recreate users table with string ID type
CREATE TABLE users (
    id            VARCHAR(36)   PRIMARY KEY,
    email         VARCHAR(255)  NOT NULL UNIQUE,
    password      VARCHAR(255)  NOT NULL,
    full_name     VARCHAR(255),
    username      VARCHAR(255),
    role          VARCHAR(255),
    is_admin      BOOLEAN,
    is_suspended  BOOLEAN,
    is_expired    BOOLEAN,
    source        VARCHAR(255),
    created_at    TIMESTAMP,
    updated_at    TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    is_active     BOOLEAN,
    department    VARCHAR(255),
    phone_number  VARCHAR(50),
    avatar_url    VARCHAR(500),
    timezone      VARCHAR(100),
    language      VARCHAR(10),
    failed_login_attempts INTEGER DEFAULT 0,
    password_changed_at TIMESTAMP,
    requires_password_change BOOLEAN DEFAULT FALSE,
    manager_id    VARCHAR(36),
    employee_id   VARCHAR(100),
    job_title     VARCHAR(255),
    location      VARCHAR(255),
    notes         TEXT
);

-- Drop and recreate the ElementCollection join table using the JPA-expected column name
DROP TABLE IF EXISTS user_groups CASCADE;

CREATE TABLE user_groups (
    user_id VARCHAR(36) NOT NULL,    -- JPA expects "user_id", not "users_id"
    groups  VARCHAR(255)
);

-- Create indexes for users table
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_admin ON users(is_admin);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_department ON users(department);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login_at ON users(last_login_at);

-- Recreate audit_records table
CREATE TABLE audit_records (
    id           BIGSERIAL PRIMARY KEY,
    username     VARCHAR(255) NOT NULL,
    action_type  VARCHAR(100) NOT NULL,
    details      TEXT,
    timestamp    TIMESTAMP    NOT NULL
);

-- Create assets table
CREATE TABLE assets (
    id                    VARCHAR(36)   PRIMARY KEY,
    name                  VARCHAR(255)  NOT NULL,
    description           TEXT,
    ip_address            VARCHAR(45)   NOT NULL,
    mac_address           VARCHAR(17),
    asset_type            VARCHAR(50)   NOT NULL,
    asset_category        VARCHAR(50),
    purdue_level          VARCHAR(20),
    manufacturer          VARCHAR(255),
    model                 VARCHAR(255),
    serial_number         VARCHAR(255),
    firmware_version      VARCHAR(100),
    operating_system      VARCHAR(255),
    os_version            VARCHAR(100),
    hostname              VARCHAR(255),
    domain                VARCHAR(255),
    location              VARCHAR(255),
    department            VARCHAR(255),
    owner                 VARCHAR(255),
    responsible_person    VARCHAR(255),
    contact_email         VARCHAR(255),
    contact_phone         VARCHAR(50),
    purchase_date         TIMESTAMP,
    warranty_expiry       TIMESTAMP,
    last_maintenance      TIMESTAMP,
    next_maintenance      TIMESTAMP,
    criticality_level     VARCHAR(20),
    risk_score            INTEGER,
    vulnerability_count   INTEGER,
    patch_level           VARCHAR(100),
    backup_status         VARCHAR(30),
    monitoring_status     VARCHAR(30),
    is_active             BOOLEAN       DEFAULT TRUE,
    is_online             BOOLEAN       DEFAULT TRUE,
    last_seen             TIMESTAMP,
    first_seen            TIMESTAMP,
    created_at            TIMESTAMP     NOT NULL,
    updated_at            TIMESTAMP,
    created_by            VARCHAR(255),
    updated_by            VARCHAR(255),
    notes                 TEXT,
    custom_fields         TEXT
);

-- Create asset_tags table for ElementCollection
CREATE TABLE asset_tags (
    asset_id VARCHAR(36) NOT NULL,
    tag      VARCHAR(255)
);

-- Create anomalies table
CREATE TABLE anomalies (
    id                        VARCHAR(36)   PRIMARY KEY,
    title                     VARCHAR(255)  NOT NULL,
    description               TEXT,
    anomaly_type              VARCHAR(50)   NOT NULL,
    severity                  VARCHAR(20)   NOT NULL,
    status                    VARCHAR(20)   NOT NULL,
    source_ip                 VARCHAR(45)   NOT NULL,
    destination_ip            VARCHAR(45)   NOT NULL,
    source_port               INTEGER,
    destination_port          INTEGER,
    protocol                  VARCHAR(50),
    asset_type                VARCHAR(50),
    asset_category            VARCHAR(50),
    purdue_level              VARCHAR(20),
    manufacturer              VARCHAR(255),
    model                     VARCHAR(255),
    hostname                  VARCHAR(255),
    location                  VARCHAR(255),
    department                VARCHAR(255),
    evidence                  TEXT,
    mitigation_steps          TEXT,
    recommendations           TEXT,
    confidence_score          DOUBLE PRECISION,
    risk_score                DOUBLE PRECISION,
    false_positive_probability INTEGER,
    mitre_tactic              VARCHAR(255),
    mitre_technique           VARCHAR(255),
    mitre_id                  VARCHAR(255),
    custom_fields             TEXT,
    detected_at               TIMESTAMP,
    resolved_at               TIMESTAMP,
    acknowledged_at           TIMESTAMP,
    escalated_at              TIMESTAMP,
    created_at                TIMESTAMP     NOT NULL,
    updated_at                TIMESTAMP,
    created_by                VARCHAR(255)  NOT NULL,
    updated_by                VARCHAR(255),
    assigned_to               VARCHAR(255),
    resolved_by               VARCHAR(255),
    notes                     TEXT,
    is_active                 BOOLEAN       DEFAULT TRUE,
    is_escalated              BOOLEAN       DEFAULT FALSE,
    is_acknowledged           BOOLEAN       DEFAULT FALSE,
    is_resolved               BOOLEAN       DEFAULT FALSE,
    is_false_positive         BOOLEAN       DEFAULT FALSE
);

-- Create anomaly_tags table for ElementCollection
CREATE TABLE anomaly_tags (
    anomaly_id VARCHAR(36) NOT NULL,
    tag        VARCHAR(255)
);

-- Create anomaly_indicators table for ElementCollection
CREATE TABLE anomaly_indicators (
    anomaly_id VARCHAR(36) NOT NULL,
    indicator  VARCHAR(255)
);

-- Add indexes for better performance
CREATE INDEX idx_assets_ip_address ON assets(ip_address);
CREATE INDEX idx_assets_mac_address ON assets(mac_address);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_asset_type ON assets(asset_type);
CREATE INDEX idx_assets_purdue_level ON assets(purdue_level);
CREATE INDEX idx_assets_criticality_level ON assets(criticality_level);
CREATE INDEX idx_assets_is_active ON assets(is_active);
CREATE INDEX idx_assets_is_online ON assets(is_online);
CREATE INDEX idx_assets_last_seen ON assets(last_seen);
CREATE INDEX idx_assets_created_at ON assets(created_at);
CREATE INDEX idx_assets_updated_at ON assets(updated_at);
CREATE INDEX idx_assets_manufacturer ON assets(manufacturer);
CREATE INDEX idx_assets_location ON assets(location);
CREATE INDEX idx_assets_department ON assets(department);
CREATE INDEX idx_assets_owner ON assets(owner);
CREATE INDEX idx_assets_risk_score ON assets(risk_score);
CREATE INDEX idx_assets_vulnerability_count ON assets(vulnerability_count);
CREATE INDEX idx_assets_next_maintenance ON assets(next_maintenance);
CREATE INDEX idx_assets_warranty_expiry ON assets(warranty_expiry);

-- Add indexes for anomalies table
CREATE INDEX idx_anomalies_title ON anomalies(title);
CREATE INDEX idx_anomalies_anomaly_type ON anomalies(anomaly_type);
CREATE INDEX idx_anomalies_severity ON anomalies(severity);
CREATE INDEX idx_anomalies_status ON anomalies(status);
CREATE INDEX idx_anomalies_source_ip ON anomalies(source_ip);
CREATE INDEX idx_anomalies_destination_ip ON anomalies(destination_ip);
CREATE INDEX idx_anomalies_protocol ON anomalies(protocol);
CREATE INDEX idx_anomalies_asset_type ON anomalies(asset_type);
CREATE INDEX idx_anomalies_purdue_level ON anomalies(purdue_level);
CREATE INDEX idx_anomalies_hostname ON anomalies(hostname);
CREATE INDEX idx_anomalies_location ON anomalies(location);
CREATE INDEX idx_anomalies_department ON anomalies(department);
CREATE INDEX idx_anomalies_confidence_score ON anomalies(confidence_score);
CREATE INDEX idx_anomalies_risk_score ON anomalies(risk_score);
CREATE INDEX idx_anomalies_mitre_tactic ON anomalies(mitre_tactic);
CREATE INDEX idx_anomalies_mitre_technique ON anomalies(mitre_technique);
CREATE INDEX idx_anomalies_mitre_id ON anomalies(mitre_id);
CREATE INDEX idx_anomalies_detected_at ON anomalies(detected_at);
CREATE INDEX idx_anomalies_resolved_at ON anomalies(resolved_at);
CREATE INDEX idx_anomalies_acknowledged_at ON anomalies(acknowledged_at);
CREATE INDEX idx_anomalies_escalated_at ON anomalies(escalated_at);
CREATE INDEX idx_anomalies_created_at ON anomalies(created_at);
CREATE INDEX idx_anomalies_updated_at ON anomalies(updated_at);
CREATE INDEX idx_anomalies_created_by ON anomalies(created_by);
CREATE INDEX idx_anomalies_updated_by ON anomalies(updated_by);
CREATE INDEX idx_anomalies_assigned_to ON anomalies(assigned_to);
CREATE INDEX idx_anomalies_resolved_by ON anomalies(resolved_by);
CREATE INDEX idx_anomalies_is_active ON anomalies(is_active);
CREATE INDEX idx_anomalies_is_escalated ON anomalies(is_escalated);
CREATE INDEX idx_anomalies_is_acknowledged ON anomalies(is_acknowledged);
CREATE INDEX idx_anomalies_is_resolved ON anomalies(is_resolved);
CREATE INDEX idx_anomalies_is_false_positive ON anomalies(is_false_positive);

-- Create blocking_rules table
CREATE TABLE blocking_rules (
    id                    BIGSERIAL PRIMARY KEY,
    enabled               BOOLEAN       DEFAULT TRUE,
    protocol              VARCHAR(50),
    attack_type_contains  VARCHAR(100),
    min_severity          VARCHAR(20),
    min_reputation_score  INTEGER,
    block_action          BOOLEAN       DEFAULT TRUE,
    created_at            TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
);

-- Create honeypot_logs table — IF NOT EXISTS so attack telemetry survives restarts
CREATE TABLE IF NOT EXISTS honeypot_logs (
    id                BIGSERIAL PRIMARY KEY,
    timestamp         TIMESTAMP     NOT NULL,
    source_ip         VARCHAR(45)   NOT NULL,
    destination_ip    VARCHAR(45),
    source_port       INTEGER,
    destination_port  INTEGER,
    protocol          VARCHAR(50)   NOT NULL,
    attack_type       VARCHAR(100),
    payload           TEXT,
    severity          VARCHAR(20),
    description       TEXT,
    geo_location      VARCHAR(255),
    user_agent        VARCHAR(500),
    session_id        VARCHAR(255),
    username_attempt  VARCHAR(255),
    password_attempt  VARCHAR(255),
    country           VARCHAR(100),
    city              VARCHAR(100),
    is_blocked        BOOLEAN       DEFAULT FALSE,
    created_at        TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
);

-- Backfill: if an older honeypot_logs table is missing the credential / geo
-- columns we added later, create them now. PostgreSQL 9.6+ supports
-- "ADD COLUMN IF NOT EXISTS" so this is safe to re-run on every startup.
ALTER TABLE honeypot_logs ADD COLUMN IF NOT EXISTS username_attempt VARCHAR(255);
ALTER TABLE honeypot_logs ADD COLUMN IF NOT EXISTS password_attempt VARCHAR(255);
ALTER TABLE honeypot_logs ADD COLUMN IF NOT EXISTS country          VARCHAR(100);
ALTER TABLE honeypot_logs ADD COLUMN IF NOT EXISTS city             VARCHAR(100);
ALTER TABLE honeypot_logs ADD COLUMN IF NOT EXISTS decoy_source     VARCHAR(50);
ALTER TABLE honeypot_logs ADD COLUMN IF NOT EXISTS site_tag         VARCHAR(100);

-- Add indexes for blocking_rules table
CREATE INDEX idx_blocking_rules_enabled ON blocking_rules(enabled);
CREATE INDEX idx_blocking_rules_protocol ON blocking_rules(protocol);
CREATE INDEX idx_blocking_rules_min_severity ON blocking_rules(min_severity);

-- Add indexes for honeypot_logs table — IF NOT EXISTS so re-runs are safe
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_timestamp        ON honeypot_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_source_ip        ON honeypot_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_protocol         ON honeypot_logs(protocol);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_attack_type      ON honeypot_logs(attack_type);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_severity         ON honeypot_logs(severity);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_is_blocked       ON honeypot_logs(is_blocked);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_country          ON honeypot_logs(country);
CREATE INDEX IF NOT EXISTS idx_honeypot_logs_destination_port ON honeypot_logs(destination_port);

-- Create alert_comments table
CREATE TABLE alert_comments (
    id                VARCHAR(36)   PRIMARY KEY,
    alert_id          VARCHAR(36)   NOT NULL,
    comment_text      TEXT          NOT NULL,
    created_by        VARCHAR(255)  NOT NULL,
    created_at        TIMESTAMP     NOT NULL,
    updated_at        TIMESTAMP
);

-- Create alert_escalations table
CREATE TABLE alert_escalations (
    id                VARCHAR(36)   PRIMARY KEY,
    alert_id          VARCHAR(36)   NOT NULL,
    escalated_by      VARCHAR(255)  NOT NULL,
    escalated_to      VARCHAR(255)  NOT NULL,
    escalation_reason TEXT,
    escalated_at      TIMESTAMP     NOT NULL,
    resolved_at       TIMESTAMP,
    status            VARCHAR(50)   NOT NULL
);

-- Create alert_rules table
CREATE TABLE alert_rules (
    id                VARCHAR(36)   PRIMARY KEY,
    rule_name         VARCHAR(255)  NOT NULL,
    rule_description  TEXT,
    rule_type         VARCHAR(50)   NOT NULL,
    conditions        TEXT,
    actions           TEXT,
    is_active         BOOLEAN       DEFAULT TRUE,
    priority          INTEGER       DEFAULT 0,
    created_by        VARCHAR(255)  NOT NULL,
    created_at        TIMESTAMP     NOT NULL,
    updated_at        TIMESTAMP
);

-- Create alert_notifications table
CREATE TABLE alert_notifications (
    id                VARCHAR(36)   PRIMARY KEY,
    alert_id          VARCHAR(36)   NOT NULL,
    notification_type VARCHAR(50)   NOT NULL,
    recipient         VARCHAR(255)  NOT NULL,
    message           TEXT,
    sent_at           TIMESTAMP     NOT NULL,
    status            VARCHAR(50)   NOT NULL,
    error_message     TEXT
);

-- Create nis2_requirements table
CREATE TABLE nis2_requirements (
    id                VARCHAR(36)   PRIMARY KEY,
    requirement_code  VARCHAR(100)  NOT NULL,
    title             VARCHAR(255)  NOT NULL,
    description       TEXT,
    category          VARCHAR(100),
    priority          VARCHAR(50),
    compliance_status VARCHAR(50)   DEFAULT 'PENDING',
    created_at        TIMESTAMP     NOT NULL,
    updated_at        TIMESTAMP
);

-- Create nis2_email_notifications table
CREATE TABLE nis2_email_notifications (
    id                VARCHAR(36)   PRIMARY KEY,
    recipient         VARCHAR(255)  NOT NULL,
    subject           VARCHAR(500)  NOT NULL,
    message           TEXT          NOT NULL,
    sent_at           TIMESTAMP     NOT NULL,
    status            VARCHAR(50)   NOT NULL,
    error_message     TEXT
);

-- Create nis2_compliance_reports table
CREATE TABLE nis2_compliance_reports (
    id                VARCHAR(36)   PRIMARY KEY,
    report_name       VARCHAR(255)  NOT NULL,
    report_type       VARCHAR(100)  NOT NULL,
    generated_by      VARCHAR(255)  NOT NULL,
    generated_at      TIMESTAMP     NOT NULL,
    report_data       TEXT,
    compliance_score  DOUBLE PRECISION,
    status            VARCHAR(50)   NOT NULL
);

-- Add indexes for new tables
CREATE INDEX idx_alert_comments_alert_id ON alert_comments(alert_id);
CREATE INDEX idx_alert_comments_created_by ON alert_comments(created_by);
CREATE INDEX idx_alert_comments_created_at ON alert_comments(created_at);

CREATE INDEX idx_alert_escalations_alert_id ON alert_escalations(alert_id);
CREATE INDEX idx_alert_escalations_escalated_by ON alert_escalations(escalated_by);
CREATE INDEX idx_alert_escalations_status ON alert_escalations(status);

CREATE INDEX idx_alert_rules_rule_type ON alert_rules(rule_type);
CREATE INDEX idx_alert_rules_is_active ON alert_rules(is_active);
CREATE INDEX idx_alert_rules_priority ON alert_rules(priority);

CREATE INDEX idx_alert_notifications_alert_id ON alert_notifications(alert_id);
CREATE INDEX idx_alert_notifications_type ON alert_notifications(notification_type);
CREATE INDEX idx_alert_notifications_status ON alert_notifications(status);

CREATE INDEX idx_nis2_requirements_code ON nis2_requirements(requirement_code);
CREATE INDEX idx_nis2_requirements_category ON nis2_requirements(category);
CREATE INDEX idx_nis2_requirements_status ON nis2_requirements(compliance_status);

CREATE INDEX idx_nis2_email_notifications_recipient ON nis2_email_notifications(recipient);
CREATE INDEX idx_nis2_email_notifications_status ON nis2_email_notifications(status);

CREATE INDEX idx_nis2_compliance_reports_type ON nis2_compliance_reports(report_type);
CREATE INDEX idx_nis2_compliance_reports_generated_by ON nis2_compliance_reports(generated_by);
CREATE INDEX idx_nis2_compliance_reports_status ON nis2_compliance_reports(status);

-- Add unique constraints
ALTER TABLE assets ADD CONSTRAINT uk_assets_ip_address UNIQUE (ip_address);
ALTER TABLE assets ADD CONSTRAINT uk_assets_mac_address UNIQUE (mac_address);
ALTER TABLE assets ADD CONSTRAINT uk_assets_hostname UNIQUE (hostname);

-- =============================================================================
-- Phase-3 DPI (Deep Packet Inspection) events
-- Each row is one successfully-dissected ICS protocol PDU. Drives the
-- Network Topology detail panel and the "rare function code" heuristics.
-- =============================================================================
CREATE TABLE IF NOT EXISTS dpi_events (
    id                 VARCHAR(64) PRIMARY KEY,
    event_time         TIMESTAMP NOT NULL,
    source_ip          VARCHAR(64) NOT NULL,
    destination_ip     VARCHAR(64) NOT NULL,
    source_port        INTEGER,
    destination_port   INTEGER,
    protocol           VARCHAR(32) NOT NULL,
    function_code      VARCHAR(16),
    function_name      VARCHAR(64),
    pdu_kind           VARCHAR(16),
    is_write           BOOLEAN,
    is_exception       BOOLEAN,
    register_address   VARCHAR(32),
    area               VARCHAR(16),
    value              VARCHAR(64),
    summary            VARCHAR(512),
    dpi_fields_json    TEXT,
    pcap_session_id    VARCHAR(64),
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dpi_events_time ON dpi_events(event_time);
CREATE INDEX IF NOT EXISTS idx_dpi_events_src_dst ON dpi_events(source_ip, destination_ip);
CREATE INDEX IF NOT EXISTS idx_dpi_events_protocol ON dpi_events(protocol);
CREATE INDEX IF NOT EXISTS idx_dpi_events_function ON dpi_events(protocol, function_code);
CREATE INDEX IF NOT EXISTS idx_dpi_events_session ON dpi_events(pcap_session_id);

-- ========================================================================
-- Case Management (SOC investigation files)
-- ========================================================================

DROP TABLE IF EXISTS case_alerts CASCADE;
DROP TABLE IF EXISTS case_tags CASCADE;
DROP TABLE IF EXISTS case_artifacts CASCADE;
DROP TABLE IF EXISTS case_timeline_entries CASCADE;
DROP TABLE IF EXISTS cases CASCADE;

CREATE TABLE cases (
    id                           VARCHAR(36)   PRIMARY KEY,
    case_number                  VARCHAR(32)   NOT NULL UNIQUE,
    title                        VARCHAR(256)  NOT NULL,
    description                  TEXT,
    status                       VARCHAR(32)   NOT NULL,
    priority                     VARCHAR(16)   NOT NULL,
    severity                     VARCHAR(16),
    category                     VARCHAR(32),
    assignee_id                  VARCHAR(128),
    assignee_name                VARCHAR(128),
    reporter_id                  VARCHAR(128),
    reporter_name                VARCHAR(128),
    created_at                   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                   TIMESTAMP,
    acknowledged_at              TIMESTAMP,
    contained_at                 TIMESTAMP,
    resolved_at                  TIMESTAMP,
    closed_at                    TIMESTAMP,
    resolution_summary           TEXT,
    mtt_acknowledge_seconds      BIGINT,
    mtt_contain_seconds          BIGINT,
    mtt_resolve_seconds          BIGINT
);
CREATE INDEX IF NOT EXISTS idx_cases_status      ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_priority    ON cases(priority);
CREATE INDEX IF NOT EXISTS idx_cases_assignee    ON cases(assignee_id);
CREATE INDEX IF NOT EXISTS idx_cases_created_at  ON cases(created_at);

CREATE TABLE case_tags (
    case_id   VARCHAR(36)  NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    tag       VARCHAR(64)  NOT NULL,
    PRIMARY KEY (case_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_case_tags_tag ON case_tags(tag);

CREATE TABLE case_timeline_entries (
    id              VARCHAR(36)  PRIMARY KEY,
    case_id         VARCHAR(36)  NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ts              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    entry_type      VARCHAR(32)  NOT NULL,
    actor_id        VARCHAR(128),
    actor_name      VARCHAR(128),
    content         TEXT,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_case_timeline_case_id ON case_timeline_entries(case_id);
CREATE INDEX IF NOT EXISTS idx_case_timeline_ts      ON case_timeline_entries(ts);

CREATE TABLE case_artifacts (
    id              VARCHAR(36)   PRIMARY KEY,
    case_id         VARCHAR(36)   NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_type   VARCHAR(32)   NOT NULL,
    value           VARCHAR(512)  NOT NULL,
    label           VARCHAR(256),
    description     TEXT,
    added_by        VARCHAR(128),
    added_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    malicious       BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_case_artifacts_case_id ON case_artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_case_artifacts_type    ON case_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_case_artifacts_value   ON case_artifacts(value);

-- Join table for many-to-many Case <-> Alert.
-- FK to alerts(id) is intentionally omitted so that case creation does not
-- hard-depend on an existing alerts row (alerts table is managed elsewhere
-- and may not be present during a fresh bootstrap).
CREATE TABLE case_alerts (
    case_id   VARCHAR(36)  NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    alert_id  VARCHAR(36)  NOT NULL,
    PRIMARY KEY (case_id, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id);

-- =====================================================================
-- Research Studio (Faz 4.1) - Bundles are scoped workspaces. One bundle
-- owns a set of documents, threads, findings, vulnerability
-- observations, inventory, a summary, and an optional watch folder. A
-- default bundle is auto-seeded on first boot and existing rows (pre
-- Faz 4.1) are re-homed into it so no research data is lost during the
-- migration. bundle_id is nullable on every child table so the seeder
-- has something to target before it runs.
-- =====================================================================

CREATE TABLE IF NOT EXISTS research_bundles (
    id                 VARCHAR(64)   PRIMARY KEY,
    name               VARCHAR(256)  NOT NULL,
    slug               VARCHAR(128)  NOT NULL UNIQUE,
    tags               VARCHAR(512),
    watch_folder_path  VARCHAR(1024),
    watch_enabled      BOOLEAN       NOT NULL DEFAULT FALSE,
    description        VARCHAR(512),
    created_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bundles_updated_at ON research_bundles(updated_at);

-- =====================================================================
-- Research Studio (Faz 3) - offline document library that feeds the
-- Assistant's RAG retrieval. Each uploaded file yields one row here and
-- many chunk rows; the chunk embeddings are rehydrated into the
-- in-memory vector store on backend startup.
-- =====================================================================

CREATE TABLE IF NOT EXISTS research_documents (
    id             VARCHAR(64)   PRIMARY KEY,
    file_name      VARCHAR(512)  NOT NULL,
    size_bytes     BIGINT        NOT NULL,
    content_type   VARCHAR(128),
    storage_path   VARCHAR(1024) NOT NULL,
    product_label  VARCHAR(256),
    page_count     INTEGER,
    chunk_count    INTEGER       NOT NULL DEFAULT 0,
    status         VARCHAR(32)   NOT NULL,
    error_message  VARCHAR(2048),
    source_type    VARCHAR(32),
    uploaded_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ingested_at    TIMESTAMP
);
-- Additive migration for schemas created before Option C #3. UNKNOWN
-- is the conservative default; the classifier re-runs on next ingest.
ALTER TABLE research_documents ADD COLUMN IF NOT EXISTS source_type VARCHAR(32);
CREATE INDEX IF NOT EXISTS idx_research_docs_status      ON research_documents(status);
CREATE INDEX IF NOT EXISTS idx_research_docs_uploaded_at ON research_documents(uploaded_at);

CREATE TABLE IF NOT EXISTS research_document_chunks (
    id            VARCHAR(64)  PRIMARY KEY,
    document_id   VARCHAR(64)  NOT NULL REFERENCES research_documents(id) ON DELETE CASCADE,
    ordinal       INTEGER      NOT NULL,
    page_number   INTEGER,
    text          TEXT         NOT NULL,
    embedding     BYTEA        NOT NULL,
    source_label  VARCHAR(512) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chunks_document ON research_document_chunks(document_id);
CREATE INDEX IF NOT EXISTS idx_chunks_ordinal  ON research_document_chunks(document_id, ordinal);

-- =====================================================================
-- Research Studio (Faz 3.5) - persistent copilot conversations and the
-- curated Findings ledger. Threads capture raw Q/A turns with the
-- citations returned by RAG; Findings are analyst-approved knowledge
-- promoted out of a message and editable thereafter.
-- =====================================================================

CREATE TABLE IF NOT EXISTS research_threads (
    id             VARCHAR(64)   PRIMARY KEY,
    title          VARCHAR(256)  NOT NULL,
    last_question  VARCHAR(512),
    message_count  INTEGER       NOT NULL DEFAULT 0,
    created_at     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_research_threads_updated_at ON research_threads(updated_at);

CREATE TABLE IF NOT EXISTS research_messages (
    id                   VARCHAR(64)  PRIMARY KEY,
    thread_id            VARCHAR(64)  NOT NULL REFERENCES research_threads(id) ON DELETE CASCADE,
    role                 VARCHAR(16)  NOT NULL,
    content              TEXT         NOT NULL,
    citations_json       TEXT,
    confidence           VARCHAR(16),
    needs_more_sources   BOOLEAN,
    alternatives_json    TEXT,
    consistency_json     TEXT,
    created_at           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Additive migration for schemas that existed before the confidence
-- footer. IF NOT EXISTS keeps it idempotent on H2 and on Postgres >= 9.6.
ALTER TABLE research_messages ADD COLUMN IF NOT EXISTS confidence         VARCHAR(16);
ALTER TABLE research_messages ADD COLUMN IF NOT EXISTS needs_more_sources BOOLEAN;
-- Alternatives column added in Option C #2 - holds the JSON-serialised
-- list of contrarian hypotheses the researcher pulled for this answer.
ALTER TABLE research_messages ADD COLUMN IF NOT EXISTS alternatives_json  TEXT;
-- Consistency warnings added in Option C #6 - serialised output of
-- SourceCrossCheckService for this assistant turn.
ALTER TABLE research_messages ADD COLUMN IF NOT EXISTS consistency_json   TEXT;
CREATE INDEX IF NOT EXISTS idx_research_messages_thread         ON research_messages(thread_id);
CREATE INDEX IF NOT EXISTS idx_research_messages_thread_created ON research_messages(thread_id, created_at);

CREATE TABLE IF NOT EXISTS research_findings (
    id                 VARCHAR(64)   PRIMARY KEY,
    title              VARCHAR(256)  NOT NULL,
    text               TEXT          NOT NULL,
    citations_json     TEXT,
    source_thread_id   VARCHAR(64),
    source_message_id  VARCHAR(64),
    tags               VARCHAR(512),
    created_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_research_findings_created_at ON research_findings(created_at);

-- =====================================================================
-- Researcher annotations - sticky-note / highlight / flag primitives
-- attached polymorphically (target_kind + target_id) to messages,
-- documents, citations, or the bundle itself. Introduced in Paket 1 A
-- to close the HMGCC "researcher workflow" requirement.
-- =====================================================================
CREATE TABLE IF NOT EXISTS research_annotations (
    id            VARCHAR(64)   PRIMARY KEY,
    bundle_id     VARCHAR(64),
    target_kind   VARCHAR(32)   NOT NULL,
    target_id     VARCHAR(128)  NOT NULL,
    kind          VARCHAR(16)   NOT NULL,
    body          TEXT          NOT NULL,
    tags          VARCHAR(256),
    author        VARCHAR(128),
    created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_research_annotations_bundle  ON research_annotations(bundle_id);
CREATE INDEX IF NOT EXISTS idx_research_annotations_target  ON research_annotations(target_kind, target_id);
CREATE INDEX IF NOT EXISTS idx_research_annotations_created ON research_annotations(created_at);

-- =====================================================================
-- Vulnerability Observations - researcher-authored hypothesis ledger
-- aligned with the HMGCC Co-Creation "Smart personal assistant for
-- security researchers" challenge. Not a CVE tracker: every row carries
-- a lifecycle (DRAFT -> UNDER_REVIEW -> VERIFIED -> MITIGATED), a
-- confidence grade, optional alternative hypotheses, and the thread +
-- message that produced it so the researcher can rewind the
-- conversation weeks later. No online CVE lookup - offline-first.
-- =====================================================================

CREATE TABLE IF NOT EXISTS vulnerability_observations (
    id                      VARCHAR(64)   PRIMARY KEY,
    title                   VARCHAR(256)  NOT NULL,
    summary                 TEXT,
    component_type          VARCHAR(32)   NOT NULL,
    component_ref           VARCHAR(512),
    affected_product        VARCHAR(256),
    severity                VARCHAR(16)   NOT NULL,
    cve_id                  VARCHAR(64),
    cvss_v31                VARCHAR(128),
    confidence              VARCHAR(16)   NOT NULL,
    needs_more_sources      BOOLEAN       NOT NULL DEFAULT FALSE,
    status                  VARCHAR(24)   NOT NULL,
    mitigation_summary      TEXT,
    source_thread_id        VARCHAR(64),
    source_message_id       VARCHAR(64),
    citations_json          TEXT,
    alternative_hypotheses  TEXT,
    tags                    VARCHAR(512),
    created_at              TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by              VARCHAR(128),
    verified_by             VARCHAR(128)
);
CREATE INDEX IF NOT EXISTS idx_vulns_status            ON vulnerability_observations(status);
CREATE INDEX IF NOT EXISTS idx_vulns_severity          ON vulnerability_observations(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_updated           ON vulnerability_observations(updated_at);
CREATE INDEX IF NOT EXISTS idx_vulns_needs_sources     ON vulnerability_observations(needs_more_sources);

-- Append-only audit trail. Cascades delete with the parent so a hard
-- delete of an observation wipes its event history too.
CREATE TABLE IF NOT EXISTS vuln_events (
    id          VARCHAR(64) PRIMARY KEY,
    vuln_id     VARCHAR(64) NOT NULL REFERENCES vulnerability_observations(id) ON DELETE CASCADE,
    kind        VARCHAR(32) NOT NULL,
    from_status VARCHAR(24),
    to_status   VARCHAR(24),
    comment     TEXT,
    actor       VARCHAR(128),
    created_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vuln_events_vuln    ON vuln_events(vuln_id);
CREATE INDEX IF NOT EXISTS idx_vuln_events_created ON vuln_events(vuln_id, created_at);

-- =====================================================================
-- Faz 4.1 migration: add bundle_id to every Research table. Done with
-- ADD COLUMN IF NOT EXISTS so the script stays idempotent on installs
-- that already went through a previous boot. Foreign keys use ON DELETE
-- SET NULL so deleting a bundle doesn't cascade-wipe the research it
-- owned - the rows become orphans and the UI shows them under a "No
-- bundle" section until they're re-homed. BundleService seeds a
-- "Default Workspace" on startup and re-homes any NULL bundle_id rows
-- into it.
-- =====================================================================

ALTER TABLE research_documents
    ADD COLUMN IF NOT EXISTS bundle_id VARCHAR(64)
        REFERENCES research_bundles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_research_docs_bundle ON research_documents(bundle_id);

ALTER TABLE research_threads
    ADD COLUMN IF NOT EXISTS bundle_id VARCHAR(64)
        REFERENCES research_bundles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_research_threads_bundle ON research_threads(bundle_id);

ALTER TABLE research_findings
    ADD COLUMN IF NOT EXISTS bundle_id VARCHAR(64)
        REFERENCES research_bundles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_research_findings_bundle ON research_findings(bundle_id);

ALTER TABLE vulnerability_observations
    ADD COLUMN IF NOT EXISTS bundle_id VARCHAR(64)
        REFERENCES research_bundles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_vulns_bundle ON vulnerability_observations(bundle_id);

-- =====================================================================
-- Faz 4.2: one technical summary per bundle. Maps 1:1 via the shared
-- PK so there is no schema churn when a bundle is renamed and no orphan
-- summaries when a bundle is deleted (ON DELETE CASCADE).
-- =====================================================================

CREATE TABLE IF NOT EXISTS bundle_summaries (
    bundle_id            VARCHAR(64) PRIMARY KEY
        REFERENCES research_bundles(id) ON DELETE CASCADE,
    text                 TEXT,
    model                VARCHAR(128),
    prompt_tokens        INTEGER,
    generated_at         TIMESTAMP,
    edited_at            TIMESTAMP,
    edited_by            VARCHAR(128),
    source_doc_ids_json  TEXT,
    status               VARCHAR(16)
);

-- Backfill column on pre-existing installs (Faz 4.2 first version shipped
-- without the status column). Safe and idempotent.
ALTER TABLE bundle_summaries
    ADD COLUMN IF NOT EXISTS status VARCHAR(16);

-- =====================================================================
-- Faz 4.3: bundle inventory (components, ports, services, protocols).
-- Single-table design with a KIND discriminator so the UI can pivot
-- without duplicate schema. Rows cascade-delete with their bundle.
-- =====================================================================

CREATE TABLE IF NOT EXISTS inventory_items (
    id          VARCHAR(64)  PRIMARY KEY,
    bundle_id   VARCHAR(64)  NOT NULL
        REFERENCES research_bundles(id) ON DELETE CASCADE,
    kind        VARCHAR(24)  NOT NULL,
    name        VARCHAR(256) NOT NULL,
    details     TEXT,
    reference   VARCHAR(256),
    source      VARCHAR(512),
    tags        VARCHAR(512),
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_inventory_bundle      ON inventory_items(bundle_id);
CREATE INDEX IF NOT EXISTS idx_inventory_bundle_kind ON inventory_items(bundle_id, kind);

-- Async "deep extract" job table. One row per bundle; the regex path
-- does not use this table (it's synchronous and returns its result
-- directly in the HTTP response).
CREATE TABLE IF NOT EXISTS inventory_extraction_jobs (
    bundle_id      VARCHAR(64) PRIMARY KEY
        REFERENCES research_bundles(id) ON DELETE CASCADE,
    status         VARCHAR(16),
    message        VARCHAR(1024),
    items_created  INTEGER,
    started_at     TIMESTAMP,
    finished_at    TIMESTAMP
);

-- Other tables (e.g., user_groups, etc.) follow...