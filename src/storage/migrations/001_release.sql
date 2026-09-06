-- Initial product release baseline. Append new revisions. Do not edit applied SQL.
CREATE TABLE IF NOT EXISTS report_searches (
	id UUID NOT NULL,
	user_id VARCHAR(100),
	query TEXT,
	filters JSONB,
	results_count INTEGER,
	timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS report_tags (
	id UUID NOT NULL,
	report_id UUID NOT NULL,
	tag VARCHAR(100) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS reports (
	id UUID NOT NULL,
	tool_name VARCHAR(255) NOT NULL,
	category VARCHAR(100),
	threat_type VARCHAR(100),
	classification_status VARCHAR(30),
	claim_attribution_status VARCHAR(30),
	claim_attribution_version VARCHAR(10),
	evidence_admissibility_status VARCHAR(30),
	evidence_admissibility_version VARCHAR(10),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
	updated_at TIMESTAMP WITH TIME ZONE,
	quality_score NUMERIC(3, 2),
	confidence_score NUMERIC(3, 2),
	trust_score NUMERIC(3, 2),
	processing_time_ms INTEGER,
	api_calls_count INTEGER,
	threat_data JSONB,
	ml_techniques JSONB,
	quality_assessment JSONB,
	web_sources JSONB,
	evidence_admissibility JSONB,
	generation_route JSONB,
	research_route JSONB,
	synthesis_route JSONB,
	evaluation_route JSONB,
	evaluation_status VARCHAR(20),
	evaluation_error_code VARCHAR(50),
	evaluation_attempts INTEGER,
	evaluated_at TIMESTAMP WITH TIME ZONE,
	evaluation_lease_id UUID,
	evaluation_lease_expires_at TIMESTAMP WITH TIME ZONE,
	evaluation_recoveries INTEGER DEFAULT '0' NOT NULL,
	markdown_s3_key VARCHAR(500),
	trace_s3_key VARCHAR(500),
	api_key_hash VARCHAR(64),
	user_id VARCHAR(100),
	status VARCHAR(20),
	generation_stage VARCHAR(20),
	generation_failure_stage VARCHAR(20),
	generation_error_code VARCHAR(50),
	generation_retryable BOOLEAN,
	generation_failure JSONB,
	review_status VARCHAR(30),
	is_flagged BOOLEAN,
	is_favorite BOOLEAN,
	version VARCHAR(20),
	search_tags JSONB,
	content_preview TEXT,
	PRIMARY KEY (id)
);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'completed';

ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_stage VARCHAR(20) DEFAULT 'completed';

ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_failure_stage VARCHAR(20);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_error_code VARCHAR(50);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_retryable BOOLEAN;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_failure JSONB;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS review_status VARCHAR(30);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS classification_status VARCHAR(30);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS claim_attribution_status VARCHAR(30);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS claim_attribution_version VARCHAR(10);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evidence_admissibility_status VARCHAR(30) DEFAULT 'unassessed';

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evidence_admissibility_version VARCHAR(10);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evidence_admissibility JSONB;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS generation_route JSONB;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS research_route JSONB;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS synthesis_route JSONB;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_route JSONB;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_status VARCHAR(20);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_error_code VARCHAR(50);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_attempts INTEGER DEFAULT 0;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluated_at TIMESTAMPTZ;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_lease_id UUID;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_lease_expires_at TIMESTAMPTZ;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS evaluation_recoveries INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_reports_pending_evaluations ON reports (evaluation_status, evaluation_lease_expires_at);

ALTER TABLE reports ADD COLUMN IF NOT EXISTS content_preview TEXT;

CREATE INDEX IF NOT EXISTS ix_reports_review_status ON reports (review_status);

CREATE INDEX IF NOT EXISTS ix_reports_classification_status ON reports (classification_status);

CREATE INDEX IF NOT EXISTS ix_reports_claim_attribution_status ON reports (claim_attribution_status);

CREATE INDEX IF NOT EXISTS ix_reports_evidence_admissibility_status ON reports (evidence_admissibility_status);

CREATE TABLE IF NOT EXISTS report_disposition_events (id UUID PRIMARY KEY, report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE, reviewer_user_id VARCHAR(100) NOT NULL, disposition VARCHAR(30) NOT NULL, note TEXT, evaluation_attempt INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

CREATE INDEX IF NOT EXISTS ix_report_disposition_events_report_id ON report_disposition_events (report_id);

CREATE INDEX IF NOT EXISTS ix_report_disposition_events_disposition ON report_disposition_events (disposition);

CREATE INDEX IF NOT EXISTS ix_report_disposition_events_current ON report_disposition_events (report_id, evaluation_attempt, created_at DESC);

CREATE TABLE IF NOT EXISTS report_runtime_dispatches (report_id UUID PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE, runtime_run_id UUID, state VARCHAR(20) NOT NULL DEFAULT 'pending', dispatch_attempts INTEGER NOT NULL DEFAULT 0, last_error_code VARCHAR(50), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

CREATE INDEX IF NOT EXISTS ix_report_runtime_dispatches_pending ON report_runtime_dispatches (state, created_at);

ALTER TABLE report_runtime_dispatches ADD COLUMN IF NOT EXISTS lease_version BIGINT NOT NULL DEFAULT 0;

ALTER TABLE report_runtime_dispatches ADD COLUMN IF NOT EXISTS lease_owner TEXT;

CREATE INDEX IF NOT EXISTS ix_reports_category ON reports (category);

CREATE INDEX IF NOT EXISTS ix_reports_created_at ON reports (created_at);

CREATE INDEX IF NOT EXISTS ix_reports_status ON reports (status);

CREATE INDEX IF NOT EXISTS ix_reports_threat_type ON reports (threat_type);

CREATE INDEX IF NOT EXISTS ix_reports_tool_name ON reports (tool_name);
