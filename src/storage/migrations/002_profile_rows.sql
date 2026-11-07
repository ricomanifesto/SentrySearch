-- Revision 2: flat evidence relations, artifact policy, stored reader state.
-- Additive only: existing JSONB columns stay authoritative during dual-write.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS reader_state_version INTEGER;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS eligible_for_judgment BOOLEAN;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS eligible_for_acceptance BOOLEAN;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS eligible_for_handoff BOOLEAN;

CREATE INDEX IF NOT EXISTS ix_reports_eligible_for_handoff ON reports (eligible_for_handoff);

CREATE INDEX IF NOT EXISTS ix_reports_user_created ON reports (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS report_sources (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	source_id VARCHAR(20) NOT NULL,
	position INTEGER NOT NULL,
	url TEXT NOT NULL,
	domain VARCHAR(255),
	title TEXT,
	access_date TEXT,
	relevance_score TEXT,
	content_type TEXT,
	key_findings TEXT,
	snapshot_status VARCHAR(20),
	snapshot_sha256 VARCHAR(64),
	snapshot_captured_at TEXT,
	snapshot_final_url TEXT,
	page_age TEXT,
	purpose VARCHAR(40),
	disposition VARCHAR(30),
	rule_id VARCHAR(80),
	reason TEXT,
	PRIMARY KEY (report_id, source_id)
);

CREATE TABLE IF NOT EXISTS report_claims (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	claim_id VARCHAR(20) NOT NULL,
	position INTEGER NOT NULL,
	claim_class VARCHAR(40) NOT NULL,
	claim_field VARCHAR(40) NOT NULL,
	ordinal INTEGER NOT NULL,
	value TEXT NOT NULL,
	evidence_role VARCHAR(30),
	PRIMARY KEY (report_id, claim_id)
);

CREATE TABLE IF NOT EXISTS report_claim_support (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	claim_id VARCHAR(20) NOT NULL,
	position INTEGER NOT NULL,
	source_id VARCHAR(20) NOT NULL,
	excerpt TEXT NOT NULL,
	verified BOOLEAN,
	anchor_ok BOOLEAN,
	snapshot_sha256 VARCHAR(64),
	PRIMARY KEY (report_id, claim_id, position)
);

CREATE TABLE IF NOT EXISTS report_indicator_observations (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	position INTEGER NOT NULL,
	claim_id VARCHAR(20),
	field TEXT NOT NULL,
	ordinal INTEGER,
	value TEXT NOT NULL,
	disposition VARCHAR(30) NOT NULL,
	rule_id VARCHAR(80),
	reason TEXT,
	PRIMARY KEY (report_id, position)
);

CREATE TABLE IF NOT EXISTS report_source_observations (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	position INTEGER NOT NULL,
	source_id VARCHAR(20),
	title TEXT,
	url TEXT,
	domain VARCHAR(255),
	purpose VARCHAR(40),
	disposition VARCHAR(30),
	rule_id VARCHAR(80),
	reason TEXT,
	snapshot_status VARCHAR(20),
	snapshot_sha256 VARCHAR(64),
	page_age TEXT,
	PRIMARY KEY (report_id, position)
);

CREATE TABLE IF NOT EXISTS report_findings (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	position INTEGER NOT NULL,
	kind VARCHAR(20) NOT NULL,
	rule_id VARCHAR(80),
	selector TEXT,
	message TEXT NOT NULL,
	PRIMARY KEY (report_id, position)
);

CREATE TABLE IF NOT EXISTS report_artifacts (
	report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	kind VARCHAR(20) NOT NULL,
	sha256 VARCHAR(64),
	s3_key VARCHAR(500) NOT NULL,
	policy_status VARCHAR(20) NOT NULL,
	policy_version INTEGER NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (report_id, kind)
);

CREATE INDEX IF NOT EXISTS ix_report_artifacts_policy ON report_artifacts (kind, policy_status);

CREATE INDEX IF NOT EXISTS ix_report_tags_report_id ON report_tags (report_id);

CREATE INDEX IF NOT EXISTS ix_report_tags_tag ON report_tags (tag)
