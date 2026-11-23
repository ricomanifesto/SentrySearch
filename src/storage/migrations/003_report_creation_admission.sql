-- Revision 3: bounded per-user creation budget, independent of report deletion.
CREATE TABLE IF NOT EXISTS report_creation_admissions (
    user_id VARCHAR(100) PRIMARY KEY,
    request_times JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_report_creation_admissions_bounded_times
        CHECK (jsonb_typeof(request_times) = 'array' AND jsonb_array_length(request_times) <= 6)
);

CREATE INDEX IF NOT EXISTS ix_report_creation_admissions_updated
    ON report_creation_admissions (updated_at);

CREATE INDEX IF NOT EXISTS ix_reports_user_generating
    ON reports (user_id) WHERE status = 'generating';

-- Preserve recent retained work at cutover. Earlier deleted rows cannot be
-- reconstructed. Writers must be drained throughout the release transaction.
INSERT INTO report_creation_admissions (user_id, request_times, updated_at)
SELECT user_id, jsonb_agg(EXTRACT(EPOCH FROM created_at) ORDER BY created_at), MAX(created_at)
FROM (
    SELECT user_id, created_at,
           row_number() OVER (PARTITION BY user_id ORDER BY created_at DESC) AS ordinal
    FROM reports
    WHERE user_id IS NOT NULL AND length(trim(user_id)) > 0
      AND created_at > NOW() - INTERVAL '1 hour'
) recent
WHERE ordinal <= 6
GROUP BY user_id
ON CONFLICT (user_id) DO NOTHING;
