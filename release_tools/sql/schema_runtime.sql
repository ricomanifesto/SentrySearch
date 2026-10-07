-- Reports the applied Goose versions of the runtime ledger (latest row per version).
SELECT 'result|schema|goose:'
       || coalesce(string_agg(version_id::text, ',' ORDER BY version_id), 'none')
FROM (
    SELECT DISTINCT ON (version_id) version_id, is_applied
    FROM public.goose_db_version
    WHERE version_id > 0
    ORDER BY version_id, id DESC
) AS latest
WHERE is_applied;
