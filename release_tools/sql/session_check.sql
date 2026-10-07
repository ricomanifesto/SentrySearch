-- Verifies the connected session before any release SQL runs: database, login,
-- verified TLS, the release session tag and the limits the client requested.
-- The server-side deadline is the earlier of the fixed job deadline and the
-- client's remaining budget anchored to this session's server clock.
SELECT set_config('release.deadline_epoch', least(:'deadline_epoch'::numeric,
           extract(epoch FROM statement_timestamp()) + :'remaining_ms'::numeric / 1000)::text,
           false) AS deadline,
       set_config('release.expect_database', :'expect_database', false) AS database,
       set_config('release.expect_principal', :'expect_principal', false) AS principal,
       set_config('release.application_name', :'application_name', false) AS application,
       set_config('release.limits',
           concat_ws(',', :'statement_ms', :'lock_ms', :'idle_ms', :'check_ms'), false) AS limits
\gset release_

DO $check$
BEGIN
    IF current_database() <> current_setting('release.expect_database') THEN
        RAISE EXCEPTION USING ERRCODE = 'RT001', MESSAGE = 'unexpected database';
    END IF;
    IF session_user <> current_setting('release.expect_principal')
       OR current_user <> current_setting('release.expect_principal') THEN
        RAISE EXCEPTION USING ERRCODE = 'RT002', MESSAGE = 'unexpected principal';
    END IF;
    IF NOT coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT003', MESSAGE = 'session is not encrypted';
    END IF;
    IF current_setting('application_name') <> current_setting('release.application_name') THEN
        RAISE EXCEPTION USING ERRCODE = 'RT004', MESSAGE = 'session tag mismatch';
    END IF;
    IF (SELECT string_agg(s.setting, ',' ORDER BY l.position)
        FROM unnest(ARRAY['statement_timeout', 'lock_timeout',
                          'idle_in_transaction_session_timeout',
                          'client_connection_check_interval'])
             WITH ORDINALITY AS l(name, position)
        JOIN pg_settings AS s ON s.name = l.name) IS DISTINCT FROM current_setting('release.limits') THEN
        RAISE EXCEPTION USING ERRCODE = 'RT005', MESSAGE = 'session limits mismatch';
    END IF;
END
$check$;
