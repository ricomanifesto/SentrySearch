-- Read-only reconciliation of release sessions, run as the database owner in the
-- same database. It reports exact session identities (pid and backend start) and
-- never cancels or terminates anything. Sessions of other roles show only what
-- PostgreSQL exposes without pg_read_all_stats: their backend type, start time
-- and state are hidden and read as unknown.
BEGIN READ ONLY;
SELECT 'result|release_sessions|' || count(*)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND datname = current_database()
  AND left(application_name, length('release:' || :'release_id' || ':'))
      = 'release:' || :'release_id' || ':';
SELECT 'result|owner_sessions|' || count(*)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid() AND usename = current_user;
SELECT concat_ws('|', 'session', pid,
           coalesce(to_char(backend_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                    'unknown'),
           coalesce(datname, 'none'),
           coalesce(usename, 'none'),
           CASE WHEN application_name ~ '^[A-Za-z0-9:_.-]{1,63}$' THEN application_name
                ELSE 'other' END,
           replace(coalesce(state, 'unknown'), ' ', '_'))
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND coalesce(backend_type, 'client backend') = 'client backend'
  AND (usename = current_user
       OR (datname = current_database() AND left(application_name, 8) = 'release:'))
ORDER BY backend_start, pid;
COMMIT;
