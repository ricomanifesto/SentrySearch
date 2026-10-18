-- Read-only count of foreign sessions on a restored instance, run only by a restore
-- verification's reconcile job, as the database owner, after reconcile.sql. A
-- foreign session is any session but this job's own connected to this database,
-- whatever its login role or application name. Excluded: engine processes, which
-- carry no user (NULL usesysid: autovacuum workers; the launcher, checkpointer and
-- writers have no database and are outside the scope anyway), and the bootstrap
-- superuser (role OID 10, the engine's own role; on RDS its management role). It
-- lists each one and never cancels or terminates anything; another role's start
-- time and state read unknown, as in reconcile.sql.
BEGIN READ ONLY;
SELECT 'result|foreign_sessions|' || count(*)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND datname = current_database()
  AND usesysid IS NOT NULL AND usesysid <> 10;
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
  AND datname = current_database()
  AND usesysid IS NOT NULL AND usesysid <> 10
ORDER BY backend_start, pid;
COMMIT;
