-- Least-authority proof for the runtime service login, run as that login by the
-- release-tools proof job. Fixtures live in one transaction that always rolls
-- back. The privilege inventory must equal db/roles/service.sql exactly, and each
-- forbidden operation must fail with insufficient_privilege (42501); anything
-- else fails the job with its RT1xx code or the server's own error.
BEGIN;
SELECT set_config('release.owner_role', :'owner_role', true) AS owner \gset proof_

DO $proof$
DECLARE
    owner_name text := current_setting('release.owner_role');
    service_oid oid;
    run uuid;
    code text;
    statement text;
BEGIN
    SELECT oid INTO service_oid FROM pg_roles
      WHERE rolname = current_user AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
        AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls;
    IF service_oid IS NULL OR EXISTS (SELECT FROM pg_auth_members WHERE member = service_oid) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT101', MESSAGE = 'service login is privileged';
    END IF;
    -- Any member (INHERIT, SET, or ADMIN to grant itself SET) could act as the
    -- service login or owner; only administrators may hold a membership.
    IF EXISTS (SELECT FROM pg_auth_members m
               JOIN pg_roles r ON r.oid = m.roleid
               JOIN pg_roles holder ON holder.oid = m.member
               WHERE r.rolname IN (current_user, owner_name)
                 AND NOT (holder.rolsuper OR holder.rolcreaterole)) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT107', MESSAGE = 'another role can act as a login';
    END IF;
    IF owner_name = current_user OR NOT EXISTS (
        SELECT FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
        WHERE d.datname = current_database() AND r.rolname = owner_name) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT102', MESSAGE = 'database owner mismatch';
    END IF;
    IF EXISTS (SELECT FROM pg_database WHERE datdba = service_oid)
       OR EXISTS (SELECT FROM pg_namespace WHERE nspowner = service_oid)
       OR EXISTS (SELECT FROM pg_class WHERE relowner = service_oid)
       OR EXISTS (SELECT FROM pg_proc WHERE proowner = service_oid)
       OR EXISTS (SELECT FROM pg_type WHERE typowner = service_oid) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT103', MESSAGE = 'service login owns objects';
    END IF;
    -- CONNECT here and USAGE on public only. template1 keeps PostgreSQL's default
    -- PUBLIC CONNECT where the administrator does not own it (documented residual).
    IF has_database_privilege(current_database(), 'CREATE')
       OR has_database_privilege(current_database(), 'TEMPORARY')
       OR EXISTS (SELECT FROM pg_database
                  WHERE has_database_privilege(oid, 'CONNECT WITH GRANT OPTION'))
       OR EXISTS (SELECT FROM pg_database
                  WHERE datname NOT IN (current_database(), 'template1') AND datallowconn
                    AND has_database_privilege(oid, 'CONNECT'))
       OR EXISTS (SELECT FROM pg_namespace WHERE has_schema_privilege(oid, 'CREATE'))
       OR EXISTS (SELECT FROM pg_namespace
                  WHERE has_schema_privilege(oid, 'USAGE WITH GRANT OPTION'))
       OR ARRAY(SELECT nspname::text FROM pg_namespace
                WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
                  AND has_schema_privilege(oid, 'USAGE')) <> ARRAY['public'] THEN
        RAISE EXCEPTION USING ERRCODE = 'RT104', MESSAGE = 'database or schema privileges differ';
    END IF;
    IF (SELECT array_agg(entry ORDER BY entry COLLATE "C") FROM (
            SELECT c.relname || ':' || p.privilege
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                                    'REFERENCES', 'TRIGGER']) AS p(privilege)
            WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND has_table_privilege(c.oid, p.privilege)) AS observed(entry))
       IS DISTINCT FROM
       ARRAY['goose_db_version:SELECT', 'runtime_run_events:SELECT', 'runtime_runs:SELECT']
       -- An allowed operation does not include authority to delegate it.
       OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                                          'REFERENCES', 'TRIGGER']) AS p(privilege)
                  WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                    AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                    AND has_table_privilege(c.oid, p.privilege || ' WITH GRANT OPTION'))
       OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                    AND c.relkind = 'S'
                    AND (has_sequence_privilege(c.oid, 'USAGE')
                         OR has_sequence_privilege(c.oid, 'SELECT')
                         OR has_sequence_privilege(c.oid, 'UPDATE'))) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT105', MESSAGE = 'table privileges differ';
    END IF;
    -- System columns (for example ctid) also support column grants.
    IF (SELECT array_agg(entry ORDER BY entry COLLATE "C") FROM (
            SELECT c.relname || '.' || a.attname || ':' || p.privilege
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum <> 0 AND NOT a.attisdropped
            CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p(privilege)
            WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND has_column_privilege(c.oid, a.attnum, p.privilege)
              AND NOT has_table_privilege(c.oid, p.privilege)) AS observed(entry))
       IS DISTINCT FROM (SELECT array_agg(entry ORDER BY entry COLLATE "C") FROM unnest(ARRAY[
            'runtime_runs.product:INSERT', 'runtime_runs.workflow_name:INSERT',
            'runtime_runs.workflow_version:INSERT', 'runtime_runs.idempotency_key:INSERT',
            'runtime_runs.request_hash:INSERT', 'runtime_runs.input_ref:INSERT',
            'runtime_runs.max_attempts:INSERT',
            'runtime_runs.state:UPDATE', 'runtime_runs.attempt:UPDATE',
            'runtime_runs.lease_owner:UPDATE', 'runtime_runs.lease_version:UPDATE',
            'runtime_runs.lease_expires_at:UPDATE', 'runtime_runs.last_heartbeat_at:UPDATE',
            'runtime_runs.next_available_at:UPDATE', 'runtime_runs.error_code:UPDATE',
            'runtime_runs.error_summary:UPDATE', 'runtime_runs.updated_at:UPDATE',
            'runtime_runs.output_ref:UPDATE',
            'runtime_run_events.run_id:INSERT', 'runtime_run_events.sequence:INSERT',
            'runtime_run_events.event_type:INSERT', 'runtime_run_events.actor_type:INSERT',
            'runtime_run_events.actor_id:INSERT', 'runtime_run_events.from_state:INSERT',
            'runtime_run_events.to_state:INSERT', 'runtime_run_events.attempt:INSERT',
            'runtime_run_events.lease_version:INSERT', 'runtime_run_events.error_code:INSERT',
            'runtime_run_events.metadata:INSERT']) AS expected(entry))
       -- Check grant options independently: ordinary table access must not mask
       -- an explicitly grantable column privilege on that same table.
       OR EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum <> 0 AND NOT a.attisdropped
                  CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p(privilege)
                  WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                    AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                    AND has_column_privilege(c.oid, a.attnum, p.privilege || ' WITH GRANT OPTION')) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT106', MESSAGE = 'column privileges differ';
    END IF;
    -- The release defines no functions; none may be callable, including any
    -- owner-defined SECURITY DEFINER function (EXECUTE defaults to PUBLIC).
    IF EXISTS (SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
               WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                 AND has_function_privilege(p.oid, 'EXECUTE')) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT108', MESSAGE = 'function privileges differ';
    END IF;

    -- Intended operations on rollback-only fixtures.
    INSERT INTO public.runtime_runs (product, workflow_name, workflow_version, idempotency_key,
        request_hash, input_ref, max_attempts)
    VALUES ('release-proof', 'release-proof', '1', 'release-proof-' || gen_random_uuid(),
        sha256('release-proof'::bytea), '{}'::jsonb, 1)
    RETURNING run_id INTO run;
    UPDATE public.runtime_runs SET state = 'retry_wait', next_available_at = now(), updated_at = now()
    WHERE run_id = run;
    INSERT INTO public.runtime_run_events (run_id, sequence, event_type, actor_type, attempt,
        lease_version)
    VALUES (run, 1, 'submitted', 'runtime', 0, 0);
    PERFORM count(*) FROM public.runtime_run_events WHERE run_id = run;
    PERFORM count(*) FROM public.goose_db_version;

    -- Denied: history mutation, DDL, role/owner escalation and server access.
    FOR code, statement IN SELECT * FROM (VALUES
        ('RT110', 'DELETE FROM public.runtime_run_events'),
        ('RT111', 'UPDATE public.runtime_run_events SET attempt = attempt'),
        ('RT112', 'DELETE FROM public.runtime_runs'),
        ('RT113', 'TRUNCATE public.runtime_run_events'),
        ('RT114', 'UPDATE public.goose_db_version SET is_applied = is_applied'),
        ('RT115', 'INSERT INTO public.goose_db_version (version_id, is_applied) VALUES (999999, true)'),
        ('RT116', 'DELETE FROM public.goose_db_version'),
        ('RT117', 'UPDATE public.runtime_runs SET created_at = created_at'),
        ('RT118', 'CREATE TABLE public.release_proof_probe (id integer)'),
        ('RT119', 'CREATE SCHEMA release_proof_probe'),
        ('RT120', 'CREATE TEMPORARY TABLE release_proof_probe (id integer)'),
        ('RT121', 'ALTER TABLE public.runtime_runs ADD COLUMN release_proof_probe integer'),
        ('RT122', 'DROP TABLE public.runtime_run_events'),
        ('RT123', format('ALTER TABLE public.runtime_runs OWNER TO %I', current_user)),
        ('RT124', format('SET ROLE %I', owner_name)),
        ('RT125', format('GRANT %I TO %I', owner_name, current_user)),
        ('RT126', 'CREATE ROLE release_proof_probe'),
        ('RT127', format('ALTER ROLE %I CREATEDB', current_user)),
        ('RT128', 'CREATE FUNCTION public.release_proof_probe() RETURNS integer LANGUAGE sql AS ''SELECT 1'''),
        ('RT129', 'COPY (SELECT 1) TO PROGRAM ''true'''),
        ('RT130', format('ALTER DATABASE %I OWNER TO %I', current_database(), current_user)),
        ('RT131', 'SELECT pg_read_file(''PG_VERSION'')')
    ) AS denials(code, statement) LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION USING ERRCODE = code, MESSAGE = 'forbidden operation succeeded';
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END LOOP;
END
$proof$;
ROLLBACK;
