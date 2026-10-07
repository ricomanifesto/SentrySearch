-- Least-authority proof for the product service login, run as that login by the
-- release-tools proof job. Fixtures live in one transaction that always rolls
-- back. The privilege inventory must equal sql/product/grants.sql exactly, and
-- each forbidden operation must fail with insufficient_privilege (42501);
-- anything else fails the job with its RT1xx code or the server's own error.
BEGIN;
SELECT set_config('release.owner_role', :'owner_role', true) AS owner \gset proof_

DO $proof$
DECLARE
    owner_name text := current_setting('release.owner_role');
    service_oid oid;
    report uuid := gen_random_uuid();
    search uuid := gen_random_uuid();
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
       IS DISTINCT FROM (SELECT array_agg(entry ORDER BY entry COLLATE "C") FROM (
            SELECT t.name || ':' || p.privilege
            FROM unnest(ARRAY['reports', 'report_runtime_dispatches',
                              'report_disposition_events', 'report_searches',
                              'report_tags']) AS t(name)
            CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE']) AS p(privilege)
            UNION ALL SELECT 'sentrysearch_schema_migrations:SELECT') AS expected(entry))
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
    IF EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum <> 0 AND NOT a.attisdropped
               CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p(privilege)
               WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
                 AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                 AND has_column_privilege(c.oid, a.attnum, p.privilege)
                 AND NOT has_table_privilege(c.oid, p.privilege))
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
    INSERT INTO public.reports (id, tool_name) VALUES (report, 'release-proof');
    UPDATE public.reports SET category = 'release-proof' WHERE id = report;
    INSERT INTO public.report_runtime_dispatches (report_id) VALUES (report);
    UPDATE public.report_runtime_dispatches SET dispatch_attempts = 1 WHERE report_id = report;
    INSERT INTO public.report_disposition_events (id, report_id, reviewer_user_id, disposition,
        evaluation_attempt)
    VALUES (gen_random_uuid(), report, 'release-proof', 'release-proof', 0);
    INSERT INTO public.report_searches (id, query) VALUES (search, 'release-proof');
    INSERT INTO public.report_tags (id, report_id, tag) VALUES (gen_random_uuid(), report, 'release-proof');
    PERFORM count(*) FROM public.sentrysearch_schema_migrations;
    DELETE FROM public.report_tags WHERE report_id = report;
    DELETE FROM public.report_searches WHERE id = search;
    DELETE FROM public.report_disposition_events WHERE report_id = report;
    DELETE FROM public.report_runtime_dispatches WHERE report_id = report;
    DELETE FROM public.reports WHERE id = report;

    -- Denied: history mutation, DDL, role/owner escalation and server access.
    FOR code, statement IN SELECT * FROM (VALUES
        ('RT110', 'UPDATE public.sentrysearch_schema_migrations SET checksum = checksum'),
        ('RT111', 'DELETE FROM public.sentrysearch_schema_migrations'),
        ('RT112', 'INSERT INTO public.sentrysearch_schema_migrations (version, checksum) VALUES (999999, ''probe'')'),
        ('RT113', 'TRUNCATE public.report_disposition_events'),
        ('RT118', 'CREATE TABLE public.release_proof_probe (id integer)'),
        ('RT119', 'CREATE SCHEMA release_proof_probe'),
        ('RT120', 'CREATE TEMPORARY TABLE release_proof_probe (id integer)'),
        ('RT121', 'ALTER TABLE public.reports ADD COLUMN release_proof_probe integer'),
        ('RT122', 'DROP TABLE public.report_tags'),
        ('RT123', format('ALTER TABLE public.reports OWNER TO %I', current_user)),
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
