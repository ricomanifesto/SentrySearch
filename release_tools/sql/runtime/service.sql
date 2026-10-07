-- Operator-only grants for a DEDICATED runtime database after migrations 1-3.
-- Use a fresh, unprivileged login; create/provision its secret separately.
-- psql -X -v ON_ERROR_STOP=1 -v database_name=sentryruntime \
--   -v service_role=sentryruntime_app "$RELEASE_DATABASE_URL" -f db/roles/service.sql
-- This is deliberately not a Goose migration and is never run at API startup.
BEGIN;
SELECT set_config('sentryruntime.grant_database', :'database_name', true);
SELECT set_config('sentryruntime.grant_role', :'service_role', true);

DO $grants$
DECLARE
    service_name text := current_setting('sentryruntime.grant_role');
    service_oid oid;
    owner_oid oid;
BEGIN
    IF current_database() <> current_setting('sentryruntime.grant_database') THEN
        RAISE EXCEPTION 'service grants require the explicitly selected runtime database';
    END IF;
    SELECT oid INTO owner_oid FROM pg_roles WHERE rolname = current_user;
    IF NOT EXISTS (SELECT FROM pg_database WHERE datname = current_database() AND datdba = owner_oid) THEN
        RAISE EXCEPTION 'service grants must run as the dedicated database owner';
    END IF;
    SELECT oid INTO service_oid FROM pg_roles
      WHERE rolname = service_name AND rolcanlogin AND NOT rolsuper
        AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls;
    IF service_oid IS NULL OR service_oid = owner_oid
       OR EXISTS (SELECT FROM pg_auth_members WHERE member = service_oid)
       OR EXISTS (SELECT FROM pg_database WHERE datdba = service_oid)
       OR EXISTS (SELECT FROM pg_namespace WHERE nspowner = service_oid)
       OR EXISTS (SELECT FROM pg_class WHERE relowner = service_oid)
       OR EXISTS (SELECT FROM pg_proc WHERE proowner = service_oid)
       OR EXISTS (SELECT FROM pg_type WHERE typowner = service_oid) THEN
        RAISE EXCEPTION 'service role must be an unprivileged non-owner login without role memberships';
    END IF;
    IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname IN ('runtime_runs', 'runtime_run_events', 'goose_db_version')
          AND c.relkind = 'r' AND c.relowner = owner_oid) <> 3 THEN
        RAISE EXCEPTION 'apply runtime migrations as the database owner before service grants';
    END IF;

    -- PUBLIC includes every login. Revoking only the named role is insufficient.
    -- This changes database-wide defaults: never apply to a shared product DB.
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM %I', current_database(), service_name);
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON SCHEMA public FROM %I', service_name);
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', service_name);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', service_name);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), service_name);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', service_name);
    EXECUTE format('GRANT SELECT ON public.runtime_runs, public.runtime_run_events TO %I', service_name);
    EXECUTE format('GRANT INSERT (product, workflow_name, workflow_version, idempotency_key,
        request_hash, input_ref, max_attempts) ON public.runtime_runs TO %I', service_name);
    EXECUTE format('GRANT UPDATE (state, attempt, lease_owner, lease_version, lease_expires_at,
        last_heartbeat_at, next_available_at, error_code, error_summary, updated_at, output_ref)
        ON public.runtime_runs TO %I', service_name);
    EXECUTE format('GRANT INSERT (run_id, sequence, event_type, actor_type, actor_id,
        from_state, to_state, attempt, lease_version, error_code, metadata)
        ON public.runtime_run_events TO %I', service_name);
    EXECUTE format('GRANT SELECT ON public.goose_db_version TO %I', service_name);
    -- No sequence grants: run IDs are UUIDs, event sequences are per-run values,
    -- and only the migration job may advance Goose's sequence/history.
END
$grants$;
COMMIT;
