-- Operator-only grants for a DEDICATED SentrySearch product database after its
-- storage revision is applied (docs/storage-release.md). The release-tools grant
-- job runs it as the database owner, never at API or worker startup:
-- psql -X -v ON_ERROR_STOP=1 -v database_name=sentrysearch \
--   -v service_role=sentrysearch_app -f release_tools/sql/product/grants.sql
BEGIN;
SELECT set_config('sentrysearch.grant_database', :'database_name', true);
SELECT set_config('sentrysearch.grant_role', :'service_role', true);

DO $grants$
DECLARE
    service_name text := current_setting('sentrysearch.grant_role');
    service_oid oid;
    owner_oid oid;
BEGIN
    IF current_database() <> current_setting('sentrysearch.grant_database') THEN
        RAISE EXCEPTION 'product grants require the explicitly selected product database';
    END IF;
    SELECT oid INTO owner_oid FROM pg_roles WHERE rolname = current_user;
    IF NOT EXISTS (SELECT FROM pg_database WHERE datname = current_database() AND datdba = owner_oid) THEN
        RAISE EXCEPTION 'product grants must run as the dedicated database owner';
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE oid = owner_oid
               AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
       OR EXISTS (SELECT FROM pg_auth_members WHERE member = owner_oid) THEN
        RAISE EXCEPTION 'the database owner must be an unprivileged login without role memberships';
    END IF;
    -- Any member could act as either login: INHERIT and SET directly, ADMIN by
    -- granting itself SET. Only administrators (superuser or CREATEROLE), such as
    -- the bootstrap administrator, may hold a membership.
    IF EXISTS (SELECT FROM pg_auth_members m
               JOIN pg_roles r ON r.oid = m.roleid
               JOIN pg_roles holder ON holder.oid = m.member
               WHERE r.rolname IN (current_user, service_name)
                 AND NOT (holder.rolsuper OR holder.rolcreaterole)) THEN
        RAISE EXCEPTION 'another role can act as the database owner or service login';
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
        WHERE n.nspname = 'public'
          AND c.relname IN ('reports', 'report_runtime_dispatches', 'report_disposition_events',
                            'report_searches', 'report_tags', 'sentrysearch_schema_migrations')
          AND c.relkind = 'r' AND c.relowner = owner_oid) <> 6 THEN
        RAISE EXCEPTION 'apply the product storage migration as the database owner before grants';
    END IF;
    IF NOT EXISTS (SELECT FROM public.sentrysearch_schema_migrations) THEN
        RAISE EXCEPTION 'product storage revision is not recorded';
    END IF;

    -- PUBLIC includes every login. Revoking only the named role is insufficient.
    -- This changes database-wide defaults: never apply to a shared database.
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
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.reports,
        public.report_runtime_dispatches, public.report_disposition_events,
        public.report_searches, public.report_tags TO %I', service_name);
    -- Readiness reads the revision marker; only the migration job may change it.
    EXECUTE format('GRANT SELECT ON public.sentrysearch_schema_migrations TO %I', service_name);
END
$grants$;
COMMIT;
