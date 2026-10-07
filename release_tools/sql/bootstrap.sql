-- Creates a dedicated database with its owner and service logins on a fresh
-- instance. The release-tools bootstrap job runs it as the instance administrator,
-- connected to the maintenance database. Re-runs converge: existing logins are
-- verified (never escalated) and their SCRAM verifiers replaced, and an existing
-- database must already belong to the owner. Plaintext passwords never reach SQL.
\getenv owner_verifier RELEASE_OWNER_VERIFIER
\getenv service_verifier RELEASE_SERVICE_VERIFIER
SELECT set_config('release.target_database', :'target_database', false) AS target,
       set_config('release.owner_role', :'owner_role', false) AS owner,
       set_config('release.service_role', :'service_role', false) AS service
\gset bootstrap_

DO $check$
DECLARE
    target text := current_setting('release.target_database');
    owner_name text := current_setting('release.owner_role');
    service_name text := current_setting('release.service_role');
BEGIN
    IF target IN ('postgres', 'template0', 'template1', 'rdsadmin')
       OR target = current_database() THEN
        RAISE EXCEPTION USING ERRCODE = 'RT201', MESSAGE = 'reserved target database';
    END IF;
    IF owner_name = service_name OR current_user IN (owner_name, service_name)
       OR EXISTS (SELECT FROM pg_roles WHERE rolname IN (owner_name, service_name)
                  AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
                       OR rolbypassrls OR NOT rolcanlogin)) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT202', MESSAGE = 'existing login is privileged';
    END IF;
    -- Neither login may belong to a role, and no role but this administrator may
    -- belong to either login (and so act as it).
    IF EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member
               WHERE r.rolname IN (owner_name, service_name))
       OR EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
                  WHERE r.rolname IN (owner_name, service_name)
                    AND m.member <> (SELECT oid FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT203', MESSAGE = 'existing login has memberships';
    END IF;
    IF EXISTS (SELECT FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
               WHERE d.datname = target AND r.rolname <> owner_name)
       OR EXISTS (SELECT FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
                  WHERE r.rolname = service_name) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT204', MESSAGE = 'database ownership conflict';
    END IF;
END
$check$;

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
              'NOBYPASSRLS NOINHERIT', login.role_name)
FROM unnest(ARRAY[:'owner_role', :'service_role']) AS login(role_name)
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = login.role_name)
\gexec
ALTER ROLE :"owner_role" PASSWORD :'owner_verifier';
ALTER ROLE :"service_role" PASSWORD :'service_verifier';

SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L',
              :'target_database', :'owner_role', 'UTF8')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'target_database')
\gexec

-- Only the owner (and later the granted service login) may connect to the target,
-- and no ordinary login may connect to the maintenance database. The target
-- revoke runs as its owner, which a non-superuser administrator needs; a revoke
-- without authority is only a warning, so the result is checked below.
SET ROLE :"owner_role";
REVOKE ALL ON DATABASE :"target_database" FROM PUBLIC;
RESET ROLE;
REVOKE ALL ON DATABASE :"expect_database" FROM PUBLIC;
DO $public$
BEGIN
    IF EXISTS (SELECT FROM pg_database d,
                   aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) AS a
               WHERE d.datname IN (current_setting('release.target_database'), current_database())
                 AND a.grantee = 0) THEN
        RAISE EXCEPTION USING ERRCODE = 'RT205', MESSAGE = 'PUBLIC can still reach a database';
    END IF;
END
$public$;

-- Server-side bounds for owner sessions, including migration jobs.
ALTER ROLE :"owner_role" SET statement_timeout = '60s';
ALTER ROLE :"owner_role" SET lock_timeout = '3s';
ALTER ROLE :"owner_role" SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE :"owner_role" SET client_connection_check_interval = '1s';

SELECT 'result|database|' || d.datname
FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
WHERE d.datname = :'target_database' AND r.rolname = :'owner_role';
SELECT 'result|principal|' || current_user;
SELECT 'result|' || kind || '|' || rolname
FROM pg_roles
JOIN (VALUES ('owner_role', :'owner_role'), ('service_role', :'service_role')) AS v(kind, name)
  ON rolname = v.name
WHERE rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
  AND NOT rolreplication AND NOT rolbypassrls;
