"""Behavioral privilege-drift fixtures shared by native and image SQL tests."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PrivilegeDrift:
    name: str
    setup: str
    exercise: str
    expected: str
    cleanup: str
    sqlstate: str


def privilege_drifts(database: str) -> tuple[PrivilegeDrift, ...]:
    """Each fixture grants real extra authority and exercises it as the service."""
    dbname, service, table, column, write_column = (
        ("sentryruntime", "runtime_app", "runtime_runs", "run_id", "product")
        if database == "runtime"
        else ("sentrysearch", "search_app", "reports", "id", "tool_name")
    )
    data = "public.release_privilege_data"
    relation_cases = []
    for kind in ("table", "partitioned", "view", "foreign", "system_column"):
        target = data
        create = f"CREATE TABLE {data}(secret text); INSERT INTO {data} VALUES ('restricted');"
        cleanup = f"DROP TABLE {data};"
        if kind == "partitioned":
            create = (
                f"CREATE TABLE {data}(secret text) PARTITION BY LIST(secret);"
                f"CREATE TABLE public.release_privilege_partition PARTITION OF {data} DEFAULT;"
                f"INSERT INTO {data} VALUES ('restricted');"
            )
        elif kind == "view":
            target = "public.release_privilege_view"
            create += f"CREATE VIEW {target} AS SELECT secret FROM {data};"
            cleanup = f"DROP VIEW {target};" + cleanup
        elif kind == "foreign":
            create = (
                "CREATE SCHEMA release_privilege_fdw;"
                "CREATE EXTENSION file_fdw WITH SCHEMA release_privilege_fdw;"
                "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA release_privilege_fdw FROM PUBLIC;"
                "CREATE SERVER release_privilege_server FOREIGN DATA WRAPPER file_fdw;"
                "DO $fixture$ DECLARE filename text := current_setting('data_directory')"
                " || '/release-privilege.csv'; BEGIN"
                " EXECUTE format('COPY (SELECT ''restricted''::text) TO %L', filename);"
                f" EXECUTE format('CREATE FOREIGN TABLE {data}(secret text)"
                " SERVER release_privilege_server OPTIONS (filename %L)', filename);"
                " END $fixture$;"
            )
            cleanup = (
                f"DROP FOREIGN TABLE {data}; DROP SERVER release_privilege_server;"
                "DROP EXTENSION file_fdw; DROP SCHEMA release_privilege_fdw;"
            )
        relation_cases.append(
            PrivilegeDrift(
                f"column_select_{kind}",
                create
                + f"GRANT SELECT({'ctid' if kind == 'system_column' else 'secret'})"
                + f" ON {target} TO {service};",
                (
                    f"SELECT count(ctid) FROM {target};"
                    if kind == "system_column"
                    else f"SELECT secret FROM {target};"
                ),
                "1" if kind == "system_column" else "restricted",
                cleanup,
                "RT106",
            )
        )

    delegation_cases = []
    for name, privilege, resource, inquiry, state in (
        (
            "table_grant_option",
            "SELECT",
            f"TABLE public.{table}",
            f"has_table_privilege('release_privilege_delegate', 'public.{table}', 'SELECT')",
            "RT105",
        ),
        (
            "column_select_grant_option_masked_by_table_select",
            f"SELECT({column})",
            f"TABLE public.{table}",
            f"has_column_privilege('release_privilege_delegate', 'public.{table}',"
            f" '{column}', 'SELECT')",
            "RT106",
        ),
        (
            "system_column_grant_option_masked_by_table_select",
            "SELECT(ctid)",
            f"TABLE public.{table}",
            f"has_column_privilege('release_privilege_delegate', 'public.{table}', 'ctid', 'SELECT')",
            "RT106",
        ),
        (
            "column_insert_grant_option",
            f"INSERT({write_column})",
            f"TABLE public.{table}",
            f"has_column_privilege('release_privilege_delegate', 'public.{table}',"
            f" '{write_column}', 'INSERT')",
            "RT106",
        ),
        (
            "database_connect_grant_option",
            "CONNECT",
            f"DATABASE {dbname}",
            f"has_database_privilege('release_privilege_delegate', '{dbname}', 'CONNECT')",
            "RT104",
        ),
        (
            "schema_usage_grant_option",
            "USAGE",
            "SCHEMA public",
            "has_schema_privilege('release_privilege_delegate', 'public', 'USAGE')",
            "RT104",
        ),
    ):
        delegation_cases.append(
            PrivilegeDrift(
                name,
                "CREATE ROLE release_privilege_delegate NOLOGIN;"
                f"GRANT {privilege} ON {resource} TO {service} WITH GRANT OPTION;",
                f"GRANT {privilege} ON {resource} TO release_privilege_delegate;"
                f"SELECT {inquiry};",
                "t",
                f"REVOKE GRANT OPTION FOR {privilege} ON {resource} FROM {service} CASCADE;"
                "DROP ROLE release_privilege_delegate;",
                state,
            )
        )
    return tuple(relation_cases + delegation_cases)
