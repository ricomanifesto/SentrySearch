-- Reports the product storage revisions and checksum prefixes.
SELECT 'result|schema|sentrysearch:'
       || coalesce(string_agg(version::text || ':' || left(checksum, 16), ',' ORDER BY version),
                   'none')
FROM public.sentrysearch_schema_migrations;
