-- Re-derives the session limits from the fixed deadline before each phase:
-- never above the caps, never past the deadline less the 2-second reserve.
DO $refresh$
DECLARE
    remaining_ms bigint := floor((current_setting('release.deadline_epoch')::numeric
        - extract(epoch FROM clock_timestamp())) * 1000) - 2000;
BEGIN
    IF remaining_ms < 1000 THEN
        RAISE EXCEPTION USING ERRCODE = 'RT010', MESSAGE = 'release job budget exhausted';
    END IF;
    PERFORM set_config('statement_timeout', least(60000, remaining_ms)::text, false);
    PERFORM set_config('lock_timeout', least(3000, remaining_ms)::text, false);
    PERFORM set_config('idle_in_transaction_session_timeout',
                       least(10000, remaining_ms)::text, false);
END
$refresh$;
