DO $$

DECLARE
    v_old text := 'authold';
    v_new text := 'auth';
BEGIN

    IF EXISTS (
        SELECT 1
        FROM pg_namespace
        WHERE nspname = v_new
    ) THEN

        IF EXISTS (
            SELECT 1
            FROM pg_namespace
            WHERE nspname = v_old
        ) THEN

            RAISE NOTICE 'Dropping old schema %', v_old;

            EXECUTE format(
                'DROP SCHEMA %I CASCADE',
                v_old
            );

        END IF;

        RAISE NOTICE 'Renaming schema % to %',
                     v_new,
                     v_old;

        EXECUTE format(
            'ALTER SCHEMA %I RENAME TO %I',
            v_new,
            v_old
        );

    ELSE

        RAISE NOTICE 'Schema % not found', v_new;

    END IF;

END;
$$