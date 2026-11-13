CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, subid integer, debug boolean = false)
    RETURNS void AS
  $$
DECLARE
  m record;
  body text;
  source_name text;
  view_owner regrole = quote_ident(session_user);
  rule pgsodium.masking_rule;
  privs aclitem[];
  priv record;
BEGIN
  SELECT DISTINCT * INTO STRICT rule FROM pgsodium.masking_rule WHERE attrelid = relid AND attnum = subid;

  source_name := relid::regclass::text;

  BEGIN
    SELECT relacl INTO STRICT privs FROM pg_catalog.pg_class WHERE oid = rule.view_name::regclass::oid;
  EXCEPTION
	WHEN undefined_table THEN
      SELECT relacl INTO STRICT privs FROM pg_catalog.pg_class WHERE oid = relid;
  END;

  body = format(
    $c$
    DROP VIEW IF EXISTS %1$I;
    CREATE VIEW %1$I %5$s AS SELECT %2$s
    FROM %3$I;
    ALTER VIEW %1$I OWNER TO %4$I;
    $c$,
    rule.view_name,
    pgsodium.decrypted_columns(relid),
    source_name,
    view_owner,
    CASE WHEN rule.security_invoker THEN 'WITH (security_invoker=true)' ELSE '' END
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  FOR priv IN SELECT * FROM pg_catalog.aclexplode(privs) LOOP
	body = format(
	  $c$
	  GRANT %I ON %I TO %I;
	  $c$,
	  priv.privilege_type,
	  rule.view_name,
	  priv.grantee::regrole::text
	);
	IF debug THEN
	  RAISE NOTICE '%', body;
	END IF;
	EXECUTE body;
  END LOOP;

  FOR m IN SELECT * FROM pgsodium.mask_columns where attrelid = relid LOOP
	IF m.key_id IS NULL AND m.key_id_column is NULL THEN
	  CONTINUE;
	ELSE
	  body = format(
		$c$
		DROP FUNCTION IF EXISTS %1$I."%2$I_encrypt_secret_%3$I"() CASCADE;

		CREATE OR REPLACE FUNCTION %1$I."%2$I_encrypt_secret_%3$I"()
		  RETURNS TRIGGER
		  LANGUAGE plpgsql
		  AS $t$
		BEGIN
		%4$s;
		RETURN new;
		END;
		$t$;

		ALTER FUNCTION  %1$I."%2$I_encrypt_secret_%3$I"() OWNER TO %5$s;

		DROP TRIGGER IF EXISTS "%2$I_encrypt_secret_trigger_%3$I" ON %6$s;

		CREATE TRIGGER "%2$I_encrypt_secret_trigger_%3$I"
		  BEFORE INSERT OR UPDATE OF "%3$I" ON %6$I
		  FOR EACH ROW
		  EXECUTE FUNCTION %1$s."%2$I_encrypt_secret_%3$I" ();
		  $c$,
		rule.relnamespace,
		rule.relname,
		m.attname,
		pgsodium.encrypted_column(relid, m),
		view_owner,
		source_name
	  );
	  if debug THEN
		RAISE NOTICE '%', body;
	  END IF;
	  EXECUTE body;
	END IF;
  END LOOP;

  RAISE NOTICE 'Masking role % %', source_name, rule.view_name;
  PERFORM pgsodium.mask_role(oid::regrole, source_name, rule.view_name)
  FROM pg_roles WHERE pgsodium.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;

CREATE OR REPLACE FUNCTION pgsodium.create_mask_view(relid oid, debug boolean = false) RETURNS void AS
  $$
DECLARE
  body text;
  source_name text;
  view_name text;
  rule pgsodium.masking_rule;
BEGIN
  SELECT DISTINCT(quote_ident(relname)) INTO STRICT view_name
    FROM pg_class c, pg_seclabel sl
   WHERE relid = c.oid
     AND sl.classoid = c.tableoid
     AND sl.objoid = c.oid;

  source_name := relid::regclass;

  body = format(
    $c$
    DROP VIEW IF EXISTS pgsodium_masks.%I;
    CREATE VIEW pgsodium_masks.%I AS SELECT %s
    FROM %I;
    $c$,
    view_name,
    view_name,
    pgsodium.decrypted_columns(relid),
    source_name
  );
  IF debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  body = format(
    $c$
    CREATE OR REPLACE FUNCTION pgsodium_masks.%I_encrypt_secret()
      RETURNS TRIGGER
      LANGUAGE plpgsql
      AS $t$
    BEGIN
    %s;
    RETURN new;
    END;
    $t$;

    DROP TRIGGER IF EXISTS %I_encrypt_secret_trigger ON %s;

    CREATE TRIGGER %I_encrypt_secret_trigger
      BEFORE INSERT ON %I
      FOR EACH ROW
      EXECUTE FUNCTION pgsodium_masks.%I_encrypt_secret ();
    $c$,
    view_name,
    pgsodium.encrypted_columns(relid),
    view_name,
    source_name,
    view_name,
    source_name,
    view_name
  );
  if debug THEN
    RAISE NOTICE '%', body;
  END IF;
  EXECUTE body;

  PERFORM pgsodium.mask_role(oid::regrole, source_name, view_name)
  FROM pg_roles WHERE pgsodium.has_mask(oid::regrole, source_name);

  RETURN;
END
  $$
  LANGUAGE plpgsql
  VOLATILE
  SET search_path='pg_catalog'
;
