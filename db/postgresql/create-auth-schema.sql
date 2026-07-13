--
-- PostgreSQL database dump
--

-- Dumped from database version 16.2
-- Dumped by pg_dump version 16.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: pg_database_owner
--

CREATE SCHEMA auth;


ALTER SCHEMA auth OWNER TO pg_database_owner;

--
-- Name: SCHEMA auth; Type: COMMENT; Schema: -; Owner: pg_database_owner
--

COMMENT ON SCHEMA auth IS 'Schema supporting user authentication';


--
-- Name: auth_add_refresh_token(bigint, character varying, timestamp without time zone); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_add_refresh_token(IN p_user_id bigint, IN p_token character varying, IN p_expires_at timestamp without time zone)
    LANGUAGE plpgsql
    AS $$declare tmp bigint;

BEGIN

	select user_id into tmp
	from auth_refresh_tokens
	where user_id = p_user_id;

	if tmp is null 
	then
	    INSERT INTO auth_refresh_tokens
	    (
	        user_id,
	        token,
	        expires_at,
			revoked
	    )
	    VALUES
	    (
	        p_user_id,
	        p_token,
	        p_expires_at,
			false
	    );
	else
		update auth_refresh_tokens
			set token = p_token,
				revoked = false,
				expires_at = p_expires_at,
				created_at = now();	
	end if;
END
$$;


ALTER PROCEDURE auth.auth_add_refresh_token(IN p_user_id bigint, IN p_token character varying, IN p_expires_at timestamp without time zone) OWNER TO postgres;

--
-- Name: auth_get_user_by_username(character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION auth.auth_get_user_by_username(p_username character varying) RETURNS TABLE(id bigint, username character varying, password_hash character varying, enabled boolean, roles character varying[])
    LANGUAGE plpgsql
    AS $$
BEGIN

    RETURN QUERY
    SELECT
        u.id,
        u.username,
        u.password_hash,
		u.enabled,
        array_remove(array_agg(r.role_name), NULL)
    FROM auth_users u
    LEFT JOIN auth_user_roles ur
           ON ur.user_id = u.id
    LEFT JOIN auth_roles r
           ON r.id = ur.role_id
    WHERE u.username = p_username
    GROUP BY
        u.id,
        u.username,
        u.password_hash;

END;
$$;


ALTER FUNCTION auth.auth_get_user_by_username(p_username character varying) OWNER TO postgres;

--
-- Name: auth_get_userid(character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION auth.auth_get_userid(p_username character varying) RETURNS bigint
    LANGUAGE plpgsql
    AS $$
declare userid bigint;
BEGIN
	select id into userid from auth_users
	where username = p_username;

END;
$$;


ALTER FUNCTION auth.auth_get_userid(p_username character varying) OWNER TO postgres;

--
-- Name: auth_get_users(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION auth.auth_get_users() RETURNS TABLE(id bigint, username character varying, password_hash character varying, enabled boolean, created_at timestamp without time zone, roles character varying[])
    LANGUAGE plpgsql
    AS $$
BEGIN

    RETURN QUERY
    SELECT
        u.id,
        u.username,
        u.password_hash,
		u.enabled,
		u.created_at,
        array_remove(array_agg(r.role_name), NULL)
    FROM auth_users u
    LEFT JOIN auth_user_roles ur
           ON ur.user_id = u.id
    LEFT JOIN auth_roles r
           ON r.id = ur.role_id
    GROUP BY
        u.id,
        u.username,
        u.password_hash;

END;
$$;


ALTER FUNCTION auth.auth_get_users() OWNER TO postgres;

--
-- Name: auth_getroles(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION auth.auth_getroles() RETURNS TABLE(role character varying, roleid integer)
    LANGUAGE plpgsql
    AS $$
begin
	return query
	select role_name, id from auth_roles r;
end
$$;


ALTER FUNCTION auth.auth_getroles() OWNER TO postgres;

--
-- Name: auth_getuserroles(bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION auth.auth_getuserroles(userid bigint) RETURNS TABLE(role character varying, roleid integer)
    LANGUAGE plpgsql
    AS $$
begin
	return query
	select role_name, id from auth_roles r
	join auth_user_roles ur on (ur.role_id = r.id)
	where ur.user_id = userid;
end
$$;


ALTER FUNCTION auth.auth_getuserroles(userid bigint) OWNER TO postgres;

--
-- Name: auth_getuserroles_byusername(character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION auth.auth_getuserroles_byusername(username character varying) RETURNS TABLE(role character varying, roleid integer)
    LANGUAGE plpgsql
    AS $$
begin
	return query
	select role_name, id from auth_roles r
	join auth_user_roles ur on (ur.role_id = r.id)
	join auth_users u on (u.id = ur.user_id)
	where u.username = username;
end
$$;


ALTER FUNCTION auth.auth_getuserroles_byusername(username character varying) OWNER TO postgres;

--
-- Name: auth_revoke_refresh_token(character varying); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_revoke_refresh_token(IN p_token character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN

    UPDATE auth_refresh_tokens
       SET revoked = TRUE
     WHERE token = p_token;

END;
$$;


ALTER PROCEDURE auth.auth_revoke_refresh_token(IN p_token character varying) OWNER TO postgres;

--
-- Name: auth_user_addaudit(bigint, timestamp with time zone, character varying, text, boolean, integer); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_user_addaudit(IN userid bigint, IN login_date timestamp with time zone DEFAULT now(), IN ip_address character varying DEFAULT NULL::character varying, IN user_agent text DEFAULT NULL::text, IN success boolean DEFAULT true, IN reason integer DEFAULT 0)
    LANGUAGE plpgsql
    AS $$
begin
	INSERT INTO auth.auth_login_audit(
		user_id, login_date, ip_address, user_agent, success, reason)
		VALUES (userid, login_date, ip_address, user_agent, success, reason);
end
$$;


ALTER PROCEDURE auth.auth_user_addaudit(IN userid bigint, IN login_date timestamp with time zone, IN ip_address character varying, IN user_agent text, IN success boolean, IN reason integer) OWNER TO postgres;

--
-- Name: auth_user_authenticate(character varying, character varying); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_user_authenticate(IN p_username character varying, IN password character varying, OUT hashedpassword character varying, OUT userid bigint)
    LANGUAGE plpgsql
    AS $$
declare venabled bool;

begin
	select id, password_hash, enabled into userid, hashedpassword, venabled
	from auth.auth_users
	where username = p_username;

	if venabled = false then
		set hashedpassword = '';
		set userid = -1;
	end if;
end
$$;


ALTER PROCEDURE auth.auth_user_authenticate(IN p_username character varying, IN password character varying, OUT hashedpassword character varying, OUT userid bigint) OWNER TO postgres;

--
-- Name: auth_user_create(character varying, character varying, character varying, character varying[], boolean); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_user_create(IN p_username character varying, IN p_email character varying, IN p_passwordhashed character varying, IN roles character varying[], IN p_enabled boolean DEFAULT true)
    LANGUAGE plpgsql
    AS $$
declare val character varying;
declare userid bigint;
declare roleid integer;
begin

	IF EXISTS (
	    SELECT 1
	    FROM auth_users
	    WHERE username = p_username
	) then
		RAISE EXCEPTION 'Duplicate user name';
	end if;

	FOREACH val IN ARRAY roles
    LOOP
		IF NOT EXISTS (
		    SELECT 1
		    FROM auth_roles
		    WHERE role_name = val
		) then
			RAISE EXCEPTION 'Invalid role: %s', val;
		end if;
    END LOOP;

	INSERT INTO auth_users(
		username, email, password_hash, enabled)
	VALUES (p_username, p_email, p_passwordhashed, p_enabled)
	RETURNING id INTO userid;

	FOREACH val IN ARRAY roles
    LOOP
		select id into roleid
		from auth_roles
		where role_name = val;
		
		insert into auth_user_roles (user_id, role_id)
		values (userid, roleid);
    END LOOP;
	
end
$$;


ALTER PROCEDURE auth.auth_user_create(IN p_username character varying, IN p_email character varying, IN p_passwordhashed character varying, IN roles character varying[], IN p_enabled boolean) OWNER TO postgres;

--
-- Name: auth_user_map(character varying); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_user_map(IN p_username character varying, OUT userid bigint)
    LANGUAGE plpgsql
    AS $$
begin

SELECT id
    INTO userid
    FROM auth_users
    WHERE username = p_username;

end
$$;


ALTER PROCEDURE auth.auth_user_map(IN p_username character varying, OUT userid bigint) OWNER TO postgres;

--
-- Name: auth_user_setroles(bigint, character varying[]); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_user_setroles(IN p_userid bigint, IN p_roles character varying[])
    LANGUAGE plpgsql
    AS $$declare val character varying;
declare roleid integer;
begin

	IF NOT EXISTS (
		SELECT 1
		FROM auth_users
		WHERE id = p_userid
	) then
		RAISE EXCEPTION 'Invalid user: %d', p_userid;
	end if;

	FOREACH val IN ARRAY p_roles
    LOOP
		IF NOT EXISTS (
		    SELECT 1
		    FROM auth_roles
		    WHERE role_name = val
		) then
			RAISE EXCEPTION 'Invalid user role: %s', val;
		end if;
    END LOOP;

	delete from auth_user_roles
	where user_id = p_userid;

	FOREACH val IN ARRAY p_roles
    LOOP
		select roleid=id from auth_roles
		where role_name = val;

		insert into auth_user_roles (user_id, role_id)
		values (p_userid, roleid);
    END LOOP;

	
end$$;


ALTER PROCEDURE auth.auth_user_setroles(IN p_userid bigint, IN p_roles character varying[]) OWNER TO postgres;

--
-- Name: auth_user_update(bigint, character varying, character varying, boolean); Type: PROCEDURE; Schema: public; Owner: postgres
--

CREATE PROCEDURE auth.auth_user_update(IN userid bigint, IN hashedpassword character varying DEFAULT NULL::character varying, IN emailaddr character varying DEFAULT NULL::character varying, IN enabled boolean DEFAULT NULL::boolean)
    LANGUAGE plpgsql
    AS $$
begin

	if hashedpassword is not null
	then
		update auth_users 
		set password_hash = hashedpassword
		where id = userid;
	end if;

	if emailaddr is not null
	then
		update auth_users 
		set email = emailaddr
		where id = userid;
	end if;

	if enabled is not null
	then
		update auth_users 
		set auth_users.enabled = enabled
		where id = userid;
	end if;

end
$$;


ALTER PROCEDURE auth.auth_user_update(IN userid bigint, IN hashedpassword character varying, IN emailaddr character varying, IN enabled boolean) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: auth_login_audit; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE auth.auth_login_audit (
    id bigint NOT NULL,
    user_id bigint,
    login_date timestamp without time zone DEFAULT now() NOT NULL,
    ip_address character varying(50),
    user_agent text,
    success boolean NOT NULL,
    reason integer DEFAULT 0 NOT NULL
);


ALTER TABLE auth.auth_login_audit OWNER TO postgres;

--
-- Name: auth_login_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE auth.auth_login_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE auth.auth_login_audit_id_seq OWNER TO postgres;

--
-- Name: auth_login_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE auth.auth_login_audit_id_seq OWNED BY auth.auth_login_audit.id;


--
-- Name: auth_login_audit_id_seq1; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE auth.auth_login_audit ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME auth.auth_login_audit_id_seq1
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: auth_refresh_tokens; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE auth.auth_refresh_tokens (
    user_id bigint NOT NULL,
    token character varying(512) NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE auth.auth_refresh_tokens OWNER TO postgres;

--
-- Name: auth_roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE auth.auth_roles (
    id integer NOT NULL,
    role_name character varying(50) NOT NULL
);


ALTER TABLE auth.auth_roles OWNER TO postgres;

--
-- Name: auth_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE auth.auth_roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE auth.auth_roles_id_seq OWNER TO postgres;

--
-- Name: auth_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE auth.auth_roles_id_seq OWNED BY auth.auth_roles.id;


--
-- Name: auth_user_roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE auth.auth_user_roles (
    user_id bigint NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE auth.auth_user_roles OWNER TO postgres;

--
-- Name: auth_users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE auth.auth_users (
    id bigint NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


ALTER TABLE auth.auth_users OWNER TO postgres;

--
-- Name: auth_users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE auth.auth_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE auth.auth_users_id_seq OWNER TO postgres;

--
-- Name: auth_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE auth.auth_users_id_seq OWNED BY auth.auth_users.id;


--
-- Name: auth_roles id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_roles ALTER COLUMN id SET DEFAULT nextval('auth.auth_roles_id_seq'::regclass);


--
-- Data for Name: auth_roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY auth.auth_roles (id, role_name) FROM stdin;
1	ADMIN
2	USER
3	MANAGER
4	READER
\.


--
-- Data for Name: auth_user_roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY auth.auth_user_roles (user_id, role_id) FROM stdin;
1	1
1	2
\.


--
-- Data for Name: auth_users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY auth.auth_users (id, username, email, password_hash, enabled, created_at, updated_at) FROM stdin;
1	test	test@example.com	$2a$10$YFTfb6qV/LPc3bIec12FVOa2yUu4DNLSE7/P5fUnIFQEx.BrrIKiC	t	2026-07-01 11:52:46.372061	2026-07-01 11:52:46.372061
\.


--
-- Name: auth_login_audit_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('auth.auth_login_audit_id_seq', 1, false);


--
-- Name: auth_login_audit_id_seq1; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('auth.auth_login_audit_id_seq1', 27, true);


--
-- Name: auth_roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('auth.auth_roles_id_seq', 4, true);


--
-- Name: auth_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('auth.auth_users_id_seq', 1, true);


--
-- Name: auth_login_audit auth_login_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_login_audit
    ADD CONSTRAINT auth_login_audit_pkey PRIMARY KEY (id);


--
-- Name: auth_refresh_tokens auth_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_refresh_tokens
    ADD CONSTRAINT auth_refresh_tokens_pkey PRIMARY KEY (user_id);


--
-- Name: auth_refresh_tokens auth_refresh_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_refresh_tokens
    ADD CONSTRAINT auth_refresh_tokens_token_key UNIQUE (token);


--
-- Name: auth_roles auth_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_roles
    ADD CONSTRAINT auth_roles_pkey PRIMARY KEY (id);


--
-- Name: auth_roles auth_roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_roles
    ADD CONSTRAINT auth_roles_role_name_key UNIQUE (role_name);


--
-- Name: auth_user_roles auth_user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_user_roles
    ADD CONSTRAINT auth_user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: auth_users auth_users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_users
    ADD CONSTRAINT auth_users_email_key UNIQUE (email);


--
-- Name: auth_users auth_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_users
    ADD CONSTRAINT auth_users_pkey PRIMARY KEY (id);


--
-- Name: auth_users auth_users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_users
    ADD CONSTRAINT auth_users_username_key UNIQUE (username);


--
-- Name: idx_refresh_token; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_token ON auth.auth_refresh_tokens USING btree (token);


--
-- Name: idx_refresh_user; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_user ON auth.auth_refresh_tokens USING btree (user_id);


--
-- Name: auth_login_audit fk_audit_user; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_login_audit
    ADD CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES auth.auth_users(id);


--
-- Name: auth_refresh_tokens fk_refresh_user; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_refresh_tokens
    ADD CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES auth.auth_users(id);


--
-- Name: auth_user_roles fk_user_roles_role; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_user_roles
    ADD CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES auth.auth_roles(id);


--
-- Name: auth_user_roles fk_user_roles_user; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY auth.auth_user_roles
    ADD CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES auth.auth_users(id);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT USAGE ON SCHEMA public TO scadenziario;


--
-- Name: TABLE auth_login_audit; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE auth.auth_login_audit TO scadenziario;


--
-- Name: TABLE auth_refresh_tokens; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE auth.auth_refresh_tokens TO scadenziario;


--
-- Name: TABLE auth_roles; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE auth.auth_roles TO scadenziario;


--
-- Name: TABLE auth_user_roles; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE auth.auth_user_roles TO scadenziario;


--
-- Name: TABLE auth_users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE auth.auth_users TO scadenziario;


--
-- PostgreSQL database dump complete
--

