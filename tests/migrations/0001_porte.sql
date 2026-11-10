
CREATE TABLE IF NOT EXISTS porte_users (
	id             bigserial PRIMARY KEY,
	facile_id      text UNIQUE,
	email          text NOT NULL UNIQUE,
	email_verified boolean NOT NULL DEFAULT false,
	name           text NOT NULL DEFAULT '',
	avatar_url     text NOT NULL DEFAULT '',
	avatar_source  text NOT NULL DEFAULT '',
	created_at     timestamptz NOT NULL DEFAULT now(),
	updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS porte_identities (
	user_id         bigint NOT NULL REFERENCES porte_users(id) ON DELETE CASCADE,
	provider        text NOT NULL,
	subject         text NOT NULL,
	password_hash   text NOT NULL DEFAULT '',
	access_token    text NOT NULL DEFAULT '',
	refresh_token   text NOT NULL DEFAULT '',
	token_expiry    timestamptz,
	roles           jsonb,
	roles_synced_at timestamptz,
	synced_at       timestamptz,
	created_at      timestamptz DEFAULT now(),
	PRIMARY KEY (provider, subject)
);
CREATE INDEX IF NOT EXISTS porte_identities_user_idx ON porte_identities (user_id);

UPDATE porte_identities SET subject = user_id::text
 WHERE provider = 'local' AND subject <> user_id::text;

CREATE TABLE IF NOT EXISTS porte_sessions (
	id           bigserial PRIMARY KEY,
	token_hash   text NOT NULL UNIQUE,
	user_id      bigint NOT NULL REFERENCES porte_users(id) ON DELETE CASCADE,
	label        text NOT NULL DEFAULT '',
	created_at   timestamptz NOT NULL DEFAULT now(),
	last_used_at timestamptz NOT NULL DEFAULT now(),
	expires_at   timestamptz
);
CREATE INDEX IF NOT EXISTS porte_sessions_user_idx ON porte_sessions (user_id);
CREATE INDEX IF NOT EXISTS porte_sessions_expiry_idx ON porte_sessions (expires_at)
	WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS porte_login_codes (
	code_hash   text PRIMARY KEY,
	user_id     bigint NOT NULL REFERENCES porte_users(id) ON DELETE CASCADE,
	expires_at  timestamptz NOT NULL,
	consumed_at timestamptz
);

CREATE TABLE IF NOT EXISTS porte_magic_links (
	token_hash  text PRIMARY KEY,
	user_id     bigint NOT NULL REFERENCES porte_users(id) ON DELETE CASCADE,
	ip          text NOT NULL DEFAULT '',
	created_at  timestamptz NOT NULL,
	expires_at  timestamptz NOT NULL,
	consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS porte_magic_links_user_idx ON porte_magic_links (user_id, created_at);
CREATE INDEX IF NOT EXISTS porte_magic_links_ip_idx ON porte_magic_links (ip, created_at)
	WHERE ip <> '';
CREATE INDEX IF NOT EXISTS porte_magic_links_expiry_idx ON porte_magic_links (expires_at);

DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns
	                WHERE table_schema = current_schema() AND table_name = 'porte_users' AND column_name = 'locale') THEN
		ALTER TABLE porte_users ADD COLUMN locale text NOT NULL DEFAULT 'en';
	END IF;
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns
	                WHERE table_schema = current_schema() AND table_name = 'porte_identities' AND column_name = 'created_at') THEN
		ALTER TABLE porte_identities ADD COLUMN created_at timestamptz;
		ALTER TABLE porte_identities ALTER COLUMN created_at SET DEFAULT now();
	ELSIF EXISTS (SELECT 1 FROM information_schema.columns
	               WHERE table_schema = current_schema() AND table_name = 'porte_identities'
	                 AND column_name = 'created_at' AND column_default IS NULL) THEN
		ALTER TABLE porte_identities ALTER COLUMN created_at SET DEFAULT now();
	END IF;
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns
	                WHERE table_schema = current_schema() AND table_name = 'porte_login_codes' AND column_name = 'consumed_at') THEN
		ALTER TABLE porte_login_codes ADD COLUMN consumed_at timestamptz;
	END IF;
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns
	                WHERE table_schema = current_schema() AND table_name = 'porte_login_codes' AND column_name = 'provider') THEN
		ALTER TABLE porte_login_codes ADD COLUMN provider text NOT NULL DEFAULT '',
		                              ADD COLUMN subject text NOT NULL DEFAULT '';
	END IF;
END
$$;


CREATE TABLE IF NOT EXISTS porte_api_keys (
	id              bigserial PRIMARY KEY,
	app             text NOT NULL,
	kind            text NOT NULL DEFAULT 'secret',
	prefix          text NOT NULL,
	token_hash      text NOT NULL UNIQUE,
	allowed_origins jsonb NOT NULL DEFAULT '[]'::jsonb,
	daily_quota     integer NOT NULL DEFAULT 0,
	created_at      timestamptz NOT NULL DEFAULT now(),
	revoked_at      timestamptz
);
CREATE INDEX IF NOT EXISTS porte_api_keys_app_idx ON porte_api_keys (app);
CREATE INDEX IF NOT EXISTS porte_api_keys_token_hash_idx ON porte_api_keys (token_hash) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS porte_api_key_usage (
	api_key_id bigint NOT NULL REFERENCES porte_api_keys(id) ON DELETE CASCADE,
	day        date NOT NULL DEFAULT CURRENT_DATE,
	count      bigint NOT NULL DEFAULT 0,
	PRIMARY KEY (api_key_id, day)
);
