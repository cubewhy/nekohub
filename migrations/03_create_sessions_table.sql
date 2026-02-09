ALTER TABLE users ADD PRIMARY KEY (id);

CREATE TABLE sessions (
  id bigint GENERATED ALWAYS AS IDENTITY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash text UNIQUE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT NOW(),
  updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
-- optimize delete session operations
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Note: the function update_timestamp was created in 01_create_users_table.sql
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();
