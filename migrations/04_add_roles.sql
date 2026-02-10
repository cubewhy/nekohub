CREATE TYPE permission AS enum ();

CREATE TABLE roles (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL UNIQUE,
  title text,
  permissions permission[]
);

CREATE TABLE user_roles (
  user_id bigint REFERENCES users(id) ON DELETE CASCADE,
  role_id bigint REFERENCES roles(id) ON DELETE CASCADE,

  PRIMARY KEY (user_id, role_id)
)
