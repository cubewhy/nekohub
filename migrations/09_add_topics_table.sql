CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE posts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  content text,

  created_at timestamptz NOT NULL DEFAULT NOW(),
  updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON posts
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TABLE topics (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  title text,
  post_id bigint REFERENCES posts(id),

  created_at timestamptz NOT NULL DEFAULT NOW(),
  updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON topics
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

CREATE TABLE tags (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text UNIQUE,
  used_count int DEFAULT 0 -- for performance practices, running COUNT(*) is heavy in production
);

-- for tags completion
CREATE INDEX idx_tags_search_gin ON tags USING gin (name gin_trgm_ops);
CREATE INDEX idx_tags_popularity ON tags (used_count DESC);

CREATE TABLE topic_tags (
  topic_id bigint REFERENCES topics(id) ON DELETE CASCADE,
  tag_id bigint REFERENCES tags(id) ON DELETE CASCADE,

  PRIMARY KEY (topic_id, tag_id)
);

CREATE INDEX idx_topic_tags_tag_id ON topic_tags(tag_id);
