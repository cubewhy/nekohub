ALTER TABLE users ADD COLUMN bio text;

DROP VIEW user_info_view;

CREATE VIEW user_info_view AS
SELECT
  u.id,
  u.username,
  u.bio,
  r_agg.roles
FROM users AS u
LEFT JOIN LATERAL (
  SELECT
      COALESCE(
        jsonb_agg(
          jsonb_build_object(
          'name', r.name,
          'title', r.title,
          'permissions', r.permissions::text[]
          )
        ) FILTER (WHERE r.id IS NOT NULL),
        '[]'
      ) AS roles
    FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.user_id = u.id
) r_agg ON TRUE;

