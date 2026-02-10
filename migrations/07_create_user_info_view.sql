CREATE VIEW user_info_view AS
SELECT
  u.id,
  u.username,
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
FROM users AS u
  LEFT JOIN user_roles ur ON u.id = ur.user_id
  LEFT JOIN roles r ON ur.role_id = r.id
GROUP BY u.id;

