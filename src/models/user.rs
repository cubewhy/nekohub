#[derive(Debug, PartialEq, sqlx::Type)]
#[sqlx(type_name = "permission", rename_all = "snake_case")]
pub enum Permission {
    CreateTopic,
    CreatePost,
}

#[derive(sqlx::FromRow)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub title: Option<String>,
    pub permissions: Vec<Permission>,
}
