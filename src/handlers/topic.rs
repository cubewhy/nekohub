use std::sync::Arc;

use anyhow::Context;
use axum::{
    Json,
    extract::{Path, State},
};
use tracing::instrument;

use crate::{
    auth::JwtClaims,
    error::{AppError, Result},
    startup::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct CreateTopicModel {
    title: String,
    content: String,
    tags: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct CreateTopicResponse {}

#[instrument(skip(claims, state, payload))]
pub async fn create_topic(
    claims: JwtClaims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateTopicModel>,
) -> Result<Json<CreateTopicResponse>> {
    let user_id = claims.user_id;
    let tags = payload.tags;

    let mut transaction = state
        .db
        .begin()
        .await
        .context("Failed to start transaction")?;

    // create the post
    let _post = sqlx::query!(
        r#"
    INSERT INTO posts (owner, content)
    VALUES ($1, $2)
    RETURNING id
    "#,
        user_id,
        payload.content,
    )
    .fetch_one(&mut *transaction)
    .await
    .context("Failed to execute create post query")?;

    // create tags
    sqlx::query!(
        r#"
    INSERT INTO tags (name)
    SELECT * FROM UNNEST($1::text[])
    ON CONFLICT (name) DO NOTHING
    "#,
        &tags[..]
    )
    .execute(&mut *transaction)
    .await
    .context("Failed to execute create tags query")?;

    // TODO: insert into topics and topic_tags table

    // TODO: remove the rollback statement after the logic completely implemented
    transaction
        .rollback()
        .await
        .context("Failed to rollback transaction")?;

    Err(AppError::Internal(anyhow::anyhow!("Not implemented yet")))
}

#[derive(Debug, serde::Deserialize)]
pub struct CreatePostReplyModel {}

#[derive(Debug, serde::Serialize)]
pub struct CreatePostReplyResponse {}

#[instrument(skip(state, payload))]
pub async fn create_post_reply(
    claims: JwtClaims,
    State(state): State<Arc<AppState>>,
    Path(topic_id): Path<i64>,
    Json(payload): Json<CreatePostReplyModel>,
) -> Result<Json<CreatePostReplyResponse>> {
    // TODO: implement create post api
    Err(AppError::Internal(anyhow::anyhow!("Not implemented yet")))
}
