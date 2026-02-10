use std::sync::Arc;

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
pub struct CreateTopicModel {}

#[derive(Debug, serde::Serialize)]
pub struct CreateTopicResponse {}

#[instrument(skip(state, payload))]
pub async fn create_topic(
    claims: JwtClaims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateTopicModel>,
) -> Result<Json<CreateTopicResponse>> {
    // TODO: implement create topic api
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
