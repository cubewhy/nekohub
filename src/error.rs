use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("User with username {0} already exists")]
    UserAlreadyExists(String),

    #[error("Internal Server Error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            Self::UserAlreadyExists(username) => {
                tracing::info!(
                    "User try to register a new account with conflict username {username}"
                );
                StatusCode::CONFLICT
            }
            Self::Internal(e) => {
                tracing::error!("{e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        let timestamp = chrono::Utc::now().timestamp();

        (
            status,
            Json(json!({
                "error": self.to_string(),
                "timestamp": timestamp
            })),
        )
            .into_response()
    }
}

pub type Result<T> = core::result::Result<T, AppError>;
