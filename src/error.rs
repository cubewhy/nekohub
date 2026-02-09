use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("User with username {0} already exists")]
    UserAlreadyExists(String),

    #[error("User try to register with an empty password")]
    EmptyPassword,

    #[error("Bad cerdentials")]
    BadCredentials { username: String, exists: bool },

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
            Self::EmptyPassword => {
                // There is no data provided in this logging message, so we keep its level debug
                tracing::debug!("User try to register with an empty password");
                StatusCode::BAD_REQUEST
            }
            Self::BadCredentials { username, exists } => {
                if *exists {
                    tracing::info!(
                        "User {username} attempt to login, but rejected with reason: bad password"
                    );
                } else {
                    tracing::debug!(
                        "An unknown (not existent) user try to auth with username {username}"
                    );
                }
                StatusCode::UNAUTHORIZED
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
