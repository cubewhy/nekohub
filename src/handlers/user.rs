use anyhow::Context;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;
use tracing::instrument;

use crate::{
    error::{AppError, Result},
    startup::AppState,
    telemetry::spawn_blocking_with_tracing,
};

#[derive(serde::Deserialize)]
pub struct RegisterUserModel {
    username: String,
    password: String,
}

#[derive(serde::Serialize)]
pub struct RegisterUserResponse {
    username: String,
}

#[instrument(name = "register_user", skip(state, payload))]
pub async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterUserModel>,
) -> Result<(StatusCode, Json<RegisterUserResponse>)> {
    let RegisterUserModel { username, password } = payload;
    if password.is_empty() {
        // empty password
        return Err(AppError::EmptyPassword);
    }

    let hashed_password = spawn_blocking_with_tracing(move || {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();

        Ok::<_, anyhow::Error>(
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!("Failed to hash password: {e:#}"))?
                .to_string(),
        )
    })
    .await
    // first "?": tokio JoinHandle error
    // second "?": anyhow::Error throwed inside the closure, Failed to hash password
    .context("Failed to wait hash password task quit")??;

    let insert_result = sqlx::query!(
        r#"
        INSERT INTO users (username, password)
        VALUES ($1, $2)
    "#,
        username,
        hashed_password,
    )
    .execute(&state.pool)
    .await;

    // https://stackoverflow.com/questions/68360932/rust-sqlx-handle-insert-on-conflict
    match insert_result {
        Ok(_) => Ok((StatusCode::CREATED, Json(RegisterUserResponse { username }))),

        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23505") => {
            return Err(AppError::UserAlreadyExists(username));
        }

        Err(e) => Err(anyhow::Error::from(e)
            .context("Failed to execute db query")
            .into()),
    }
}

#[derive(serde::Deserialize)]
pub struct LoginModel {
    username: String,
    password: String,
}

#[instrument(name = "authorize_user", skip(state, payload))]
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginModel>,
) -> impl IntoResponse {
    "it just works (login)"
}
