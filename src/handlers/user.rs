use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use jsonwebtoken::{EncodingKey, Header};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{Level, event, instrument};

use crate::{
    error::{AppError, Result},
    startup::{AppState, AuthState},
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
    access_token: String,
    refresh_token: String,
}

#[instrument(name = "register_user", skip(state, payload))]
pub async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterUserModel>,
) -> Result<(StatusCode, Json<RegisterUserResponse>)> {
    let RegisterUserModel { username, password } = payload;
    let AuthState {
        access_token_ttl,
        refresh_token_ttl,
        jwt_secret,
    } = &state.auth;

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
        RETURNING (id)
    "#,
        username,
        hashed_password,
    )
    .fetch_one(&state.db)
    .await;

    // https://stackoverflow.com/questions/68360932/rust-sqlx-handle-insert-on-conflict
    match insert_result {
        Ok(user) => {
            let TokenCredentials {
                access_token,
                refresh_token,
            } = create_session(
                &state.db,
                jwt_secret,
                *access_token_ttl,
                *refresh_token_ttl,
                user.id,
            )
            .await?;

            let json = RegisterUserResponse {
                username,
                access_token,
                refresh_token,
            };
            Ok((StatusCode::CREATED, Json(json)))
        }

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

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TokenCredentials {
    access_token: String,
    refresh_token: String,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    #[serde(flatten)]
    credentials: TokenCredentials,
}

#[instrument(name = "authorize_user", skip(state, payload))]
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginModel>,
) -> Result<Json<LoginResponse>> {
    let username = payload.username;
    let AuthState {
        jwt_secret,
        access_token_ttl,
        refresh_token_ttl,
    } = &state.auth;

    // get the user in the database
    let user = sqlx::query!(
        r#"
        SELECT id, username, password FROM users WHERE username = $1
    "#,
        &username
    )
    .fetch_optional(&state.db)
    .await
    .context("Failed to execute db query")?;

    let Some(user) = user else {
        return Err(AppError::BadCredentials {
            username,
            exists: false,
        });
    };

    event!(Level::DEBUG, "User {} attempt to login", user.username);

    let hashed_password = user.password;

    // compare password
    let compare_result = spawn_blocking_with_tracing(move || {
        let password = payload.password.as_bytes();
        let parsed_hash = PasswordHash::new(&hashed_password).map_err(|e| {
            anyhow::anyhow!("Failed to load password hash, is user column broken? Error: {e:#}")
        })?;
        Ok::<_, anyhow::Error>(
            Argon2::default()
                .verify_password(password, &parsed_hash)
                .is_ok(),
        )
    })
    .await
    .context("Failed to wait compare password task finish")??;

    if !compare_result {
        // bad password
        return Err(AppError::BadCredentials {
            username,
            exists: true,
        });
    }

    // create session
    let credentials = create_session(
        &state.db,
        jwt_secret,
        *access_token_ttl,
        *refresh_token_ttl,
        user.id,
    )
    .await?;

    Ok(Json(LoginResponse { credentials }))
}

async fn create_session(
    db: &PgPool,
    jwt_secret: &str,
    access_token_ttl: std::time::Duration,
    refresh_token_ttl: std::time::Duration,
    user_id: i64,
) -> Result<TokenCredentials> {
    let access_token_expires_at = chrono::Utc::now() + access_token_ttl;
    let refresh_token_expires_at = chrono::Utc::now() + refresh_token_ttl;

    // issue refresh token
    let refresh_token = JwtToken::new(user_id, refresh_token_expires_at).issue(jwt_secret)?;

    let refresh_token_hash = {
        let hash_bytes = Sha256::digest(&refresh_token);
        format!("{hash_bytes:x}")
    };

    // issue access token
    let access_token = JwtToken::new(user_id, access_token_expires_at).issue(jwt_secret)?;

    // create session in database
    sqlx::query!(
        r#"
        INSERT INTO sessions (user_id, refresh_token_hash, expires_at)
        VALUES ($1, $2, $3)
    "#,
        user_id,
        refresh_token_hash,
        refresh_token_expires_at,
    )
    .execute(db)
    .await
    .context("Failed to execute query")?;

    Ok(TokenCredentials {
        access_token: access_token.to_string(),
        refresh_token,
    })
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JwtToken {
    exp: usize,
    iat: usize,

    user_id: i64,
}

impl JwtToken {
    pub fn new(user_id: i64, exp_at: DateTime<Utc>) -> Self {
        let now = Utc::now();

        Self {
            exp: exp_at.timestamp() as usize,
            iat: now.timestamp() as usize,
            user_id,
        }
    }

    pub fn issue(&self, secret: &str) -> Result<String> {
        let encoding_key = EncodingKey::from_secret(secret.as_ref());
        let header = Header::default();
        let token =
            jsonwebtoken::encode(&header, self, &encoding_key).context("Failed to issue jwt")?;

        Ok(token)
    }
}
