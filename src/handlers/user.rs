use anyhow::Context;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{Json, extract::State, http::StatusCode};
use jsonwebtoken::{DecodingKey, Validation};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{Level, event, instrument};

use crate::{
    auth::JwtClaims,
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
                ..
            } = create_or_update_session(
                &state.db,
                jwt_secret,
                *access_token_ttl,
                *refresh_token_ttl,
                user.id,
                None,
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
    access_token_exp_at: usize,

    refresh_token: String,
    refresh_token_exp_at: usize,
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
    let credentials = create_or_update_session(
        &state.db,
        jwt_secret,
        *access_token_ttl,
        *refresh_token_ttl,
        user.id,
        None,
    )
    .await?;

    Ok(Json(LoginResponse { credentials }))
}

#[instrument(skip(db, jwt_secret))]
async fn create_or_update_session(
    db: &PgPool,
    jwt_secret: &str,
    access_token_ttl: std::time::Duration,
    refresh_token_ttl: std::time::Duration,
    user_id: i64,
    previous_token_hash: Option<String>,
) -> Result<TokenCredentials> {
    let access_token_expires_at = chrono::Utc::now() + access_token_ttl;
    let refresh_token_expires_at = chrono::Utc::now() + refresh_token_ttl;

    // issue refresh token
    let refresh_token = JwtClaims::new(user_id, refresh_token_expires_at).issue(jwt_secret)?;

    let refresh_token_hash = {
        let hash_bytes = Sha256::digest(&refresh_token);
        format!("{hash_bytes:x}")
    };

    // issue access token
    let access_token = JwtClaims::new(user_id, access_token_expires_at).issue(jwt_secret)?;

    if let Some(previous_token_hash) = previous_token_hash {
        // update the session
        sqlx::query!(
            r#"
            UPDATE sessions
            SET
                refresh_token_hash = $1,
                expires_at = $2
            WHERE refresh_token_hash = $3
            "#,
            refresh_token_hash,
            refresh_token_expires_at,
            previous_token_hash,
        )
        .execute(db)
        .await
        .context("Failed to execute query")?;

        event!(
            Level::INFO,
            "Refresh token for user {}, new session exp timestamp is {}",
            user_id,
            refresh_token_expires_at.to_string()
        );
    } else {
        // create session
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
    }

    Ok(TokenCredentials {
        access_token: access_token.to_string(),
        access_token_exp_at: access_token_expires_at.timestamp() as usize,

        refresh_token,
        refresh_token_exp_at: refresh_token_expires_at.timestamp() as usize,
    })
}

#[derive(serde::Serialize)]
pub struct RefreshResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(serde::Deserialize)]
pub struct RefreshModel {
    refresh_token: String,
}

#[instrument(name = "refresh_token", skip(state, payload))]
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshModel>,
) -> Result<Json<RefreshResponse>> {
    let RefreshModel {
        refresh_token: old_refresh_token,
    } = payload;
    let AuthState {
        access_token_ttl,
        refresh_token_ttl,
        jwt_secret,
    } = &state.auth;

    let validation_res = jsonwebtoken::decode::<JwtClaims>(
        &old_refresh_token,
        &DecodingKey::from_secret(state.auth.jwt_secret.as_ref()),
        &Validation::default(),
    );
    if let Err(e) = validation_res {
        return Err(AppError::BadRefreshToken(e));
    }

    // calculate hash for the old refresh token
    let old_refresh_token_hash = {
        let hash_bytes = Sha256::digest(&old_refresh_token);
        format!("{hash_bytes:x}")
    };

    // find the session in database
    let session_option = sqlx::query!(
        r#"
        SELECT expires_at, user_id FROM sessions
        WHERE refresh_token_hash = $1
    "#,
        old_refresh_token_hash
    )
    .fetch_optional(&state.db)
    .await
    .context("Failed to execute query")?;

    let Some(session) = session_option else {
        return Err(AppError::SessionNotFound(old_refresh_token_hash));
    };

    let TokenCredentials {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        ..
    } = create_or_update_session(
        &state.db,
        jwt_secret,
        *access_token_ttl,
        *refresh_token_ttl,
        session.user_id,
        Some(old_refresh_token_hash),
    )
    .await?;

    Ok(Json(RefreshResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
    }))
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct UserInfoResponse {
    id: i64,
    username: String,
    roles: sqlx::types::Json<Vec<RoleResponse>>,
    // TODO: response bio, avatar list (important, it is a list) after the systems implemented
}

#[derive(Debug, serde::Serialize, serde::Deserialize, sqlx::Type)]
pub struct RoleResponse {
    pub name: String,
    pub title: Option<String>,
}

#[instrument(skip(state, claims))]
pub async fn user_info(
    claims: JwtClaims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<UserInfoResponse>> {
    let user_id = claims.user_id;

    // query user in database
    let user = sqlx::query_as!(
        UserInfoResponse,
        r#"
    SELECT
        id as "id!",
        username as "username!",
        roles as "roles!: sqlx::types::Json<Vec<RoleResponse>>"
    FROM user_info_view
    WHERE id = $1
    "#,
        user_id
    )
    .fetch_one(&state.db)
    .await
    .context("Failed to execute query")?;

    Ok(Json(user))
}
