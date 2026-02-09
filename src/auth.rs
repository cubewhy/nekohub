use std::sync::Arc;

use anyhow::Context;
use axum::{extract::FromRequestParts, http::request::Parts};
use chrono::{DateTime, Utc};
use jsonwebtoken::{EncodingKey, Header};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    startup::AppState,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct JwtClaims {
    exp: usize,
    iat: usize,
    jti: Uuid,

    user_id: i64,
}

impl JwtClaims {
    pub fn new(user_id: i64, exp_at: DateTime<Utc>) -> Self {
        let now = Utc::now();

        Self {
            exp: exp_at.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4(),
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

impl FromRequestParts<Arc<AppState>> for JwtClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> core::result::Result<Self, Self::Rejection> {
        let jwt_secret = &state.auth.jwt_secret;

        // get the Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::MissingToken)?;

        if !auth_header.starts_with("Bearer ") {
            // unsupported token type
            return Err(AppError::UnsupportedTokenType);
        }

        let token = &auth_header[7..]; // Strip "Bearer "

        let token_data = jsonwebtoken::decode::<Self>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_ref()),
            &jsonwebtoken::Validation::default(),
        )
        .map_err(|_| AppError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
