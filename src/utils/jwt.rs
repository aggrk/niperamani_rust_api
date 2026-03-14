use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,       // user id
    pub role: String,
    pub exp: usize,
}

pub fn create_token(user_id: i64, role: &str) -> anyhow::Result<String> {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiry = Utc::now() + Duration::days(7);

    let claims = Claims {
        sub: user_id,
        role: role.to_string(),
        exp: expiry.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok(token)
}

pub fn verify_token(token: &str) -> anyhow::Result<Claims> {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(data.claims)
}

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, header, StatusCode},
    Json,
};

// Called on every protected route automatically
pub struct AuthUser {
    pub id:   i64,
    pub role: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try Authorization header first, then fall back to cookie
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned)
            .or_else(|| {
                parts.headers
                    .get(header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|cookies| {
                        cookies.split(';').find_map(|c| {
                            let c = c.trim();
                            c.strip_prefix("token=").map(str::to_owned)
                        })
                    })
            })
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "Missing token" })),
                )
            })?;

        // verify_token is used HERE
        let claims = verify_token(&token).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Invalid or expired token" })),
            )
        })?;

        Ok(AuthUser {
            id:   claims.sub,
            role: claims.role,
        })
    }
}