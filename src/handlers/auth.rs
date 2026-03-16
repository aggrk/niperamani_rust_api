use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use serde::Deserialize;
use sqlx::MySqlPool;
use uuid::Uuid;
use validator::Validate;

use crate::{
    models::user::{
        AuthResponse, ForgotPasswordPayload, RegisterPayload,
        ResetPasswordPayload, SigninPayload, User, UserPublic,
    },
    utils::{
        email::{send_password_reset_email, send_verification_email},
        jwt::create_token,
    },
};

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": message })))
}

// POST /auth/register
pub async fn register(
    State(pool): State<MySqlPool>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {

    payload.validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;

    let hashed = hash(&payload.password, DEFAULT_COST)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password"))?;

    let verification_token  = Uuid::new_v4().to_string();
    let token_expires_naive = (Utc::now() + Duration::hours(24)).naive_utc();

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    let result = sqlx::query!(
        r#"
        INSERT INTO users
            (name, email, phone, password, verification_token, verification_token_expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
        payload.name,
        payload.email,
        payload.phone as Option<String>,
        hashed,
        verification_token,
        token_expires_naive,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("Duplicate entry") {
            error(StatusCode::CONFLICT, "Email already in use")
        } else {
            error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user")
        }
    })?;

    let user_id = result.last_insert_id() as i64;

    let user = User::find_by_id_tx(&mut tx, user_id)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user"))?
        .ok_or_else(|| error(StatusCode::INTERNAL_SERVER_ERROR, "User not found after insert"))?;

    // Send email BEFORE committing — rolls back if email fails
    send_verification_email(&user.email, &verification_token)
        .await
        .map_err(|e| {
            tracing::error!("Failed to send verification email: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to send verification email")
        })?;

    tx.commit()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit transaction"))?;

    let token = create_token(user.id, &user.role)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token"))?;

    let cookie = Cookie::build(("token", token.clone()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::days(7));

    Ok((
        StatusCode::CREATED,
        [
            (header::AUTHORIZATION, format!("Bearer {}", token)),
            (header::SET_COOKIE, cookie.to_string()),
        ],
        Json(AuthResponse {
            token: token.clone(),
            user:  UserPublic::from(user),
        }),
    )
        .into_response())
}

// POST /auth/signin
pub async fn signin(
    State(pool): State<MySqlPool>,
    Json(payload): Json<SigninPayload>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {

    payload.validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;

    let user = User::find_by_email(&pool, &payload.email)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Invalid email or password"))?;

    if user.status == "pending" {
        return Err(error(StatusCode::FORBIDDEN, "Please verify your email before signing in"));
    }

    if user.status == "suspended" {
        return Err(error(StatusCode::FORBIDDEN, "Your account has been suspended"));
    }

    let password_matches = verify(&payload.password, &user.password)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify password"))?;

    if !password_matches {
        return Err(error(StatusCode::UNAUTHORIZED, "Invalid email or password"));
    }

    let token = create_token(user.id, &user.role)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token"))?;

    let cookie = Cookie::build(("token", token.clone()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::days(7));

    Ok((
        StatusCode::OK,
        [
            (header::AUTHORIZATION, format!("Bearer {}", token)),
            (header::SET_COOKIE, cookie.to_string()),
        ],
        Json(AuthResponse {
            token: token.clone(),
            user:  UserPublic::from(user),
        }),
    )
        .into_response())
}

// GET /auth/verify-email?token=...
#[derive(Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

pub async fn verify_email(
    State(pool): State<MySqlPool>,
    Query(params): Query<VerifyQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {

    let now = Utc::now().naive_utc();

    let result = sqlx::query!(
        r#"
        UPDATE users
        SET status                        = 'active',
            verification_token            = NULL,
            verification_token_expires_at = NULL
        WHERE verification_token            = ?
          AND verification_token_expires_at > ?
          AND status                        = 'pending'
        "#,
        params.token,
        now,
    )
    .execute(&pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Verification failed"))?;

    if result.rows_affected() == 0 {
        return Err(error(StatusCode::BAD_REQUEST, "Invalid or expired token"));
    }

    Ok(Json(serde_json::json!({ "message": "Email verified successfully" })))
}

// POST /auth/forgot-password
pub async fn forgot_password(
    State(pool): State<MySqlPool>,
    Json(payload): Json<ForgotPasswordPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {

    payload.validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;

    let user = User::find_by_email(&pool, &payload.email)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    // Always return the same response — prevents email enumeration
    if let Some(user) = user {
        if user.status == "active" {
            let reset_token         = Uuid::new_v4().to_string();
            let token_expires_naive = (Utc::now() + Duration::hours(1)).naive_utc();

            sqlx::query!(
                r#"
                UPDATE users
                SET password_reset_token      = ?,
                    password_reset_expires_at = ?
                WHERE id = ?
                "#,
                reset_token,
                token_expires_naive,
                user.id,
            )
            .execute(&pool)
            .await
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

            let email       = user.email.clone();
            let token_clone = reset_token.clone();

            tokio::spawn(async move {
                if let Err(e) = send_password_reset_email(&email, &token_clone).await {
                    tracing::error!("Failed to send password reset email: {}", e);
                }
            });
        }
    }

    Ok(Json(serde_json::json!({
        "message": "If an account with that email exists, a password reset link has been sent"
    })))
}

// POST /auth/reset-password
pub async fn reset_password(
    State(pool): State<MySqlPool>,
    Json(payload): Json<ResetPasswordPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {

    payload.validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;

    if payload.password != payload.confirm_password {
        return Err(error(StatusCode::BAD_REQUEST, "Passwords do not match"));
    }

    let user = User::find_by_reset_token(&pool, &payload.token)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid or expired reset token"))?;

    let hashed = hash(&payload.password, DEFAULT_COST)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password"))?;

    let now = Utc::now().naive_utc();

    sqlx::query!(
        r#"
        UPDATE users
        SET password                  = ?,
            password_changed_at       = ?,
            password_reset_token      = NULL,
            password_reset_expires_at = NULL
        WHERE id = ?
        "#,
        hashed,
        now,
        user.id,
    )
    .execute(&pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to reset password"))?;

    Ok(Json(serde_json::json!({
        "message": "Password reset successfully. You can now sign in with your new password."
    })))
}

// POST /auth/logout
pub async fn logout() -> Result<Response, (StatusCode, Json<serde_json::Value>)> {

    // Clear the cookie by setting max_age to 0
    let cookie = Cookie::build(("token", ""))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(0));  // ← expires immediately

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie.to_string())],
        Json(serde_json::json!({ "message": "Logged out successfully" })),
    )
        .into_response())
}