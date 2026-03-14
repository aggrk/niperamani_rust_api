use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use axum::extract::Query;
use serde::Deserialize;
use axum_extra::extract::cookie::{Cookie, SameSite};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use sqlx::MySqlPool;
use uuid::Uuid;

use crate::{
    utils::email::send_verification_email,
    utils::jwt::create_token,
    models::user::{AuthResponse, RegisterPayload, SigninPayload,User, UserPublic},
};

pub async fn register(
    State(pool): State<MySqlPool>,
    Json(payload): Json<RegisterPayload>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {

    // 1. Hash password
    let hashed = hash(&payload.password, DEFAULT_COST)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password"))?;

    // 2. Generate verification token (expires in 24h)
    let verification_token    = Uuid::new_v4().to_string();
    let token_expires         = Utc::now() + Duration::hours(24);
    let token_expires_naive   = token_expires.naive_utc();

    // 3. Begin transaction — rolls back automatically if we return an Err
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    // 4. Insert user inside the transaction
    let result = sqlx::query!(
        r#"
        INSERT INTO users
            (name, email, phone, password, verification_token, verification_token_expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
        payload.name,
        payload.email,
        payload.phone,
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

    // 5. Fetch the newly created user (still inside transaction)
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE id = ?",
        user_id
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user"))?;

    // 6. Try sending verification email BEFORE committing
    //    If this fails the transaction is dropped and the user is NOT saved
    send_verification_email(&user.email, &verification_token)
        .await
        .map_err(|e| {
            tracing::error!("Failed to send verification email: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to send verification email")
        })?;

    // 7. Email sent — now commit the transaction
    tx.commit()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit transaction"))?;

    // 8. Create JWT
    let token = create_token(user.id, &user.role)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token"))?;

    // 9. Build cookie
    let cookie = Cookie::build(("token", token.clone()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::days(7));

    // 10. Build response
    let body = AuthResponse {
        token: token.clone(),
        user:  UserPublic::from(user),
    };

    let response = (
        StatusCode::CREATED,
        [
            (header::AUTHORIZATION, format!("Bearer {}", token)),
            (header::SET_COOKIE, cookie.to_string()),
        ],
        Json(body),
    )
        .into_response();

    Ok(response)
}

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": message })))
}

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
        SET status = 'active',
            verification_token = NULL,
            verification_token_expires_at = NULL
        WHERE verification_token = ?
          AND verification_token_expires_at > ?
          AND status = 'pending'
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


pub async fn signin(
    State(pool): State<MySqlPool>,
    Json(payload): Json<SigninPayload>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {

    // 1. Find user by email
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE email = ?",
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
    .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "Invalid email or password"))?;

    // 2. Check if account is verified
    if user.status == "pending" {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Please verify your email before signing in",
        ));
    }

    // 3. Check if account is suspended
    if user.status == "suspended" {
        return Err(error(
            StatusCode::FORBIDDEN,
            "Your account has been suspended",
        ));
    }

    // 4. Verify password
    let password_matches = verify(&payload.password, &user.password)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify password"))?;

    if !password_matches {
        return Err(error(StatusCode::UNAUTHORIZED, "Invalid email or password"));
    }

    // 5. Create JWT
    let token = create_token(user.id, &user.role)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token"))?;

    // 6. Build cookie
    let cookie = Cookie::build(("token", token.clone()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::days(7));

    // 7. Build response
    let body = AuthResponse {
        token: token.clone(),
        user: UserPublic::from(user),
    };

    let response = (
        StatusCode::OK,
        [
            (header::AUTHORIZATION, format!("Bearer {}", token)),
            (header::SET_COOKIE, cookie.to_string()),
        ],
        Json(body),
    )
        .into_response();

    Ok(response)
}

