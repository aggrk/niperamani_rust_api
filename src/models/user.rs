use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id:                            i64,
    pub name:                          String,
    pub email:                         String,
    pub phone:                         Option<String>,
    pub role:                          String,
    pub status:                        String,
    #[serde(skip_serializing)]
    pub password:                      String,
    pub password_changed_at:           Option<NaiveDateTime>,
    pub password_reset_token:          Option<String>,
    pub password_reset_expires_at:     Option<NaiveDateTime>,
    pub verification_token:            Option<String>,
    pub verification_token_expires_at: Option<NaiveDateTime>,
    pub created_at:                    NaiveDateTime,
}

impl User {
    pub async fn find_by_id_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        id: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id, name, email,
                phone                           as "phone: String",
                role, status, password,
                password_changed_at             as "password_changed_at: chrono::NaiveDateTime",
                password_reset_token            as "password_reset_token: String",
                password_reset_expires_at       as "password_reset_expires_at: chrono::NaiveDateTime",
                verification_token              as "verification_token: String",
                verification_token_expires_at   as "verification_token_expires_at: chrono::NaiveDateTime",
                created_at
            FROM users WHERE id = ?
            "#,
            id
        )
        .fetch_optional(&mut **tx)
        .await
    }

    pub async fn find_by_email(
        pool: &sqlx::MySqlPool,
        email: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id, name, email,
                phone                           as "phone: String",
                role, status, password,
                password_changed_at             as "password_changed_at: chrono::NaiveDateTime",
                password_reset_token            as "password_reset_token: String",
                password_reset_expires_at       as "password_reset_expires_at: chrono::NaiveDateTime",
                verification_token              as "verification_token: String",
                verification_token_expires_at   as "verification_token_expires_at: chrono::NaiveDateTime",
                created_at
            FROM users WHERE email = ?
            "#,
            email
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_reset_token(
        pool: &sqlx::MySqlPool,
        token: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let now = chrono::Utc::now().naive_utc();
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id, name, email,
                phone                           as "phone: String",
                role, status, password,
                password_changed_at             as "password_changed_at: chrono::NaiveDateTime",
                password_reset_token            as "password_reset_token: String",
                password_reset_expires_at       as "password_reset_expires_at: chrono::NaiveDateTime",
                verification_token              as "verification_token: String",
                verification_token_expires_at   as "verification_token_expires_at: chrono::NaiveDateTime",
                created_at
            FROM users
            WHERE password_reset_token      = ?
              AND password_reset_expires_at > ?
              AND status                    = 'active'
            "#,
            token,
            now,
        )
        .fetch_optional(pool)
        .await
    }
}

fn validate_password(password: &str) -> Result<(), validator::ValidationError> {
    if password.len() < 8 {
        let mut e = validator::ValidationError::new("too_short");
        e.message = Some("Password must be at least 8 characters".into());
        return Err(e);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        let mut e = validator::ValidationError::new("no_uppercase");
        e.message = Some("Password must contain at least one uppercase letter".into());
        return Err(e);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        let mut e = validator::ValidationError::new("no_lowercase");
        e.message = Some("Password must contain at least one lowercase letter".into());
        return Err(e);
    }
    if !password.chars().any(|c| c.is_numeric()) {
        let mut e = validator::ValidationError::new("no_number");
        e.message = Some("Password must contain at least one number".into());
        return Err(e);
    }
    if !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
        let mut e = validator::ValidationError::new("no_special_char");
        e.message = Some("Password must contain at least one special character".into());
        return Err(e);
    }
    Ok(())
}

fn validate_phone(phone: &str) -> Result<(), validator::ValidationError> {
    let valid = phone
        .chars()
        .all(|c| c.is_numeric() || c == '+' || c == '-' || c == ' ');
    if !valid {
        let mut e = validator::ValidationError::new("invalid_phone");
        e.message = Some("Phone number contains invalid characters".into());
        return Err(e);
    }
    Ok(())
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterPayload {
    #[validate(length(min = 2, max = 100, message = "Name must be between 2 and 100 characters"))]
    pub name:     String,

    #[validate(email(message = "Invalid email address"))]
    pub email:    String,

    #[validate(length(min = 10, max = 20, message = "Phone must be between 10 and 20 characters"))]
    #[validate(custom(function = "validate_phone"))]
    pub phone:    Option<String>,

    #[validate(length(min = 8, max = 72, message = "Password must be between 8 and 72 characters"))]
    #[validate(custom(function = "validate_password"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SigninPayload {
    #[validate(email(message = "Invalid email address"))]
    pub email:    String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordPayload {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ResetPasswordPayload {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,

    #[validate(length(min = 8, max = 72, message = "Password must be between 8 and 72 characters"))]
    #[validate(custom(function = "validate_password"))]
    pub password: String,

    #[validate(length(min = 1, message = "Confirm password is required"))]
    pub confirm_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user:  UserPublic,
}

#[derive(Debug, Serialize)]
pub struct UserPublic {
    pub id:     i64,
    pub name:   String,
    pub email:  String,
    pub role:   String,
    pub status: String,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self {
            id:     u.id,
            name:   u.name,
            email:  u.email,
            role:   u.role,
            status: u.status,
        }
    }
}