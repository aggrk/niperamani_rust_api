use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id:                           i64,
    pub name:                         String,
    pub email:                        String,
    pub phone:                        Option<String>,
    pub role:                         String,
    pub status:                       String,
    #[serde(skip_serializing)]        // never expose password in responses
    pub password:                     String,
    pub password_changed_at:          Option<NaiveDateTime>,
    pub password_reset_token:         Option<String>,
    pub password_reset_expires_at:    Option<NaiveDateTime>,
    pub verification_token:           Option<String>,
    pub verification_token_expires_at: Option<NaiveDateTime>,
    pub created_at:                   NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    pub name:     String,
    pub email:    String,
    pub phone:    Option<String>,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SigninPayload {
    pub email:    String,
    pub password: String,
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
        Self { id: u.id, name: u.name, email: u.email, role: u.role, status: u.status }
    }
}