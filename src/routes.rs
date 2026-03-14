use axum::{routing::{get, post}, Router};
use sqlx::MySqlPool;
use crate::handlers::auth::{register, signin, verify_email};
use crate::handlers::sites::{get_sites, create_site};

pub fn create_router(pool: MySqlPool) -> Router {
    Router::new()
        .route("/auth/register",      post(register))
        .route("/auth/signin",        post(signin))      // ← new
        .route("/auth/verify-email",  get(verify_email))
        .route("/sites", get(get_sites).post(create_site))
        .with_state(pool)
}