use axum::{routing::{get, post},extract::DefaultBodyLimit,http::{header, HeaderValue, Method}, Router};
use sqlx::MySqlPool;
use tower_http::{cors::CorsLayer,trace::TraceLayer};
use crate::handlers::auth::{register, signin,logout, verify_email,forgot_password, reset_password};
use crate::handlers::sites::{get_sites, create_site,update_site, delete_site, get_site};

pub fn create_router(pool: MySqlPool) -> Router {
       

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .allow_credentials(true);

    Router::new()
        .route("/auth/register",      post(register))
        .route("/auth/signin",        post(signin))      // ← new
        .route("/auth/verify-email",  get(verify_email)) 
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password",  post(reset_password))
        .route("/auth/logout", post(logout))
        .route("/sites", get(get_sites).post(create_site))
        .route("/sites/{id}", get(get_site).patch(update_site).delete(delete_site))
        .layer(cors)
        .layer(TraceLayer::new_for_http())  
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB max body size
        .with_state(pool)
}