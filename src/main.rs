mod db;
mod utils;  
mod handlers;
mod models;
mod routes;

use dotenvy::dotenv;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let pool = db::connect().await;
    let app = routes::create_router(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("Listening on :3000");
    axum::serve(listener, app).await.unwrap();
}