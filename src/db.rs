use sqlx::{MySqlPool, mysql::MySqlPoolOptions};

pub async fn connect() -> MySqlPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("Failed to connect to MySQL")
}