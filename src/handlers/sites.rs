use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use sqlx::MySqlPool;

use crate::{
    models::site::{CreateSitePayload, Site, SiteWithSkills},
    utils::jwt::AuthUser,
};

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": message })))
}

// GET /sites — fetch all sites (any authenticated user can browse)
pub async fn get_sites(
    _auth: AuthUser,
    State(pool): State<MySqlPool>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {

    let sites = sqlx::query_as!(
        Site,
        "SELECT * FROM sites ORDER BY posted_at DESC"
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch sites"))?;

    // Fetch skills for each site
    let mut sites_with_skills = Vec::new();

    for site in sites {
        let skills = sqlx::query_scalar!(
            "SELECT skill FROM site_skills WHERE site_id = ?",
            site.id
        )
        .fetch_all(&pool)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch skills"))?;

        sites_with_skills.push(SiteWithSkills::from_site(site, skills));
    }

    Ok(Json(serde_json::json!({
        "count": sites_with_skills.len(),
        "sites": sites_with_skills,
    })))
}

// POST /sites — only engineers can post a site
pub async fn create_site(
    auth: AuthUser,
    State(pool): State<MySqlPool>,
    Json(payload): Json<CreateSitePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {

    // Only engineers/admins can post sites
    if auth.role != "engineer" && auth.role != "admin" {
        return Err(error(StatusCode::FORBIDDEN, "Only engineers can post sites"));
    }

    // Validate dates
    if payload.end_date <= payload.start_date {
        return Err(error(StatusCode::BAD_REQUEST, "End date must be after start date"));
    }

    if payload.skills_required.is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "At least one skill is required"));
    }

    // Begin transaction — insert site + skills atomically
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    // Insert site
    let result = sqlx::query!(
        r#"
        INSERT INTO sites
            (engineer_id, title, address, coordinates, required_handymen,
             start_date, end_date, payment_per_day, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        auth.id,
        payload.title,
        payload.address,
        payload.coordinates,
        payload.required_handymen,
        payload.start_date,
        payload.end_date,
        payload.payment_per_day,
        payload.description,
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create site"))?;

    let site_id = result.last_insert_id() as i64;

    // Insert each skill
    for skill in &payload.skills_required {
        sqlx::query!(
            "INSERT INTO site_skills (site_id, skill) VALUES (?, ?)",
            site_id,
            skill
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save skills"))?;
    }

    tx.commit()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit"))?;

    Ok(Json(serde_json::json!({
        "message": "Site created successfully",
        "site_id": site_id,
    })))
}