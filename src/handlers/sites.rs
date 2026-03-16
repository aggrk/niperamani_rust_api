use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use sqlx::MySqlPool;
use validator::Validate;

use crate::{
    models::site::{CreateSitePayload, Site, SiteWithSkills, UpdateSitePayload},
    utils::jwt::AuthUser,
};

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": message })))
}

// Helper to fetch a site with its skills
async fn fetch_site_with_skills(
    pool: &MySqlPool,
    site_id: i64,
) -> Result<SiteWithSkills, (StatusCode, Json<serde_json::Value>)> {
    let site = sqlx::query_as!(
        Site,
        "SELECT * FROM sites WHERE id = ?",
        site_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
    .ok_or_else(|| error(StatusCode::NOT_FOUND, "Site not found"))?;

    let skills = sqlx::query_scalar!(
        "SELECT skill FROM site_skills WHERE site_id = ?",
        site_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch skills"))?;

    Ok(SiteWithSkills::from_site(site, skills))
}

// GET /sites — all sites (any authenticated user)
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

// GET /sites/:id — get a single site
pub async fn get_site(
    _auth: AuthUser,
    State(pool): State<MySqlPool>,
    Path(site_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let site = fetch_site_with_skills(&pool, site_id).await?;

    Ok(Json(serde_json::json!({ "site": site })))
}

// PATCH /sites/:id — update a site (only the engineer who posted it)
pub async fn update_site(
    auth: AuthUser,
    State(pool): State<MySqlPool>,
    Path(site_id): Path<i64>,
    Json(payload): Json<UpdateSitePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
      // Validate first
    payload.validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;


    // 1. Fetch site to check ownership
    let site = sqlx::query_as!(
        Site,
        "SELECT * FROM sites WHERE id = ?",
        site_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
    .ok_or_else(|| error(StatusCode::NOT_FOUND, "Site not found"))?;

    // 2. Only the engineer who posted it or an admin can update
    if site.engineer_id != auth.id && auth.role != "admin" {
        return Err(error(StatusCode::FORBIDDEN, "You can only update your own sites"));
    }

    // 3. Validate dates if both are provided
    let start = payload.start_date.unwrap_or(site.start_date);
    let end   = payload.end_date.unwrap_or(site.end_date);

    if end <= start {
        return Err(error(StatusCode::BAD_REQUEST, "End date must be after start date"));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    // 4. Update only provided fields using COALESCE
    sqlx::query!(
        r#"
        UPDATE sites SET
            title             = COALESCE(?, title),
            address           = COALESCE(?, address),
            coordinates       = COALESCE(?, coordinates),
            required_handymen = COALESCE(?, required_handymen),
            start_date        = ?,
            end_date          = ?,
            payment_per_day   = COALESCE(?, payment_per_day),
            description       = COALESCE(?, description)
        WHERE id = ?
        "#,
        payload.title,
        payload.address,
        payload.coordinates,
        payload.required_handymen,
        start,
        end,
        payload.payment_per_day,
        payload.description,
        site_id,
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update site"))?;

    // 5. If skills provided, replace them entirely
    if let Some(skills) = &payload.skills_required {
        if skills.is_empty() {
            return Err(error(StatusCode::BAD_REQUEST, "At least one skill is required"));
        }

        // Delete old skills
        sqlx::query!("DELETE FROM site_skills WHERE site_id = ?", site_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update skills"))?;

        // Insert new skills
        for skill in skills {
            sqlx::query!(
                "INSERT INTO site_skills (site_id, skill) VALUES (?, ?)",
                site_id,
                skill
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to insert skill"))?;
        }
    }

    tx.commit()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit"))?;

    // 6. Return updated site
    let updated = fetch_site_with_skills(&pool, site_id).await?;

    Ok(Json(serde_json::json!({
        "message": "Site updated successfully",
        "site": updated,
    })))
}

// DELETE /sites/:id — delete a site (only the engineer who posted it)
pub async fn delete_site(
    auth: AuthUser,
    State(pool): State<MySqlPool>,
    Path(site_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {

    // 1. Fetch site to check ownership
    let site = sqlx::query_as!(
        Site,
        "SELECT * FROM sites WHERE id = ?",
        site_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
    .ok_or_else(|| error(StatusCode::NOT_FOUND, "Site not found"))?;

    // 2. Only the engineer who posted it or an admin can delete
    if site.engineer_id != auth.id && auth.role != "admin" {
        return Err(error(StatusCode::FORBIDDEN, "You can only delete your own sites"));
    }

    // 3. Delete site — site_skills deleted automatically via ON DELETE CASCADE
    sqlx::query!("DELETE FROM sites WHERE id = ?", site_id)
        .execute(&pool)
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete site"))?;

    Ok(Json(serde_json::json!({
        "message": "Site deleted successfully",
    })))
}

// POST /sites — create a site
pub async fn create_site(
    auth: AuthUser,
    State(pool): State<MySqlPool>,
    Json(payload): Json<CreateSitePayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
   // Validate first
    payload.validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()))?;

    // Then check dates
    if payload.end_date <= payload.start_date {
        return Err(error(StatusCode::BAD_REQUEST, "End date must be after start date"));
    }

    if auth.role != "engineer" && auth.role != "admin" {
        return Err(error(StatusCode::FORBIDDEN, "Only engineers can post sites"));
    }

    if payload.end_date <= payload.start_date {
        return Err(error(StatusCode::BAD_REQUEST, "End date must be after start date"));
    }

    if payload.skills_required.is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "At least one skill is required"));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

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