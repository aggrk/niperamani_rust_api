use chrono::{NaiveDate, NaiveDateTime};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Site {
    pub id:                 i64,
    pub engineer_id:        i64,
    pub title:              String,
    pub address:            String,
    pub coordinates:        String,
    pub required_handymen:  i32,
    pub start_date:         NaiveDate,
    pub end_date:           NaiveDate,
    pub payment_per_day:    Decimal,  // ← was f64
    pub description:        Option<String>,
    pub posted_at:          NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct SiteWithSkills {
    pub id:                 i64,
    pub engineer_id:        i64,
    pub title:              String,
    pub address:            String,
    pub coordinates:        String,
    pub required_handymen:  i32,
    pub start_date:         NaiveDate,
    pub end_date:           NaiveDate,
    pub payment_per_day:    Decimal,  // ← was f64
    pub description:        Option<String>,
    pub posted_at:          NaiveDateTime,
    pub skills:             Vec<String>,
}

impl SiteWithSkills {
    pub fn from_site(site: Site, skills: Vec<String>) -> Self {
        Self {
            id:                site.id,
            engineer_id:       site.engineer_id,
            title:             site.title,
            address:           site.address,
            coordinates:       site.coordinates,
            required_handymen: site.required_handymen,
            start_date:        site.start_date,
            end_date:          site.end_date,
            payment_per_day:   site.payment_per_day,
            description:       site.description,
            posted_at:         site.posted_at,
            skills,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateSitePayload {
    pub title:              String,
    pub address:            String,
    pub coordinates:        String,
    pub required_handymen:  i32,
    pub skills_required:    Vec<String>,
    pub start_date:         NaiveDate,
    pub end_date:           NaiveDate,
    pub payment_per_day:    Decimal,  // ← was f64
    pub description:        Option<String>,
}