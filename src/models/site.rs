use chrono::{NaiveDate, NaiveDateTime};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use validator::Validate;

// Custom validator for Decimal > 0
fn validate_positive_decimal(value: &Decimal) -> Result<(), validator::ValidationError> {
    if *value > Decimal::ZERO {
        Ok(())
    } else {
        Err(validator::ValidationError::new("payment_must_be_positive"))
    }
}

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
    pub payment_per_day:    Decimal,
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
    pub payment_per_day:    Decimal,
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

#[derive(Debug, Deserialize, Validate)]
pub struct CreateSitePayload {
    #[validate(length(min = 3, max = 255, message = "Title must be between 3 and 255 characters"))]
    pub title:              String,

    #[validate(length(min = 3, max = 255, message = "Address must be between 3 and 255 characters"))]
    pub address:            String,

    #[validate(length(min = 3, max = 100, message = "Invalid coordinates format"))]
    pub coordinates:        String,

    #[validate(range(min = 1, max = 1000, message = "Required handymen must be between 1 and 1000"))]
    pub required_handymen:  i32,

    #[validate(length(min = 1, max = 20, message = "Must provide between 1 and 20 skills"))]
    pub skills_required:    Vec<String>,

    pub start_date:         NaiveDate,
    pub end_date:           NaiveDate,

    #[validate(custom(function = "validate_positive_decimal"))]
    pub payment_per_day:    Decimal,

    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    pub description:        Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateSitePayload {
    #[validate(length(min = 3, max = 255, message = "Title must be between 3 and 255 characters"))]
    pub title:              Option<String>,

    #[validate(length(min = 3, max = 255, message = "Address must be between 3 and 255 characters"))]
    pub address:            Option<String>,

    #[validate(length(min = 3, max = 100, message = "Invalid coordinates format"))]
    pub coordinates:        Option<String>,

    #[validate(range(min = 1_i32, max = 1000_i32, message = "Required handymen must be between 1 and 1000"))]
    pub required_handymen:  Option<i32>,

    #[validate(length(min = 1, max = 20, message = "Must provide between 1 and 20 skills"))]
    pub skills_required:    Option<Vec<String>>,

    pub start_date:         Option<NaiveDate>,
    pub end_date:           Option<NaiveDate>,

    #[validate(custom(function = "validate_positive_decimal"))]
    pub payment_per_day:    Option<Decimal>,

    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    pub description:        Option<String>,
}