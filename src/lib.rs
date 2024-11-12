#[cfg(test)]
mod test;
pub mod token;
pub mod routes;
pub mod state;

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use tracing::error;
use utoipa::ToSchema;

//expect implementation with logging to keep history of panic errors for Result
impl<T, E> ResultLogError<T, E> for Result<T, E> 
where 
    E: Display
{
    fn expect_and_log(self, message: &str) -> T {
        return match self {
            Ok(key) => key,
            Err(e) => {
                error!("{}: {}", message, e);
                panic!("{}: {}", message, e);
            }
        };
    }
}

//expect implementation with logging to keep history of panic errors for Option
impl<T> OptionLogError<T> for Option<T> {
    fn expect_and_log(self, message: &str) -> T {
        return match self {
            Some(key) => key,
            None => {
                error!("{}", message);
                panic!("{}", message);
            }
        };
    }
}

pub trait ResultLogError<T, E> {
    fn expect_and_log(self, message: &str) -> T; 
}

pub trait OptionLogError<T> {
    fn expect_and_log(self, message: &str) -> T; 
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(ToSchema)]
pub struct Permission {
    name: String,
    audience: String,
    description: String
}

impl Permission {
    pub async fn exists(&self, db: &MySqlPool) -> bool {
        sqlx::query!(
            "
                SELECT
                    name, audience, description
                FROM 
                    Permissions 
                WHERE
                    name = ? AND 
                    audience = ? AND
                    description = ?
            ",
            &self.name,
            &self.audience,
            &self.description
            )
            .fetch_optional(db)
            .await
            .is_ok_and(|x| x.is_some())
    }
    pub async fn insert(&self, db: &MySqlPool) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "
                INSERT INTO Permissions 
                    (name, audience, description)
                VALUES
                    (?, ?, ?)
            ",
            &self.name,
            &self.audience,
            &self.description
            )
            .fetch_optional(db)
            .await
            .and_then(|_| Ok(()))
    }
}
