use sqlx::MySqlPool;
use serde::{Serialize, Deserialize};

pub const DEFAULT_TOKEN_DURATION_HOURS: usize = 1;
pub const DEFAULT_IP: &str = "0.0.0.0";
pub const DEFAULT_PORT: u16 = 3000;

use crate::token::*;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub ip: String,
    pub port: u16,
    pub token_duration: u32,
    pub db_string: String
}

impl Config {
    pub fn load_from_env() -> Self {
        let db_string = std::env::var("DATABASE_URL")
            .expect("Connection string not found");
        let ip = std::env::var("IP")
            .unwrap_or(DEFAULT_IP.to_string());
        let token_duration = std::env::var("TOKEN_DURATION")
            .unwrap_or(DEFAULT_TOKEN_DURATION_HOURS.to_string())
            .parse::<u32>()
            .unwrap();
        let port = std::env::var("PORT")
            .unwrap_or(DEFAULT_PORT.to_string())
            .parse::<u16>()
            .unwrap();

        Self { ip, port, token_duration, db_string }
    }
}

pub struct ServiceState {
    pub config: Config,
    pub token_generator: TokenGenerator,
    pub pool: MySqlPool
}


