use std::sync::Arc;
use serde::{Serialize, Deserialize};
use axum::{
    Json,
    extract::{Request, State},
    routing::{get, post},
    Router, http::{header, StatusCode}
};
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};
use toml;

mod test;
mod token;
use token::*;
use tracing::info;

const TOKEN_DURATION_HOURS: usize = 1;
const DEFAULT_PORT: u16 = 3000;

#[derive(Serialize, Deserialize)]
struct Config {
    ip: String,
    port: Option<u16>,
    token_duration: u32,
    db_string: String
}

struct ServiceState {
    config: Config,
    token_generator: TokenGenerator,
    pool: MySqlPool
}


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = std::fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config).expect("Wrong configuraitons");
    let address = format!("{}:{}", config.ip, config.port.unwrap_or(DEFAULT_PORT));


    let pub_key = std::fs::read_to_string("keys/pubkey.pem").unwrap();
    let priv_key = std::fs::read_to_string("keys/privkey.pem").unwrap();

    let pub_key = pub_key.as_bytes();
    let priv_key = priv_key.as_bytes();

    let url = config.db_string.clone();
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Unable to connect to db");

    let token_generator = TokenGenerator::new(pub_key, priv_key).unwrap();

    let state = Arc::new(ServiceState { config, token_generator, pool });

    let app = Router::new()
        .route("/", get(ping))
        .route("/verify", post(verify))
        .route("/login", post(login))
        .route("/register", post(register))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("Unable to connect to the server");

    info!("Starting authentication service on {}", &address);
    axum::serve(listener, app)
        .await
        .expect("Error while starting application");
}


async fn register() {
}

async fn login(
    state: State<Arc<ServiceState>>,
    Json(credentials): Json<Credentials>
) -> String
{
    state.token_generator.token(credentials.email, state.config.token_duration).unwrap()
}

async fn ping() -> String {
    "pong".to_string()
}

async fn verify(
    state: State<Arc<ServiceState>>,
    req: Request
) -> Result<(), StatusCode> 
{
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Err(e) = state.token_generator.verify(auth_header) {
        return Err(StatusCode::UNAUTHORIZED);
    };

    Ok(())
}
