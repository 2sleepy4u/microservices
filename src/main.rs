use std::sync::Arc;
use serde::{Serialize, Deserialize};
use axum::{
    Json,
    extract::{Request, State},
    routing::{get, post},
    Router, http::{header, StatusCode}
};
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};

mod test;
mod token;
use token::*;
use tracing::{info, warn, error};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;

const DEFAULT_TOKEN_DURATION_HOURS: usize = 1;
const DEFAULT_IP: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 3000;

#[derive(Serialize, Deserialize)]
struct Config {
    ip: String,
    port: u16,
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
    let debug_file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("log-debug.json")
        .unwrap();

    let subscriber = tracing_subscriber::Registry::default()
        .with(
            //log to console
            tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(true)
        )
        .with(
            //log to file
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(debug_file)
        );
    
    tracing::subscriber::set_global_default(subscriber).unwrap();
    
    dotenv::dotenv().ok();

    let db_string = std::env::var("DATABASE_URL").expect("Connection string not found");
    let ip = std::env::var("IP").unwrap_or(DEFAULT_IP.to_string());
    let token_duration = std::env::var("TOKEN_DURATION").unwrap_or(DEFAULT_TOKEN_DURATION_HOURS.to_string()).parse::<u32>().unwrap();
    let port = std::env::var("PORT").unwrap_or(DEFAULT_PORT.to_string()).parse::<u16>().unwrap();


    let pub_key = std::fs::read_to_string("keys/pubkey.pem").unwrap();
    let priv_key = std::fs::read_to_string("keys/privkey.pem").unwrap();

    let pub_key = pub_key.as_bytes();
    let priv_key = priv_key.as_bytes();

    let url = db_string.clone();
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("Unable to connect to db");

    let address = format!("{}:{}", ip, port);

    let config: Config = Config { ip, port, token_duration, db_string };
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


async fn register(
    state: State<Arc<ServiceState>>,
    Json(credentials): Json<Credentials>
) -> Result<(), StatusCode> 
{
    if let Err(e) = credentials.register(&state.pool).await {
        warn!("{:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(())
}

async fn login(
    state: State<Arc<ServiceState>>,
    Json(credentials): Json<Credentials>
) -> Result<String, StatusCode> 
{
    match credentials.get_user(&state.pool).await {
        Ok(res) if res.is_some() => {
            return state.token_generator.token(credentials.email, state.config.token_duration)
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR));
        },
        Ok(_)=> return Err(StatusCode::INTERNAL_SERVER_ERROR),
        Err(e) => {
            error!("{}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
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
        warn!("{:?}", e);
        return Err(StatusCode::UNAUTHORIZED);
    };

    Ok(())
}
