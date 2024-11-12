use std::sync::Arc;

use axum::{
    routing::post,
    Router, http::{header::CONTENT_TYPE, Method}, middleware};
use sqlx::mysql::MySqlPoolOptions;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::prelude::*;
use utoipa::OpenApi;

use auth::{token::*, ResultLogError};
use auth::state::*;
use auth::routes::ApiDoc;
use auth::routes;



#[tokio::main]
async fn main() {
    #[cfg(debug_assertions)]
    std::fs::write("./api-docs/open-api.json", ApiDoc::openapi().to_pretty_json().unwrap()).unwrap();

    //log file
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
    
    //load dotenv file
    dotenv::dotenv().ok();

    //load config from env
    let config: Config = Config::load_from_env();

    let address = format!("{}:{}", config.ip, config.port);
    let pub_key = config.pub_key.as_bytes();
    let priv_key = config.priv_key.as_bytes();

    let url = config.db_string.clone();

    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect_and_log("Unable to connect to db");


    //initialize service shared state
    //Initialize the token generator once so it stores the keys, reducing performance overhead
    let token_generator = TokenGenerator::new(pub_key, priv_key).unwrap();
    let state = Arc::new(ServiceState { config, token_generator, pool });

    let app = Router::new()
        .route("/register", post(routes::register))
        .route("/assign_role", post(routes::assign_role))
        .route("/create_role", post(routes::create_role))
        //protects above endpoints with token login
        .layer(middleware::from_fn_with_state(state.clone(), routes::is_auth))
        //      .route("/ping", get(routes::ping))
        .route("/verify", post(routes::verify))
        .route("/login", post(routes::login))
        .with_state(state)
        .layer(ServiceBuilder::new()
               //logs all the http traffic
               .layer(TraceLayer::new_for_http())
               //handle CORS requests
               .layer(CorsLayer::new()
                      .allow_methods([Method::GET, Method::POST])
                      .allow_origin(Any)
                      .allow_headers([CONTENT_TYPE])
                     )
          );

    #[cfg(debug_assertions)]
    let app = app.merge(utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
                        .url("/api-docs/openapi.json", ApiDoc::openapi()));


    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect_and_log("Unable to connect to the server");

    info!("Starting authentication service on {}", &address);

    axum::serve(listener, app)
        .await
        .expect_and_log("Error while starting application");
}
