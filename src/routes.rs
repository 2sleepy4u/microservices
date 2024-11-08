use std::sync::Arc;
use tracing::{info, warn, error};
use axum::{
    Json,
    extract::{Request, State},
    http::{header::{self}, StatusCode}, middleware::Next
};

use utoipa::OpenApi;

use crate::token::*;
use crate::state::*;



#[derive(OpenApi)]
#[openapi(paths(register, login, verify, ping))]
pub struct ApiDoc;



///middleware to handle endpoints which require authentication
pub async fn is_auth(
    state: State<Arc<ServiceState>>,
    req: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Err(e) = state.token_generator.verify(auth_header) {
        warn!("{:?}", e);
        return Err(StatusCode::UNAUTHORIZED);
    };

    let response = next.run(req).await;


    Ok(response)
}

#[utoipa::path(
    post,
    path = "/register",
    responses(
        (status = 200, description = "User successfully registered", body = Credentials),
        (status = NOT_ACCEPTABLE, description = "Not valid email"),
        (status = NOT_ACCEPTABLE, description = "Not valid password")
        ),
        )]
pub async fn register(
    state: State<Arc<ServiceState>>,
    Json(credentials): Json<Credentials>
) -> Result<(), StatusCode> 
{
    if !credentials.validate_email() {
        warn!("Email format not valid");
        return Err(StatusCode::NOT_ACCEPTABLE);
    }

    if !credentials.validate_password() {
        warn!("Weak password");
        return Err(StatusCode::NOT_ACCEPTABLE);
    }

    if let Err(e) = credentials.register(&state.pool).await {
        warn!("{:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(())
}

#[utoipa::path(
    post,
    path = "/login",
    responses(
        (status = 200, description = "User successfully logged. Token is retrived.", body = Credentials),
        (status = UNAUTHORIZED, description = ""),
        ),
        )]
pub async fn login(
    state: State<Arc<ServiceState>>,
    Json(credentials): Json<Credentials>
) -> Result<String, StatusCode> 
{
    match credentials.get_user(&state.pool).await {
        Ok(res) if res.is_some() => {
            return state.token_generator.token(credentials.email, state.config.token_duration)
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR));
        },
        Ok(_)=> return Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            error!("{}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}

#[utoipa::path(
    get,
    path = "/ping",
    responses(
        (status = 200, description = "Pong"),
        ),
        )]
pub async fn ping() -> String {
    "pong".to_string()
}

#[utoipa::path(
    post,
    path = "/verify",
    responses(
        (status = 200, description = "The token is valid"),
        ),
        )]
pub async fn verify(
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
