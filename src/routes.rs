use std::{fs::Permissions, sync::Arc};
use serde::Serialize;
use tracing::{debug, error, info, warn};
use axum::{
    Json,
    extract::{Request, State, Host},
    http::{header::{self}, StatusCode}, middleware::Next
};

use utoipa::OpenApi;

use crate::{token::*, Permission};
use crate::state::*;



#[derive(OpenApi)]
#[openapi(
    modifiers(&Authorize),
    paths(register, login, verify, assign_role, create_role, ping))]
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
        .ok_or(StatusCode::UNAUTHORIZED)?
        .replace("Bearer ", "");

    if let Err(e) = state.token_generator.verify(&auth_header) {
        warn!("{:?}", e);
        return Err(StatusCode::UNAUTHORIZED);
    };

    let response = next.run(req).await;


    Ok(response)
}
use utoipa::openapi;
use utoipa::openapi::security::*;
use utoipa::Modify;
#[derive(Debug, Serialize)]
struct Authorize;

impl Modify for Authorize {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        if let Some(schema) = openapi.components.as_mut() {
            schema.add_security_scheme(
                "Token",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}


#[utoipa::path(
    post,
    path = "/assign_role",
    responses(
        (status = 200, description = "Role assigned successfully", body = User),
        (status = INTERNAL_SERVER_ERROR, description = "Error in update or insert"),
        ),
    request_body = User,
    security(
        ("Token"= [])
    ),
)]
pub async fn assign_role(
    state: State<Arc<ServiceState>>,
    Host(audience): Host,
    Json(user): Json<User>
) -> Result<(), StatusCode> 
{
    if user.get_user(&audience, &state.pool)
        .await
        .is_ok_and(|x| x.is_some()) 
    {
        if let Err(e) = user.update(&audience, &state.pool).await {
            error!("{}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    } else {
        if let Err(e) = user.insert(&audience, &state.pool).await {
            error!("{}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    Ok(())
}


#[utoipa::path(
    post,
    path = "/create_role",
    responses(
        (status = 200, description = "Role created successfully", body = Permission),
        (status = EXPECTATION_FAILED, description = "This role already exists"),
        ),
    request_body = Permission,
    security(
        ("Token"= [])
    ),

)]

pub async fn create_role(
    state: State<Arc<ServiceState>>,
    Json(permission): Json<Permission>
) -> Result<(), StatusCode> 
{
    if permission.exists(&state.pool).await {
        warn!("This role already exists: {}", permission.name);
        return Err(StatusCode::EXPECTATION_FAILED);
    } 

    if let Err(e) = permission.insert(&state.pool).await {
        error!("{}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(())
}

#[utoipa::path(
    post,
    path = "/register",
    responses(
        (status = 200, description = "User successfully registered", body = Credentials),
        (status = NOT_ACCEPTABLE, description = "Not valid email"),
        (status = NOT_ACCEPTABLE, description = "Not valid password")
        ),
    request_body = Credentials,
    security(
        ("Token"= [])
    ),
)]
pub async fn register(
    state: State<Arc<ServiceState>>,
    Host(audience): Host,
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

    if let Err(e) = credentials.register(audience, &state.pool).await {
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
    request_body = Credentials
)]
pub async fn login(
    state: State<Arc<ServiceState>>,
    Host(audience): Host,
    Json(credentials): Json<Credentials>
) -> Result<String, StatusCode> 
{
    let auth_service = state.config.ip.clone();
    match credentials.get_user(audience.clone(), &state.pool).await {
        Ok(Some(user)) => {
            let payload = Payload::new(state.config.token_duration, user.email, auth_service, audience, user.role);
            return state.token_generator.token(payload)
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR));
        },
        Ok(None)=> return Err(StatusCode::UNAUTHORIZED),
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
    security(
        ("Token"= [])
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
        .ok_or(StatusCode::UNAUTHORIZED)?
        .replace("Bearer ", "");

    if let Err(e) = state.token_generator.verify(&auth_header) {
        warn!("{:?}", e);
        return Err(StatusCode::UNAUTHORIZED);
    };

    Ok(())

}
