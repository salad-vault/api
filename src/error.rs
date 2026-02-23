use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    TooManyRequests(String),
    Internal(String),
    Database(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            ApiError::NotFound(msg) => write!(f, "Not found: {msg}"),
            ApiError::Conflict(msg) => write!(f, "Conflict: {msg}"),
            ApiError::TooManyRequests(msg) => write!(f, "Too many requests: {msg}"),
            ApiError::Internal(msg) => write!(f, "Internal error: {msg}"),
            ApiError::Database(msg) => write!(f, "Database error: {msg}"),
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        // Security: return generic messages to avoid info leakage
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (actix_web::http::StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Unauthorized(_) => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "Identifiants invalides".to_string(),
            ),
            ApiError::NotFound(_) => (
                actix_web::http::StatusCode::NOT_FOUND,
                "Ressource introuvable".to_string(),
            ),
            ApiError::Conflict(_) => (
                actix_web::http::StatusCode::CONFLICT,
                "Conflit".to_string(),
            ),
            ApiError::TooManyRequests(_) => (
                actix_web::http::StatusCode::TOO_MANY_REQUESTS,
                "Trop de tentatives".to_string(),
            ),
            ApiError::Internal(_) | ApiError::Database(_) => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Erreur interne".to_string(),
            ),
        };

        log::error!("{self}");

        HttpResponse::build(status).json(ErrorBody { error: message })
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        ApiError::Database(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        ApiError::Unauthorized(err.to_string())
    }
}
