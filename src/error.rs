use axum::{http::StatusCode, response::IntoResponse};

#[derive(Debug)]
pub enum ApiError {
    InputValidation,
    Base64,
    Opaque,
    JWTError,
    ServerError,
    ServerNotFound,
    Unauthorized,
    Forbidden,
    Conflict,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            ApiError::InputValidation => StatusCode::BAD_REQUEST,
            ApiError::Base64 => StatusCode::BAD_REQUEST,
            ApiError::Opaque => StatusCode::BAD_REQUEST,
            ApiError::JWTError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServerNotFound => StatusCode::NOT_FOUND,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::Conflict => StatusCode::CONFLICT,
        };

        status.into_response()
    }
}

