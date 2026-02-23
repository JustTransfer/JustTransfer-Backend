use axum::{http::StatusCode, response::IntoResponse};
use diesel::result::Error as DieselError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("username already exists")]
    UsernameTaken,

    #[error("email already used")]
    EmailTaken,

    #[error("internal error")]
    Internal,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("insufficient storage")]
    InsufficientStorage,

    #[error("resource not found")]
    NotFound,
}
impl From<aws_sdk_s3::error::BuildError> for ServerError {
    fn from(_: aws_sdk_s3::error::BuildError) -> Self {
        ServerError::Internal
    }
}
impl From<std::array::TryFromSliceError> for ServerError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        ServerError::Internal
    }
}
impl From<DieselError> for ServerError {
    fn from(err: DieselError) -> Self {
        match err {
            _ => ServerError::Internal,
        }
    }
}

impl From<ServerError> for ApiError {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::UsernameTaken | ServerError::EmailTaken => ApiError::Conflict,
            ServerError::Internal => ApiError::ServerError,
            ServerError::Unauthorized => ApiError::Unauthorized,
            ServerError::Forbidden => ApiError::Forbidden,
            ServerError::InsufficientStorage => ApiError::InsufficientStorage,
            ServerError::NotFound => ApiError::ServerNotFound,
        }
    }
}



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
    InsufficientStorage,
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
            ApiError::InsufficientStorage => StatusCode::INSUFFICIENT_STORAGE,
        };

        status.into_response()
    }
}

