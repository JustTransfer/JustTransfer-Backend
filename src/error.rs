use axum::{http::StatusCode, response::IntoResponse};
use diesel::result::Error as DieselError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
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

    #[error("monthly transfer quota reached")]
    QuotaExceeded,

    #[error("resource not found")]
    NotFound,

    #[error("error sending email")]
    EmailSendError,

    #[error("input validation error")]
    InputValidation,
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
            ServerError::EmailTaken => ApiError::Conflict,
            ServerError::Internal => ApiError::ServerError,
            ServerError::Unauthorized => ApiError::Unauthorized,
            ServerError::Forbidden => ApiError::Forbidden,
            ServerError::InsufficientStorage => ApiError::InsufficientStorage,
            ServerError::QuotaExceeded => ApiError::QuotaExceeded,
            ServerError::NotFound => ApiError::ServerNotFound,
            ServerError::EmailSendError => ApiError::ServerError,
            ServerError::InputValidation => ApiError::InputValidation,
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    InputValidation,
    Base64,
    Opaque,
    SessionError,
    ServerError,
    ServerNotFound,
    Unauthorized,
    Forbidden,
    Conflict,
    InsufficientStorage,
    QuotaExceeded,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            ApiError::InputValidation => StatusCode::BAD_REQUEST,
            ApiError::Base64 => StatusCode::BAD_REQUEST,
            ApiError::Opaque => StatusCode::BAD_REQUEST,
            ApiError::SessionError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServerNotFound => StatusCode::NOT_FOUND,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::Conflict => StatusCode::CONFLICT,
            ApiError::InsufficientStorage => StatusCode::INSUFFICIENT_STORAGE,
            ApiError::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
        };

        status.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(error: ApiError) -> StatusCode {
        error.into_response().status()
    }

    #[test]
    fn api_errors_map_to_http_statuses() {
        let cases = [
            (ApiError::InputValidation, StatusCode::BAD_REQUEST),
            (ApiError::Base64, StatusCode::BAD_REQUEST),
            (ApiError::Opaque, StatusCode::BAD_REQUEST),
            (ApiError::SessionError, StatusCode::INTERNAL_SERVER_ERROR),
            (ApiError::ServerError, StatusCode::INTERNAL_SERVER_ERROR),
            (ApiError::ServerNotFound, StatusCode::NOT_FOUND),
            (ApiError::Unauthorized, StatusCode::UNAUTHORIZED),
            (ApiError::Forbidden, StatusCode::FORBIDDEN),
            (ApiError::Conflict, StatusCode::CONFLICT),
            (
                ApiError::InsufficientStorage,
                StatusCode::INSUFFICIENT_STORAGE,
            ),
            (ApiError::QuotaExceeded, StatusCode::TOO_MANY_REQUESTS),
        ];
        for (error, expected) in cases {
            let name = format!("{error:?}");
            assert_eq!(status(error), expected, "{name}");
        }
    }

    #[test]
    fn server_errors_map_to_http_statuses() {
        let cases = [
            (ServerError::EmailTaken, StatusCode::CONFLICT),
            (ServerError::Internal, StatusCode::INTERNAL_SERVER_ERROR),
            (ServerError::Unauthorized, StatusCode::UNAUTHORIZED),
            (ServerError::Forbidden, StatusCode::FORBIDDEN),
            (
                ServerError::InsufficientStorage,
                StatusCode::INSUFFICIENT_STORAGE,
            ),
            (ServerError::QuotaExceeded, StatusCode::TOO_MANY_REQUESTS),
            (ServerError::NotFound, StatusCode::NOT_FOUND),
            // Mail failures must not leak as a distinct status.
            (
                ServerError::EmailSendError,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (ServerError::InputValidation, StatusCode::BAD_REQUEST),
        ];
        for (error, expected) in cases {
            let name = error.to_string();
            assert_eq!(status(error.into()), expected, "{name}");
        }
    }

    #[test]
    fn database_errors_are_internal() {
        let error: ServerError = DieselError::NotFound.into();
        assert!(matches!(error, ServerError::Internal));
    }
}
