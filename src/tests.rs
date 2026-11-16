
pub(crate) fn encoded() -> String {
    "A".repeat(crate::consts::MIN_LENGTH_BASE64 as usize)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        response::IntoResponse,
    };
    use chrono::{Duration, TimeZone, Utc};

    use crate::api_handlers::auth::{Role, RoleLimits, UserClaims};
    use crate::api_handlers::misc::{
        validate_email, validate_file_size_with_limit, validate_int_param, validate_int_param_64,
        validate_optional_email,
    };
    use crate::error::{ApiError, ServerError};
    use crate::server::{cron, payment};
    use crate::{api_handlers::misc::AppState, build_router};
    use diesel::r2d2::ConnectionManager;
    use diesel::PgConnection;
    use proptest::prelude::*;
    use tower::ServiceExt;
    use uuid::Uuid;

    const TEST_EMAIL: &str = "test@example.com";
    const TEST_TIME: chrono::DateTime<Utc> =
        chrono::DateTime::from_timestamp(1_767_276_000, 0).unwrap();

    fn test_app() -> axum::Router {
        let _ = crate::consts::FRONTEND_URL.set("http://localhost".to_owned());
        let _ = crate::consts::SESSION_DURATION_MINUTES.set(60);

        let db = diesel::r2d2::Pool::builder()
            .max_size(1)
            .build_unchecked(ConnectionManager::<PgConnection>::new(
                "postgres://unused:unused@localhost/unused",
            ));
        let s3 = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .build(),
        );
        let mailer = lettre::SmtpTransport::builder_dangerous("localhost").build();

        build_router(AppState {
            db,
            s3,
            bucket_name: "test".to_owned(),
            mailer,
        })
    }

    fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .unwrap()
    }

    async fn status_for(request: Request<Body>) -> StatusCode {
        test_app().oneshot(request).await.unwrap().status()
    }

    fn test_claims() -> UserClaims {
        UserClaims {
            id: Uuid::nil(),
            email: TEST_EMAIL.to_owned(),
            role: Role::Anonymous,
            iat: 0,
        }
    }

    fn test_limits() -> RoleLimits {
        RoleLimits {
            max_lifetime: 7,
            max_file_size: 100,
            max_downloads: 3,
        }
    }

    #[tokio::test]
    async fn protected_routes_require_a_session() {
        assert_eq!(
            status_for(request(Method::GET, "/api/user", Body::empty())).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn register_route_rejects_invalid_payloads_at_http_boundary() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/register/start")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"client_registration_start":"short"}"#))
            .unwrap();

        assert_eq!(status_for(request).await, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn integer_validators_enforce_lower_and_upper_bounds() {
        for value in [0, 1, 1000] {
            assert!(validate_int_param(value).is_ok(), "value: {value}");
        }
        for value in [-1, 1001] {
            assert!(validate_int_param(value).is_err(), "value: {value}");
        }
        assert!(validate_int_param_64(0).is_ok());
        assert!(validate_int_param_64(-1).is_err());
    }

    #[test]
    fn email_validators_accept_and_reject_expected_values() {
        for email in [TEST_EMAIL, "user+tag@example.co.uk"] {
            assert!(validate_email(email).is_ok(), "email: {email}");
        }
        for email in ["not-an-email", ""] {
            assert!(validate_email(email).is_err(), "email: {email}");
        }
    }

    #[test]
    fn api_errors_map_to_their_contract_statuses() {
        let cases = [
            (ApiError::InputValidation, StatusCode::BAD_REQUEST),
            (ApiError::Unauthorized, StatusCode::UNAUTHORIZED),
            (ApiError::ServerNotFound, StatusCode::NOT_FOUND),
            (ApiError::QuotaExceeded, StatusCode::TOO_MANY_REQUESTS),
        ];

        for (error, expected) in cases {
            assert_eq!(error.into_response().status(), expected);
        }

        let mapped: ApiError = ServerError::EmailTaken.into();
        assert_eq!(mapped.into_response().status(), StatusCode::CONFLICT);
    }

    #[test]
    fn remaining_api_errors_map_to_their_contract_statuses() {
        let cases = [
            (ApiError::Base64, StatusCode::BAD_REQUEST),
            (ApiError::Opaque, StatusCode::BAD_REQUEST),
            (ApiError::SessionError, StatusCode::INTERNAL_SERVER_ERROR),
            (ApiError::ServerError, StatusCode::INTERNAL_SERVER_ERROR),
            (ApiError::Forbidden, StatusCode::FORBIDDEN),
            (
                ApiError::InsufficientStorage,
                StatusCode::INSUFFICIENT_STORAGE,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.into_response().status(), expected);
        }
    }

    #[test]
    fn roles_parse_known_values_and_reject_unknown_values() {
        for (value, role) in [
            ("user", Role::User),
            ("premium", Role::Premium),
            ("admin", Role::Admin),
            ("anonymous", Role::Anonymous),
        ] {
            assert_eq!(Role::try_from(value), Ok(role));
        }
        assert_eq!(Role::try_from("unknown"), Err(()));
        assert_eq!(Role::Anonymous.to_string(), "anonymous");
    }

    #[test]
    fn authorization_accepts_valid_values_and_rejects_invalid_values() {
        let claims = test_claims();
        let limits = test_limits();

        assert!(claims
            .authorize_upload_at(TEST_TIME, limits, TEST_TIME, 1, 1, 1)
            .is_ok());
        for (creation_time, lifetime, file_size, downloads) in [
            (TEST_TIME + Duration::minutes(2), 1, 1, 1),
            (TEST_TIME, 0, 1, 1),
            (TEST_TIME, 1, 0, 1),
            (TEST_TIME, 1, 1, 4),
        ] {
            assert!(claims
                .authorize_upload_at(
                    TEST_TIME,
                    limits,
                    creation_time,
                    lifetime,
                    file_size,
                    downloads
                )
                .is_err());
        }
        assert!(claims.authorize_update_with_limits(limits, 7, 3).is_ok());
        assert!(claims.authorize_update_with_limits(limits, 8, 3).is_err());
    }

    #[test]
    fn file_size_validator_requires_a_positive_value_within_limit() {
        for size in [0, 101] {
            assert!(validate_file_size_with_limit(size, 100).is_err());
        }
        assert!(validate_file_size_with_limit(1, 100).is_ok());
    }

    #[test]
    fn optional_receiver_email_uses_email_validation_when_present() {
        assert!(validate_optional_email("receiver@example.com").is_ok());
        for email in [" ", "invalid"] {
            assert!(validate_optional_email(email).is_err(), "email: {email}");
        }
    }

    #[test]
    fn next_monthly_run_handles_the_december_boundary() {
        let december = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            cron::next_monthly_run(december),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn next_daily_run_returns_the_following_midnight() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 30, 0).unwrap();
        assert_eq!(
            cron::next_daily_run(now),
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn webhook_signatures_require_matching_body_secret_and_timestamp() {
        let _ = unsafe { libsodium_sys::sodium_init() };
        let secret = [7u8; 32];
        let timestamp = 1_700_000_000i64;
        let body = br#"{"type":"checkout.session.completed"}"#;
        let header = webhook_header(body, timestamp, &secret);

        assert!(payment::verify_webhook_signature_at(
            body, &header, &secret, timestamp
        ));
        assert!(!payment::verify_webhook_signature_at(
            body,
            &header,
            &secret,
            timestamp + 301
        ));
        assert!(!payment::verify_webhook_signature_at(
            br#"{"type":"tampered"}"#,
            &header,
            &secret,
            timestamp
        ));
        assert!(!payment::verify_webhook_signature_at(
            body,
            "t=not-a-timestamp,v1=00",
            &secret,
            timestamp
        ));
    }

    fn webhook_header(body: &[u8], timestamp: i64, secret: &[u8; 32]) -> String {
        let message = format!("{timestamp}.{}", String::from_utf8_lossy(body));
        let mut signature = [0u8; 32];
        let result = unsafe {
            libsodium_sys::crypto_auth_hmacsha256(
                signature.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u64,
                secret.as_ptr(),
            )
        };
        assert_eq!(result, 0);
        format!("t={timestamp},v1={}", hex::encode(signature))
    }

    proptest! {
        #[test]
        fn integer_validator_accepts_exactly_values_in_its_domain(value in any::<i32>()) {
            let expected = (0..=1000).contains(&value);
            prop_assert_eq!(validate_int_param(value).is_ok(), expected);
        }
    }
}
