#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
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

    #[tokio::test]
    async fn should_reject_authenticated_route_without_session() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/user")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn should_reject_short_registration_payload_at_http_boundary() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/register/start")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client_registration_start":"short"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn should_validate_integer_boundaries() {
        assert!(validate_int_param(0).is_ok());
        assert!(validate_int_param(-1).is_err());
        assert!(validate_int_param(1001).is_err());
        assert!(validate_int_param_64(0).is_ok());
        assert!(validate_int_param_64(-1).is_err());
    }

    #[test]
    fn should_validate_email_and_reject_invalid_values() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("").is_err());
    }

    #[test]
    fn should_map_api_errors_to_http_statuses() {
        assert_eq!(
            ApiError::InputValidation.into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Unauthorized.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::ServerNotFound.into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::QuotaExceeded.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let mapped: ApiError = ServerError::EmailTaken.into();
        assert_eq!(mapped.into_response().status(), StatusCode::CONFLICT);
    }

    #[test]
    fn should_map_every_api_error_to_its_contract_status() {
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
    fn should_parse_supported_roles_and_reject_unknown_roles() {
        assert_eq!(Role::try_from("premium"), Ok(Role::Premium));
        assert_eq!(Role::try_from("unknown"), Err(()));
        assert_eq!(Role::Anonymous.to_string(), "anonymous");
    }

    #[test]
    fn should_authorize_upload_when_values_are_within_limits() {
        let claims = UserClaims {
            id: Uuid::nil(),
            email: "test@example.com".to_owned(),
            role: Role::Anonymous,
            iat: 0,
        };
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let limits = RoleLimits {
            max_lifetime: 7,
            max_file_size: 100,
            max_downloads: 3,
        };

        assert!(claims
            .authorize_upload_at(now, limits, now, 1, 1, 1)
            .is_ok());
        assert!(claims
            .authorize_upload_at(now, limits, now + Duration::minutes(2), 1, 1, 1)
            .is_err());
        assert!(claims
            .authorize_upload_at(now, limits, now, 0, 1, 1)
            .is_err());
        assert!(claims
            .authorize_upload_at(now, limits, now, 1, 0, 1)
            .is_err());
        assert!(claims
            .authorize_upload_at(now, limits, now, 1, 1, 4)
            .is_err());
        assert!(claims.authorize_update_with_limits(limits, 7, 3).is_ok());
        assert!(claims.authorize_update_with_limits(limits, 8, 3).is_err());
    }

    #[test]
    fn should_reject_zero_file_size() {
        assert!(validate_file_size_with_limit(0, 100).is_err());
        assert!(validate_file_size_with_limit(101, 100).is_err());
        assert!(validate_file_size_with_limit(1, 100).is_ok());
    }

    #[test]
    fn should_validate_optional_receiver_email() {
        assert!(validate_optional_email("receiver@example.com").is_ok());
        assert!(validate_optional_email(" ").is_err());
        assert!(validate_optional_email("invalid").is_err());
    }

    #[test]
    fn should_calculate_next_month_boundary() {
        let december = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            cron::next_monthly_run(december),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn should_calculate_next_daily_midnight() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 30, 0).unwrap();
        assert_eq!(
            cron::next_daily_run(now),
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn should_accept_only_valid_stripe_signatures() {
        let _ = unsafe { libsodium_sys::sodium_init() };
        let secret = [7u8; 32];
        let timestamp = 1_700_000_000i64;
        let body = br#"{"type":"checkout.session.completed"}"#;
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
        let header = format!("t={timestamp},v1={}", hex::encode(signature));

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

    proptest! {
        #[test]
        fn should_accept_only_nonnegative_integers_within_limit(value in any::<i32>()) {
            let expected = (0..=1000).contains(&value);
            prop_assert_eq!(validate_int_param(value).is_ok(), expected);
        }
    }
}
