use crate::consts::{MAX_FILE_SIZE_CONNECTED_PREMIUM, MAX_VALUE_INT, MAX_VALUE_INT_FILE_SIZE};
use aws_sdk_s3::Client;
use diesel::r2d2::ConnectionManager;
use diesel::{r2d2, PgConnection};
use validator::{Validate, ValidationError};

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub s3: Client,
    pub bucket_name: String,
    pub mailer: lettre::SmtpTransport,
}

///
/// General validation functions
///

pub fn validate_int_param(value: i32) -> Result<(), ValidationError> {
    if value < 0 {
        return Err(ValidationError::new("invalid_value"));
    }

    if value > MAX_VALUE_INT {
        return Err(ValidationError::new("value_too_large"));
    }

    Ok(())
}

pub fn validate_int_param_64(value: i64) -> Result<(), ValidationError> {
    if value < 0 {
        return Err(ValidationError::new("invalid_value"));
    }

    if value > MAX_VALUE_INT_FILE_SIZE as i64 {
        return Err(ValidationError::new("value_too_large"));
    }

    Ok(())
}

///
/// Validation functions for messages (already enforced by the API)
///

pub fn validate_file_size(size: i64) -> Result<(), ValidationError> {
    let max_size = *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap();
    validate_file_size_with_limit(size, max_size)
}

pub fn validate_file_size_with_limit(size: i64, max_size: i64) -> Result<(), ValidationError> {
    if size <= 0 || size > max_size {
        return Err(ValidationError::new("invalid_file_size"));
    }
    Ok(())
}

///
/// Validation functions for connected messages
///

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    #[derive(Validate)]
    struct EmailValidation<'a> {
        #[validate(email)]
        email: &'a str,
    }

    let email_validation = EmailValidation { email };
    email_validation
        .validate()
        .map_err(|_| ValidationError::new("invalid_email"))
}

pub fn validate_optional_email(email: &str) -> Result<(), ValidationError> {
    if email.trim().is_empty() {
        return Err(ValidationError::new("invalid_email"));
    }

    validate_email(email)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn email_validation() {
        for email in ["test@example.com", "user+tag@example.co.uk"] {
            assert!(validate_email(email).is_ok(), "{email}");
        }
        for email in ["not-an-email", "", "@example.com", "user@"] {
            assert!(validate_email(email).is_err(), "{email}");
        }
    }

    #[test]
    fn optional_email_rejects_blank_and_invalid_values() {
        assert!(validate_optional_email("receiver@example.com").is_ok());
        for email in ["", "   ", "invalid"] {
            assert!(validate_optional_email(email).is_err(), "{email:?}");
        }
    }

    #[test]
    fn file_size_must_be_positive_and_within_limit() {
        assert!(validate_file_size_with_limit(1, 100).is_ok());
        assert!(validate_file_size_with_limit(100, 100).is_ok());
        for size in [i64::MIN, -1, 0, 101] {
            assert!(validate_file_size_with_limit(size, 100).is_err(), "{size}");
        }
    }

    #[test]
    fn file_size_uses_the_premium_limit() {
        crate::tests::support::init_config();
        let max = *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap();
        assert!(validate_file_size(max).is_ok());
        assert!(validate_file_size(max + 1).is_err());
    }

    proptest! {
        #[test]
        fn int_param_accepts_exactly_0_to_max(value in any::<i32>()) {
            let expected = (0..=MAX_VALUE_INT).contains(&value);
            prop_assert_eq!(validate_int_param(value).is_ok(), expected);
        }

        #[test]
        fn int_param_64_accepts_exactly_0_to_max(value in prop_oneof![
            any::<i64>(),
            (MAX_VALUE_INT_FILE_SIZE - 2)..=(MAX_VALUE_INT_FILE_SIZE + 2),
            -2i64..=2,
        ]) {
            let expected = (0..=MAX_VALUE_INT_FILE_SIZE).contains(&value);
            prop_assert_eq!(validate_int_param_64(value).is_ok(), expected);
        }
    }
}
