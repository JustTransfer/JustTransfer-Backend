use aws_sdk_s3::Client;
use diesel::{r2d2, PgConnection};
use diesel::r2d2::ConnectionManager;
use validator::{ValidationError, Validate};
use crate::consts::{MAX_FILE_SIZE_CONNECTED_PREMIUM, MAX_VALUE_INT, MAX_VALUE_INT_FILE_SIZE};

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
/// Validation functions for messages
///

pub fn validate_file_size(size: i64) -> Result<(), ValidationError> {
    if size == 0 || size > *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap() {
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
    email_validation.validate().map_err(|_| ValidationError::new("invalid_email"))
}

pub fn validate_optional_email(email: &str) -> Result<(), ValidationError> {
    if email.trim().is_empty() {
        return Err(ValidationError::new("invalid_email"));
    }

    validate_email(email)
}