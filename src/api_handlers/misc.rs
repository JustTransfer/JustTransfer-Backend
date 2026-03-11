use aws_sdk_s3::Client;
use diesel::{r2d2, PgConnection};
use diesel::r2d2::ConnectionManager;
use validator::{ValidationError, Validate};
use crate::consts::{MAX_FILE_SIZE_ANONYMOUS, MAX_FILE_SIZE_CONNECTED, MAX_LENGTH_USERNAME, MAX_VALUE_INT, MAX_VALUE_INT_FILE_SIZE, MIN_LENGTH_USERNAME};

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub s3: Client,
    pub bucket_name: String,
    pub bucket_name_anonymous: String,
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
/// Validation functions for anonymous messages
///

pub fn validate_file_size_anonymous(size: i64) -> Result<(), ValidationError> {
    if size == 0 || size > MAX_FILE_SIZE_ANONYMOUS {
        return Err(ValidationError::new("invalid_file_size"));
    }
    Ok(())
}

///
/// Validation functions for connected messages
///

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    // Check length
    if username.len() < MIN_LENGTH_USERNAME || username.len() > MAX_LENGTH_USERNAME {
        return Err(ValidationError::new("invalid_length"));
    }

    // Allow only alphanumeric characters and underscores
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(ValidationError::new("invalid_characters"));
    }

    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    #[derive(Validate)]
    struct EmailValidation<'a> {
        #[validate(email)]
        email: &'a str,
    }

    let email_validation = EmailValidation { email };
    email_validation.validate().map_err(|_| ValidationError::new("invalid_email"))
}