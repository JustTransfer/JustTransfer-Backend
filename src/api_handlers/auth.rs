use axum::{http::StatusCode, response::Response, RequestExt};
use serde::{Deserialize, Serialize};
use axum::extract::{Request, Path};
use axum::middleware::Next;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer, cookie::time::Duration};

use chrono::Utc;
// use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, errors::Error};
use uuid::Uuid;
use std::fmt;
use tracing::{info, instrument};

use crate::consts::*;
use crate::{api_handlers, consts};
use crate::api_handlers::auth;
use crate::models::*;
use crate::error::*;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Premium,
    Admin,
    Anonymous,
}

impl TryFrom<&str> for Role {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "user" => Ok(Role::User),
            "premium" => Ok(Role::Premium),
            "admin" => Ok(Role::Admin),
            "anonymous" => Ok(Role::Anonymous),
            _ => Err(()),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Role::User => "user",
            Role::Premium => "premium",
            Role::Admin => "admin",
            Role::Anonymous => "anonymous",
        };
        write!(f, "{s}")
    }
}

impl Role {
    pub fn max_lifetime(&self) -> i32 {
        match self {
            Role::User => MAX_LIFETIME_CONNECTED,
            Role::Premium => MAX_LIFETIME_CONNECTED_PREMIUM,
            Role::Admin => MAX_LIFETIME_CONNECTED_PREMIUM,
            Role::Anonymous => MAX_LIFETIME_ANONYMOUS,
        }
    }

    pub fn max_file_size(&self) -> i64 {
        match self {
            Role::User => MAX_FILE_SIZE_CONNECTED,
            Role::Premium => MAX_FILE_SIZE_CONNECTED_PREMIUM,
            Role::Admin => MAX_FILE_SIZE_CONNECTED_PREMIUM,
            Role::Anonymous => MAX_FILE_SIZE_ANONYMOUS,
        }
    }

    pub fn max_downloads(&self) -> i32 {
        match self {
            Role::User => MAX_DOWNLOADS_CONNECTED,
            Role::Premium => MAX_DOWNLOADS_CONNECTED_PREMIUM,
            Role::Admin => MAX_DOWNLOADS_CONNECTED_PREMIUM,
            Role::Anonymous => MAX_DOWNLOADS_ANONYMOUS,
        }
    }

    pub fn max_messages(&self) -> Option<i64> {
        match self {
            Role::User => Some(MAX_NUMBER_CONNECTED_TRANSFERS_MONTH),
            Role::Premium => Some(MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH),
            Role::Admin => Some(MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH),
            Role::Anonymous => Some(MAX_NUMBER_ANONYMOUS_TRANSFERS_TOT),
        }
    }
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub username: String,
    pub role: Role,
    pub iat: usize, // issued at, as a timestamp in seconds since the epoch
}

impl Claims {
    pub fn authorize_upload(&self, creation_time: chrono::DateTime<chrono::Utc>, lifetime: i32, file_size: i64, max_downloads: i32) -> Result<(), ApiError> {
        
        // Creation time
        let now = Utc::now();
        if creation_time > now + chrono::Duration::minutes(MAX_TIME_MARGIN) || creation_time < now - chrono::Duration::minutes(MAX_TIME_MARGIN) {
            return Err(ApiError::Forbidden);
        }
        
        // Lifetime
        if lifetime < 1 || lifetime > self.role.max_lifetime() {
            return Err(ApiError::Forbidden);
        }

        // File size
        if file_size > self.role.max_file_size() {
            return Err(ApiError::Forbidden);
        }

        // Max downloads
        if max_downloads < 1 || max_downloads > self.role.max_downloads() {
            return Err(ApiError::Forbidden);
        }

        Ok(())
    }
}

// TODO use persistent store
pub fn get_session_layer() -> SessionManagerLayer<MemoryStore> {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_expiry(Expiry::OnInactivity(Duration::hours(SESSION_DURATION_HOURS)));

    session_layer
}

#[instrument(skip(session, req, next))]
pub async fn require_auth(
    session: Session,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if session.get::<String>(AUTH_KEY).await.unwrap_or(None).is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extend the request with the user's role and username for later use in handlers
    if let Some(username) = session.get::<String>(AUTH_KEY).await.unwrap_or(None) {
        let role = session.get::<String>(AUTH_KEY_ROLE).await.unwrap_or(None).unwrap_or("user".to_string());
        let created_at_str = session.get::<String>(AUTH_KEY_CREATED_AT).await.unwrap_or(None).unwrap_or("0".to_string());
        let created_at = created_at_str.parse::<usize>().unwrap_or(0);

        req.extensions_mut().insert(Claims {
            username,
            role: Role::try_from(role.as_str()).unwrap_or(Role::User),
            iat: created_at,
        });
    }

    Ok(next.run(req).await)
}

#[instrument(skip(session, req, next))]
pub async  fn require_auth_anonymous(
    session: Session,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if session.get::<String>(AUTH_KEY_ANONYMOUS).await.unwrap_or(None).is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extend the request with the anonymous message ID for later use in handlers
    if let Some(message_id) = session.get::<String>(AUTH_KEY_ANONYMOUS).await.unwrap_or(None) {

        req.extensions_mut().insert(Claims {
            username: message_id,
            role: Role::Anonymous,
            iat: 0,
        });
    }

    Ok(next.run(req).await)
}

/*pub fn create_anonymous_cookie (message_id: &Uuid) -> Result<CookieJar, ApiError> {

    let token = create_jwt(&*message_id.to_string(), auth::Role::Anonymous)
        .map_err(|_| ApiError::JWTError)?;

    let cookie_name = format!("{}_{}", AUTH_HEADER_ANONYMOUS, message_id);
    let cookie = Cookie::build((cookie_name, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .finish();

    let jar = CookieJar::new().add(cookie);

    Ok(jar)
}

pub fn create_connected_cookie (username: &String, role: Role) -> Result<CookieJar, ApiError> {

    let token = create_jwt(&username, role)
        .map_err(|_| ApiError::JWTError)?;

    // Create cookie (HttpOnly, Secure for production)
    let cookie = Cookie::build((AUTH_HEADER, token.clone()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .finish();

    let jar = CookieJar::new().add(cookie);

    Ok(jar)
}

pub fn create_jwt(user_id: &str, role: Role) -> Result<String, Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(JWT_DURATION_MINUTES))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        username: user_id.to_owned(),
        role: role,
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET_KEY.get().unwrap().as_ref()),
    )
}

pub fn verify_jwt(token: &str) -> Result<TokenData<Claims>, Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET_KEY.get().unwrap().as_ref()),
        &Validation::default(),
    )
}

pub async fn jwt_auth_connected(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    // Get the Cookie
    let headers = req.headers();
    if let Some(cookie_header) = headers.get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Look for the jwt_token cookie
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();

                if let Some(token) = cookie.strip_prefix(AUTH_HEADER) {
                    let token = token.trim_start_matches('=').trim();

                    return match verify_jwt(token) {
                        Ok(token_data) => {
                            // Add claims to request extensions if needed
                            req.extensions_mut().insert(token_data.claims);

                            // Proceed to the next middleware or handler
                            return Ok(next.run(req).await);
                        }
                        Err(_) => Err(StatusCode::UNAUTHORIZED), // Invalid JWT
                    };
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED) // No Authorization header or invalid token
}

pub async fn jwt_auth_anonymous(mut req: Request, next: Next) -> Result<Response, StatusCode> {

    let Path(id): Path<String> = req.extract_parts().await.map_err(|_| StatusCode::BAD_REQUEST)?;

    let expected_cookie_name = format!("{}_{}", AUTH_HEADER_ANONYMOUS, id);

    // Get the Cookie
    let headers = req.headers();
    if let Some(cookie_header) = headers.get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Look for the jwt_token cookie
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();

                // Check if the cookie name matches the expected format for anonymous tokens
                if let Some(token) = cookie.strip_prefix(&expected_cookie_name) {
                    let token = token.trim_start_matches('=').trim();

                    return match verify_jwt(token) {
                        Ok(token_data) => {
                            // Add claims to request extensions if needed
                            req.extensions_mut().insert(token_data.claims);

                            // Proceed to the next middleware or handler
                            return Ok(next.run(req).await);
                        },
                        Err(_) => Err(StatusCode::UNAUTHORIZED), // Invalid JWT
                    }
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED) // No Authorization header or invalid token
}*/