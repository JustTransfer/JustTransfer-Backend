use axum::{http::StatusCode, response::Response, RequestExt};
use serde::{Deserialize, Serialize};
use axum::extract::{Request, Path};
use axum::middleware::Next;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer, cookie::time::Duration};

use chrono::Utc;
use uuid::Uuid;
use std::fmt;
use tracing::{info, instrument, warn};

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

pub fn get_session_layer() -> SessionManagerLayer<MemoryStore> {
    // In-memory session store
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(true)
        .with_expiry(Expiry::OnInactivity(Duration::hours(SESSION_DURATION_HOURS)));

    session_layer
}

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

// Check if the iat of the session is recent
pub async  fn require_fresh_login(
    session: Session,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {

    if session.get::<String>(AUTH_KEY).await.unwrap_or(None).is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let created_at: Option<i64> = session.get(AUTH_KEY_CREATED_AT).await.unwrap_or(None);

    if let Some(ts) = created_at {
        let now = Utc::now().timestamp();

        if (now - ts).abs() > (FRESH_SESSION_DURATION_MINUTES * 60) {
            warn!("Session is not fresh: created at {}, now is {}, difference is {} seconds", ts, now, (now - ts).abs());
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}