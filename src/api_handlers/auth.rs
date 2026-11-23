use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::middleware::Next;
use axum::{http::StatusCode, response::Response};
use serde::{Deserialize, Serialize};
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};

use chrono::Utc;
use std::fmt;
use tracing::warn;
use uuid::Uuid;

use crate::api_handlers::misc::AppState;
use crate::consts::*;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleLimits {
    pub max_lifetime: i64,
    pub max_file_size: i64,
    pub max_downloads: i64,
}

impl Role {
    pub fn max_lifetime(&self) -> i64 {
        match self {
            Role::User => *MAX_LIFETIME_CONNECTED.get().unwrap(),
            Role::Premium => *MAX_LIFETIME_CONNECTED_PREMIUM.get().unwrap(),
            Role::Admin => *MAX_LIFETIME_CONNECTED_PREMIUM.get().unwrap(),
            Role::Anonymous => *MAX_LIFETIME_ANONYMOUS.get().unwrap(),
        }
    }

    pub fn max_file_size(&self) -> i64 {
        match self {
            Role::User => *MAX_FILE_SIZE_CONNECTED.get().unwrap(),
            Role::Premium => *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap(),
            Role::Admin => *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap(),
            Role::Anonymous => *MAX_FILE_SIZE_ANONYMOUS.get().unwrap(),
        }
    }

    pub fn max_downloads(&self) -> i64 {
        match self {
            Role::User => *MAX_DOWNLOADS_CONNECTED.get().unwrap(),
            Role::Premium => *MAX_DOWNLOADS_CONNECTED_PREMIUM.get().unwrap(),
            Role::Admin => *MAX_DOWNLOADS_CONNECTED_PREMIUM.get().unwrap(),
            Role::Anonymous => *MAX_DOWNLOADS_ANONYMOUS.get().unwrap(),
        }
    }

    pub fn max_messages(&self) -> Option<i64> {
        match self {
            Role::User => Some(*MAX_NUMBER_CONNECTED_TRANSFERS_MONTH.get().unwrap()),
            Role::Premium => Some(*MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH.get().unwrap()),
            Role::Admin => Some(*MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH.get().unwrap()),
            Role::Anonymous => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserClaims {
    pub id: Uuid,
    pub email: String,
    pub role: Role,
    pub iat: i64, // Issued at timestamp
}

impl UserClaims {
    pub fn authorize_upload_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limits: RoleLimits,
        creation_time: chrono::DateTime<chrono::Utc>,
        lifetime: i64,
        file_size: i64,
        max_downloads: i64,
    ) -> Result<(), ApiError> {
        if creation_time > now + chrono::Duration::minutes(MAX_TIME_MARGIN)
            || creation_time < now - chrono::Duration::minutes(MAX_TIME_MARGIN)
            || lifetime < 1
            || lifetime > limits.max_lifetime
            || file_size < 1
            || file_size > limits.max_file_size
            || max_downloads < 1
            || max_downloads > limits.max_downloads
        {
            return Err(ApiError::Forbidden);
        }
        Ok(())
    }

    pub fn authorize_upload(
        &self,
        creation_time: chrono::DateTime<chrono::Utc>,
        lifetime: i64,
        file_size: i64,
        max_downloads: i64,
    ) -> Result<(), ApiError> {
        self.authorize_upload_at(
            Utc::now(),
            RoleLimits {
                max_lifetime: self.role.max_lifetime(),
                max_file_size: self.role.max_file_size(),
                max_downloads: self.role.max_downloads(),
            },
            creation_time,
            lifetime,
            file_size,
            max_downloads,
        )
    }

    pub fn authorize_update(&self, lifetime: i64, max_downloads: i64) -> Result<(), ApiError> {
        self.authorize_update_with_limits(
            RoleLimits {
                max_lifetime: self.role.max_lifetime(),
                max_file_size: self.role.max_file_size(),
                max_downloads: self.role.max_downloads(),
            },
            lifetime,
            max_downloads,
        )
    }

    pub fn authorize_update_with_limits(
        &self,
        limits: RoleLimits,
        lifetime: i64,
        max_downloads: i64,
    ) -> Result<(), ApiError> {
        // Lifetime
        if lifetime < 1 || lifetime > limits.max_lifetime {
            return Err(ApiError::Forbidden);
        }

        // Max downloads
        if max_downloads < 1 || max_downloads > limits.max_downloads {
            return Err(ApiError::Forbidden);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LinkClaims {
    pub id: Uuid,
}

pub fn get_session_layer(cookie_name: &'static str) -> SessionManagerLayer<MemoryStore> {
    // In-memory session store
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name(cookie_name)
        .with_secure(true)
        .with_expiry(Expiry::OnInactivity(Duration::minutes(
            *SESSION_DURATION_MINUTES.get().unwrap(),
        )));

    session_layer
}

// Rebuilds the claims of an account session from the database.
// Role and email are read from database, so a downgrade takes effect immediately
// Returns `Ok(None)` when the session is not, or no longer, a valid account session.
async fn load_session_claims(
    session: &Session,
    state: &AppState,
) -> Result<Option<UserClaims>, StatusCode> {
    // Load the user ID, creation timestamp, and session version from the session
    let (user_id, created_at, version) = match (
        session
            .get::<Uuid>(AUTH_KEY_USER_ID)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        session
            .get::<i64>(AUTH_KEY_CREATED_AT)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        session
            .get::<i64>(AUTH_KEY_SESSION_VERSION)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    ) {
        (Some(user_id), Some(created_at), Some(version)) => (user_id, created_at, version),
        _ => return Ok(None),
    };

    let user = crate::server::connected::get_session_user(user_id, &state.db)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Check that the session is still valid: the version must match and the session must not be too old
    let valid = match &user {
        Some(user) => {
            user.session_version == version
                && Utc::now().timestamp() - created_at <= MAX_SESSION_LIFETIME_DAYS * 24 * 60 * 60
        }
        None => false,
    };

    if !valid {
        // Drop the stale account data, keeping any link transfer authorization
        for key in [
            AUTH_KEY_USER_ID,
            AUTH_KEY_CREATED_AT,
            AUTH_KEY_SESSION_VERSION,
        ] {
            session
                .remove_value(key)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        return Ok(None);
    }

    let user = user.unwrap();
    Ok(Some(UserClaims {
        id: user_id,
        email: user.email,
        role: Role::try_from(user.role.as_str()).unwrap_or(Role::User),
        iat: created_at,
    }))
}

pub async fn require_auth(
    State(state): State<AppState>,
    session: Session,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let claims = load_session_claims(&session, &state)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Extend the request with the user's role and email for later use in handlers
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

// Link transfers the session is logged in to, with the session version of each transfer at login time
type LinkSessions = HashMap<Uuid, i64>;

async fn get_link_sessions(session: &Session) -> Result<LinkSessions, ApiError> {
    Ok(session
        .get::<LinkSessions>(AUTH_KEY_LINK)
        .await
        .map_err(|_| ApiError::ServerError)?
        .unwrap_or_default())
}

/// Authorize the session for the link transfer `id`, logged in at `session_version`.
pub async fn authorize_link_session(
    session: &Session,
    id: Uuid,
    session_version: i64,
) -> Result<(), ApiError> {
    let mut sessions = get_link_sessions(session).await?;
    sessions.insert(id, session_version);
    session
        .insert(AUTH_KEY_LINK, sessions)
        .await
        .map_err(|_| ApiError::ServerError)
}

/// Remove the authorization of the session for the link transfer `id`.
async fn revoke_link_session(session: &Session, id: Uuid) -> Result<(), ApiError> {
    let mut sessions = get_link_sessions(session).await?;
    if sessions.remove(&id).is_some() {
        session
            .insert(AUTH_KEY_LINK, sessions)
            .await
            .map_err(|_| ApiError::ServerError)?;
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct LinkAuthParam {
    id: Uuid,
}
pub async fn require_auth_link(
    State(state): State<AppState>,
    Path(params): Path<LinkAuthParam>,
    session: Session,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let sessions = get_link_sessions(&session)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(&version) = sessions.get(&params.id) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // The session is only valid while the transfer exists and its password has
    // not changed since the login
    let current = crate::server::link::get_link_session_version(params.id, &state.db)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if current != Some(version) {
        revoke_link_session(&session, params.id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extend the request with the anonymous message ID for later use in handlers
    req.extensions_mut().insert(LinkClaims { id: params.id });

    Ok(next.run(req).await)
}

pub async fn optional_auth(
    State(state): State<AppState>,
    session: Session,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(claims) = load_session_claims(&session, &state).await? {
        req.extensions_mut().insert(claims);
    }

    Ok(next.run(req).await)
}

// Check if the iat of the session is recent
pub async fn require_fresh_login(
    session: Session,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check if the user is connected
    let _user_id = session
        .get::<Uuid>(AUTH_KEY_USER_ID)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let created_at: Option<i64> = session.get(AUTH_KEY_CREATED_AT).await.unwrap_or(None);

    if let Some(ts) = created_at {
        let now = Utc::now().timestamp();

        if (now - ts).abs() > (FRESH_SESSION_DURATION_MINUTES.get().unwrap() * 60) {
            warn!(
                "Session is not fresh: created at {}, now is {}, difference is {} seconds",
                ts,
                now,
                (now - ts).abs()
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::*;
    use chrono::{DateTime, Duration as ChronoDuration};

    const ROLES: [(&str, Role); 4] = [
        ("user", Role::User),
        ("premium", Role::Premium),
        ("admin", Role::Admin),
        ("anonymous", Role::Anonymous),
    ];

    const LIMITS: RoleLimits = RoleLimits {
        max_lifetime: 7,
        max_file_size: 100,
        max_downloads: 3,
    };

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_767_276_000, 0).unwrap()
    }

    fn claims(role: Role) -> UserClaims {
        UserClaims {
            id: Uuid::nil(),
            email: "test@example.com".to_owned(),
            role,
            iat: 0,
        }
    }

    fn upload(created: DateTime<Utc>, lifetime: i64, size: i64, downloads: i64) -> bool {
        claims(Role::User)
            .authorize_upload_at(now(), LIMITS, created, lifetime, size, downloads)
            .is_ok()
    }

    #[test]
    fn role_round_trips_through_its_string_form() {
        for (name, role) in ROLES {
            assert_eq!(Role::try_from(name), Ok(role.clone()));
            assert_eq!(role.to_string(), name);
            // The session stores the Display form and serde must agree with it.
            assert_eq!(serde_json::to_value(&role).unwrap(), name);
        }
        for unknown in ["", "User", "superuser", "test"] {
            assert_eq!(Role::try_from(unknown), Err(()), "{unknown:?}");
        }
    }

    #[test]
    fn role_limits_come_from_the_matching_configuration() {
        init_config();
        let expected = [
            (
                Role::Anonymous,
                (
                    ANON_MAX_LIFETIME,
                    ANON_MAX_FILE_SIZE,
                    ANON_MAX_DOWNLOADS,
                    None,
                ),
            ),
            (
                Role::User,
                (
                    USER_MAX_LIFETIME,
                    USER_MAX_FILE_SIZE,
                    USER_MAX_DOWNLOADS,
                    Some(USER_MONTHLY_TRANSFERS),
                ),
            ),
            (
                Role::Premium,
                (
                    PREMIUM_MAX_LIFETIME,
                    PREMIUM_MAX_FILE_SIZE,
                    PREMIUM_MAX_DOWNLOADS,
                    Some(PREMIUM_MONTHLY_TRANSFERS),
                ),
            ),
            (
                Role::Admin,
                (
                    PREMIUM_MAX_LIFETIME,
                    PREMIUM_MAX_FILE_SIZE,
                    PREMIUM_MAX_DOWNLOADS,
                    Some(PREMIUM_MONTHLY_TRANSFERS),
                ),
            ),
        ];
        for (role, limits) in expected {
            let actual = (
                role.max_lifetime(),
                role.max_file_size(),
                role.max_downloads(),
                role.max_messages(),
            );
            assert_eq!(actual, limits, "{role}");
        }
    }

    #[test]
    fn upload_accepts_values_on_the_limits() {
        let margin = ChronoDuration::minutes(MAX_TIME_MARGIN);
        assert!(upload(now(), 1, 1, 1));
        assert!(upload(
            now(),
            LIMITS.max_lifetime,
            LIMITS.max_file_size,
            LIMITS.max_downloads
        ));
        assert!(upload(now() - margin, 1, 1, 1));
        assert!(upload(now() + margin, 1, 1, 1));
    }

    #[test]
    fn upload_rejects_each_value_just_outside_the_limits() {
        let past_margin = ChronoDuration::minutes(MAX_TIME_MARGIN) + ChronoDuration::seconds(1);
        let cases = [
            ("clock ahead", now() + past_margin, 1, 1, 1),
            ("clock behind", now() - past_margin, 1, 1, 1),
            ("lifetime 0", now(), 0, 1, 1),
            ("lifetime over", now(), LIMITS.max_lifetime + 1, 1, 1),
            ("size 0", now(), 1, 0, 1),
            ("size over", now(), 1, LIMITS.max_file_size + 1, 1),
            ("downloads 0", now(), 1, 1, 0),
            ("downloads over", now(), 1, 1, LIMITS.max_downloads + 1),
        ];
        for (name, created, lifetime, size, downloads) in cases {
            assert!(!upload(created, lifetime, size, downloads), "{name}");
        }
    }

    #[test]
    fn update_enforces_lifetime_and_download_limits() {
        let user = claims(Role::User);
        let ok = |lifetime, downloads| {
            user.authorize_update_with_limits(LIMITS, lifetime, downloads)
                .is_ok()
        };
        assert!(ok(1, 1));
        assert!(ok(LIMITS.max_lifetime, LIMITS.max_downloads));
        assert!(!ok(0, 1));
        assert!(!ok(LIMITS.max_lifetime + 1, 1));
        assert!(!ok(1, 0));
        assert!(!ok(1, LIMITS.max_downloads + 1));
    }

    #[test]
    fn upload_and_update_apply_the_callers_role_limits() {
        init_config();
        let created = Utc::now();
        let anonymous = claims(Role::Anonymous);
        let premium = claims(Role::Premium);

        assert!(anonymous
            .authorize_upload(created, ANON_MAX_LIFETIME, ANON_MAX_FILE_SIZE, 1)
            .is_ok());
        assert!(anonymous
            .authorize_upload(created, 1, ANON_MAX_FILE_SIZE + 1, 1)
            .is_err());
        assert!(premium
            .authorize_upload(created, 1, ANON_MAX_FILE_SIZE + 1, 1)
            .is_ok());

        assert!(claims(Role::User)
            .authorize_update(USER_MAX_LIFETIME, 1)
            .is_ok());
        assert!(claims(Role::User)
            .authorize_update(USER_MAX_LIFETIME + 1, 1)
            .is_err());
        assert!(premium.authorize_update(USER_MAX_LIFETIME + 1, 1).is_ok());
    }
}
