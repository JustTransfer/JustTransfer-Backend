use axum::{http::StatusCode, response::Response, RequestExt};
use serde::{Deserialize, Serialize};
use axum::extract::{Request, Path};
use axum::middleware::Next;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, errors::Error};

use crate::consts::*;
use crate::consts;
use crate::models::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub username: String, // username
    pub role: String, // user role
    pub exp: usize,  // expiration time as UNIX timestamp
}

pub fn create_jwt(user_id: &str, role: &str) -> Result<String, Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(JWT_DURATION_MINUTES))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        username: user_id.to_owned(),
        role: role.to_owned(),
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
}