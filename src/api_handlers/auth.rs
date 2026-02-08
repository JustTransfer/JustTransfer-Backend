use axum::{http::StatusCode, response::Response};
use serde::{Deserialize, Serialize};
use axum::extract::Request;
use axum::middleware::Next;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, errors::Error};

use crate::consts::*;
use crate::consts;
use crate::models::*;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    username: String, // username
    role: String, // user role
    exp: usize,  // expiration time as UNIX timestamp
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

fn verify_jwt(token: &str) -> Result<TokenData<Claims>, Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET_KEY.get().unwrap().as_ref()),
        &Validation::default(),
    )
}

pub async fn jwt_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
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
                        Ok(_) => Ok(next.run(req).await), // JWT is valid, proceed to next handler
                        Err(_) => Err(StatusCode::UNAUTHORIZED), // Invalid JWT
                    }
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED) // No Authorization header or invalid token
}