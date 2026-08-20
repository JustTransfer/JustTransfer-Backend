use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::api_handlers::auth::UserClaims;
use crate::api_handlers::misc::AppState;
use crate::error::ApiError;
use crate::server;

#[derive(Deserialize, Debug)]
pub struct CreateCheckout {
    plan: String, // "user" | "premium"
}

#[derive(Serialize)]
pub struct CreateCheckoutResult {
    checkout_url: String,
}

#[instrument(skip(state), fields(user_id = %claims_session.id), err(Debug))]
pub async fn create_subscription_checkout(
    Extension(claims_session): Extension<UserClaims>,
    State(state): State<AppState>,
    Json(payload): Json<CreateCheckout>,
) -> Result<impl IntoResponse, ApiError> {

    if payload.plan != "premium" {
        return Err(ApiError::InputValidation);
    }

    let checkout_url = server::payment::create_subscription_gateway(
        claims_session.id,
        &claims_session.email,
        &payload.plan,
    )
        .await?;

    Ok((StatusCode::OK, Json(CreateCheckoutResult { checkout_url })))
}

#[instrument(skip_all, err(Debug))]
pub async fn payrexx_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let signature = headers
        .get("X-Webhook-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Forbidden)?;

    if !server::payment::verify_webhook_signature(&body, signature) {
        return Err(ApiError::Forbidden);
    }

    let payload: server::payment::WebhookPayload =
        serde_json::from_slice(&body).map_err(|_| ApiError::InputValidation)?;

    server::payment::handle_webhook(payload, &state.db).await?;

    Ok(StatusCode::OK)
}