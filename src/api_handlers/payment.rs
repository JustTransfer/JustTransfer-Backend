use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::api_handlers::auth::UserClaims;
use crate::api_handlers::misc::AppState;
use crate::error::ApiError;
use crate::server;

#[derive(Deserialize, Debug)]
pub struct CreateCheckout {
    plan: String,
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
    let checkout_url = server::payment::create_subscription_checkout(
        claims_session.id,
        &claims_session.email,
        &payload.plan,
    ).await?;

    Ok((StatusCode::OK, Json(CreateCheckoutResult { checkout_url })))
}

#[instrument(skip(state), fields(user_id = %claims_session.id), err(Debug))]
pub async fn cancel_subscription(
    Extension(claims_session): Extension<UserClaims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(sub_id) = server::connected::get_stripe_subscription_id(claims_session.id, &state.db)? else {
        return Err(ApiError::InputValidation); // nothing to cancel
    };

    server::payment::cancel_subscription(&sub_id).await?;
    // role flips back to "user" once Stripe's customer.subscription.deleted webhook lands
    Ok(StatusCode::OK)
}

#[instrument(skip_all, err(Debug))]
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let signature = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Forbidden)?;

    if !server::payment::verify_webhook_signature(&body, signature) {
        return Err(ApiError::Forbidden);
    }

    let event: server::payment::StripeEvent =
        serde_json::from_slice(&body).map_err(|_| ApiError::InputValidation)?;

    server::payment::handle_webhook(event, &state.db).await?;

    Ok(StatusCode::OK)
}