use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::server;
use crate::api_handlers::misc::DbPool;
use crate::consts::*;
use crate::error::ServerError;

pub async fn create_subscription_checkout(
    user_id: Uuid,
    email: &str,
    plan: &str,
) -> Result<String, ServerError> {
    if plan != "premium" {
        return Err(ServerError::InputValidation);
    }

    let params: Vec<(String, String)> = vec![
        ("mode".into(), "subscription".into()),
        ("client_reference_id".into(), user_id.to_string()),
        ("customer_email".into(), email.to_string()),
        (
            "line_items[0][price]".into(),
            STRIPE_PRICE_ID_PREMIUM.get().unwrap().clone(),
        ),
        ("line_items[0][quantity]".into(), "1".into()),
        (
            "success_url".into(),
            format!(
                "{}/account?subscription=success",
                FRONTEND_URL.get().unwrap()
            ),
        ),
        (
            "cancel_url".into(),
            format!(
                "{}/pricing?subscription=cancelled",
                FRONTEND_URL.get().unwrap()
            ),
        ),
        (
            "subscription_data[metadata][user_id]".into(),
            user_id.to_string(),
        ),
    ];

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .bearer_auth(STRIPE_SECRET_KEY.get().unwrap())
        .form(&params)
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(
            "Stripe checkout session creation failed: {} — {}",
            status,
            body
        );
        return Err(ServerError::Internal);
    }

    let body: serde_json::Value = resp.json().await.map_err(|_| ServerError::Internal)?;
    body["url"]
        .as_str()
        .map(str::to_string)
        .ok_or(ServerError::Internal)
}

pub async fn cancel_subscription(sub_id: &str) -> Result<(), ServerError> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("https://api.stripe.com/v1/subscriptions/{sub_id}"))
        .bearer_auth(STRIPE_SECRET_KEY.get().unwrap())
        .form(&[("cancel_at_period_end", "true")])
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    if !resp.status().is_success() {
        return Err(ServerError::Internal);
    }

    Ok(())
}

/// Verifies `Stripe-Signature: t=<unix_ts>,v1=<hex hmac>`.
/// HMAC is computed over "{timestamp}.{raw_body}" with the webhook secret.
pub fn verify_webhook_signature(raw_body: &[u8], signature_header: &str) -> bool {
    let mut timestamp: Option<&str> = None;
    let mut v1: Option<&str> = None;

    for part in signature_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = Some(ts);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            v1 = Some(sig);
        }
    }

    let (Some(timestamp), Some(v1)) = (timestamp, v1) else {
        return false;
    };

    // Reject stale timestamps
    let Ok(ts) = timestamp.parse::<i64>() else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now = now.as_secs() as i64;
    if (now - ts).abs() > WEBHOOK_TIMESTAMP_TOLERANCE_SECS {
        return false;
    }

    // Decode the signature from hex
    let Ok(sig_bytes) = hex::decode(v1) else {
        return false;
    };
    if sig_bytes.len() != libsodium_sys::crypto_auth_hmacsha256_BYTES as usize {
        return false;
    }

    // Check the MAC
    let secret = STRIPE_WEBHOOK_SECRET.get().unwrap().as_bytes();
    let mut computed = [0u8; libsodium_sys::crypto_auth_hmacsha256_BYTES as usize];

    let hmac_ok = unsafe {
        let mut state = std::mem::MaybeUninit::<libsodium_sys::crypto_auth_hmacsha256_state>::uninit();
        if libsodium_sys::crypto_auth_hmacsha256_init(
            state.as_mut_ptr(),
            secret.as_ptr(),
            secret.len(),
        ) != 0 {
            return false;
        }
        let mut state = state.assume_init();

        libsodium_sys::crypto_auth_hmacsha256_update(
            &mut state,
            timestamp.as_ptr(),
            timestamp.len() as u64,
        );
        libsodium_sys::crypto_auth_hmacsha256_update(&mut state, b".".as_ptr(), 1);
        libsodium_sys::crypto_auth_hmacsha256_update(
            &mut state,
            raw_body.as_ptr(),
            raw_body.len() as u64,
        );

        if libsodium_sys::crypto_auth_hmacsha256_final(&mut state, computed.as_mut_ptr()) != 0 {
            return false;
        }

        // Check the MAC
        libsodium_sys::sodium_memcmp(
            computed.as_ptr() as *const _,
            sig_bytes.as_ptr() as *const _,
            computed.len(),
        ) == 0
    };

    hmac_ok
}

#[derive(Deserialize, Debug)]
pub struct StripeEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Deserialize, Debug)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

pub async fn handle_webhook(event: StripeEvent, pool: &DbPool) -> Result<(), ServerError> {
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            let obj = &event.data.object;
            let Some(user_id) = obj["client_reference_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                return Ok(());
            };
            let sub_id = obj["subscription"].as_str().map(str::to_string);
            let customer_id = obj["customer"].as_str().map(str::to_string);

            crate::server::connected::activate_subscription(
                user_id,
                "premium",
                sub_id,
                customer_id,
                pool,
            )?;
        }
        "customer.subscription.deleted" => {
            let Some(sub_id) = event.data.object["id"].as_str() else {
                return Ok(());
            };
            if let Some(user_id) =
                crate::server::connected::find_user_by_stripe_subscription_id(sub_id, pool)?
            {
                crate::server::connected::deactivate_subscription(user_id, pool)?;
            }
        }
        // e.g. failed renewal payment -> status becomes "past_due"/"unpaid"
        "customer.subscription.updated" => {
            let obj = &event.data.object;
            let status = obj["status"].as_str().unwrap_or("");
            if matches!(status, "canceled" | "unpaid" | "incomplete_expired") {
                if let Some(sub_id) = obj["id"].as_str() {
                    if let Some(user_id) =
                        crate::server::connected::find_user_by_stripe_subscription_id(sub_id, pool)?
                    {
                        crate::server::connected::deactivate_subscription(user_id, pool)?;
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}
