use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::api_handlers::misc::DbPool;
use crate::consts::*;
use crate::error::ServerError;
use crate::server;

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
        ("allow_promotion_codes".into(), "true".into()),
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

pub async fn cancel_subscription(
    user_id: Uuid,
    sub_id: &str,
    pool: &DbPool,
    mailer: &lettre::SmtpTransport,
) -> Result<(), ServerError> {
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

    let body = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|_| ServerError::Internal)?;

    let current_period_end = body
        .get("items")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("current_period_end"))
        .and_then(|v| v.as_i64())
        .ok_or(ServerError::Internal)?;

    // convert to chrono::DateTime<chrono::Utc>
    let end_time_utc = chrono::DateTime::<chrono::Utc>::from_timestamp(current_period_end, 0)
        .ok_or(ServerError::Internal)?;

    server::connected::update_subscription_end(user_id, end_time_utc, pool, mailer)?;

    Ok(())
}

/// Verifies `Stripe-Signature: t=<unix_ts>,v1=<hex hmac>`.
/// HMAC is computed over "{timestamp}.{raw_body}" with the webhook secret.
pub fn verify_webhook_signature(raw_body: &[u8], signature_header: &str) -> bool {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    verify_webhook_signature_at(
        raw_body,
        signature_header,
        STRIPE_WEBHOOK_SECRET.get().unwrap().as_bytes(),
        now.as_secs() as i64,
    )
}

pub fn verify_webhook_signature_at(
    raw_body: &[u8],
    signature_header: &str,
    secret: &[u8],
    now: i64,
) -> bool {
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
    let mut computed = [0u8; libsodium_sys::crypto_auth_hmacsha256_BYTES as usize];

    let hmac_ok = unsafe {
        let mut state =
            std::mem::MaybeUninit::<libsodium_sys::crypto_auth_hmacsha256_state>::uninit();
        if libsodium_sys::crypto_auth_hmacsha256_init(
            state.as_mut_ptr(),
            secret.as_ptr(),
            secret.len(),
        ) != 0
        {
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

pub async fn handle_webhook(
    event: StripeEvent,
    pool: &DbPool,
    mailer: &lettre::SmtpTransport,
) -> Result<(), ServerError> {
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

            server::connected::activate_subscription(
                user_id,
                "premium",
                sub_id,
                customer_id,
                pool,
                mailer,
            )?;
        }
        "customer.subscription.deleted" => {
            let Some(sub_id) = event.data.object["id"].as_str() else {
                return Ok(());
            };
            if let Some(user_id) =
                server::connected::find_user_by_stripe_subscription_id(sub_id, pool)?
            {
                server::connected::deactivate_subscription(user_id, pool, mailer)?;
            }
        }
        // e.g. failed renewal payment -> status becomes "past_due"/"unpaid"
        "customer.subscription.updated" => {
            let obj = &event.data.object;
            let status = obj["status"].as_str().unwrap_or("");
            if matches!(status, "canceled" | "unpaid" | "incomplete_expired") {
                if let Some(sub_id) = obj["id"].as_str() {
                    if let Some(user_id) =
                        server::connected::find_user_by_stripe_subscription_id(sub_id, pool)?
                    {
                        server::connected::deactivate_subscription(user_id, pool, mailer)?;
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::{init_config, mailer, offline_db, stripe_signature};

    const SECRET: &[u8] = b"whsec_unit_test";
    const NOW: i64 = 1_700_000_000;
    const BODY: &[u8] = br#"{"type":"checkout.session.completed"}"#;

    fn sign(body: &[u8], timestamp: i64, secret: &[u8]) -> String {
        let header = stripe_signature(body, timestamp, secret);
        header.split_once(",v1=").unwrap().1.to_owned()
    }

    fn header(body: &[u8], timestamp: i64, secret: &[u8]) -> String {
        stripe_signature(body, timestamp, secret)
    }

    fn verify(body: &[u8], header: &str) -> bool {
        verify_webhook_signature_at(body, header, SECRET, NOW)
    }

    #[test]
    fn accepts_a_valid_signature_within_tolerance() {
        assert!(verify(BODY, &header(BODY, NOW, SECRET)));
        let edge = NOW - WEBHOOK_TIMESTAMP_TOLERANCE_SECS;
        assert!(verify(BODY, &header(BODY, edge, SECRET)));
        // Stripe may send extra schemes; only v1 matters.
        let with_v0 = format!("{},v0=deadbeef", header(BODY, NOW, SECRET));
        assert!(verify(BODY, &with_v0));
    }

    #[test]
    fn rejects_stale_or_future_timestamps() {
        for ts in [
            NOW - WEBHOOK_TIMESTAMP_TOLERANCE_SECS - 1,
            NOW + WEBHOOK_TIMESTAMP_TOLERANCE_SECS + 1,
        ] {
            assert!(!verify(BODY, &header(BODY, ts, SECRET)), "ts = {ts}");
        }
    }

    #[test]
    fn rejects_tampering_and_wrong_secret() {
        let valid = header(BODY, NOW, SECRET);
        assert!(!verify(br#"{"type":"tampered"}"#, &valid));
        assert!(!verify(BODY, &header(BODY, NOW, b"other secret")));
        // Signature for a different timestamp than the one announced.
        let swapped = format!("t={},v1={}", NOW, sign(BODY, NOW - 1, SECRET));
        assert!(!verify(BODY, &swapped));
    }

    #[test]
    fn rejects_malformed_headers() {
        let sig = sign(BODY, NOW, SECRET);
        for header in [
            String::new(),
            format!("t={NOW}"),
            format!("v1={sig}"),
            format!("t=not-a-number,v1={sig}"),
            format!("t={NOW},v1=not-hex"),
            format!("t={NOW},v1={}", &sig[..sig.len() - 2]),
            format!("t={NOW},v1={sig}00"),
        ] {
            assert!(!verify(BODY, &header), "{header:?}");
        }
    }

    #[test]
    fn verify_uses_the_configured_secret_and_clock() {
        init_config();
        let secret = STRIPE_WEBHOOK_SECRET.get().unwrap().as_bytes();
        let now = chrono::Utc::now().timestamp();
        assert!(verify_webhook_signature(BODY, &header(BODY, now, secret)));
        assert!(!verify_webhook_signature(BODY, &header(BODY, now, SECRET)));
    }

    #[tokio::test]
    async fn checkout_only_supports_the_premium_plan() {
        let result = create_subscription_checkout(Uuid::nil(), "a@example.com", "gold").await;
        assert!(matches!(result, Err(ServerError::InputValidation)));
    }

    #[tokio::test]
    async fn ignores_irrelevant_or_incomplete_events() {
        init_config();
        // None of these may touch the (unreachable) database.
        let events = [
            serde_json::json!({"type": "invoice.paid", "data": {"object": {}}}),
            serde_json::json!({"type": "checkout.session.completed", "data": {"object": {}}}),
            serde_json::json!({"type": "checkout.session.completed",
                               "data": {"object": {"client_reference_id": "not-a-uuid"}}}),
            serde_json::json!({"type": "customer.subscription.deleted", "data": {"object": {}}}),
            serde_json::json!({"type": "customer.subscription.updated",
                               "data": {"object": {"id": "sub_1", "status": "past_due"}}}),
        ];
        for event in events {
            let parsed: StripeEvent = serde_json::from_value(event.clone()).unwrap();
            assert!(
                handle_webhook(parsed, &offline_db(), &mailer())
                    .await
                    .is_ok(),
                "{event}"
            );
        }
    }
}
