use libsodium_sys::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::Deserialize;
use uuid::Uuid;

use crate::consts::*;
use crate::error::ServerError;
use crate::api_handlers::misc::DbPool;

type HmacSha256 = Hmac<Sha256>;

fn plan_amount_cents(plan: &str) -> Result<i64, ServerError> {
    match plan {
        // Connected plan is free
        "user" => Err(ServerError::InputValidation),
        "premium" => Ok(*PRICE_PREMIUM.get().unwrap() * 100), // convert CHF to cents
        _ => Err(ServerError::InputValidation),
    }
}

fn sign(params: &[(String, String)]) -> Result<String, ServerError> {
    let query = serde_urlencoded::to_string(params).map_err(|_| ServerError::Internal)?;
    let mut mac = HmacSha256::new_from_slice(PAYREXX_API_SECRET.get().unwrap().as_bytes())
        .map_err(|_| ServerError::Internal)?;
    mac.update(query.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

/// Creates a Payrexx Gateway configured as a recurring subscription and
/// returns the checkout link to redirect the user to.
pub async fn create_subscription_gateway(
    user_id: Uuid,
    email: &str,
    plan: &str,
) -> Result<String, ServerError> {
    let amount = plan_amount_cents(plan)?;

    // referenceId carries both the user id and the plan so the webhook
    // can activate the right role without a round trip to Payrexx.
    let reference_id = format!("{}:{}", user_id, plan);

    let mut params: Vec<(String, String)> = vec![
        ("amount".into(), amount.to_string()),
        ("currency".into(), "CHF".into()),
        ("purpose".into(), format!("JustTransfer {plan} subscription")),
        ("referenceId".into(), reference_id),
        ("subscriptionState".into(), "true".into()),
        ("subscriptionInterval".into(), "P1M".into()), // monthly
        ("skipResultPage".into(), "false".into()),
        ("successRedirectUrl".into(), format!("{}/account?subscription=success", FRONTEND_URL.get().unwrap())),
        ("failedRedirectUrl".into(), format!("{}/pricing?subscription=failed", FRONTEND_URL.get().unwrap())),
        ("cancelRedirectUrl".into(), format!("{}/pricing?subscription=cancelled", FRONTEND_URL.get().unwrap())),
        ("fields[email][value]".into(), email.to_string()),
    ];

    let signature = sign(&params)?;
    params.push(("ApiSignature".into(), signature));

    let url = format!(
        "https://api.payrexx.com/v1.16/Gateway/?instance={}",
        PAYREXX_INSTANCE.get().unwrap()
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    if !resp.status().is_success() {
        tracing::error!("Payrexx gateway creation failed: {}", resp.status());
        return Err(ServerError::Internal);
    }

    let body: serde_json::Value = resp.json().await.map_err(|_| ServerError::Internal)?;
    body["data"][0]["link"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or(ServerError::Internal)
}

/// Verifies the `X-Webhook-Signature` header: lowercase hex SHA-256 HMAC
/// of the raw request body, keyed with the webhook signing secret.
pub fn verify_webhook_signature(raw_body: &[u8], signature_header: &str) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(PAYREXX_WEBHOOK_SECRET.get().unwrap().as_bytes()) else {
        return false;
    };
    mac.update(raw_body);
    let expected = hex::encode(mac.finalize().into_bytes());

    if expected.len() != signature_header.len() {
        return false;
    }

    unsafe {
        sodium_memcmp(
            expected.as_ptr().cast(),
            signature_header.as_ptr().cast(),
            expected.len(),
        ) == 0
    }
}

#[derive(Deserialize, Debug)]
pub struct WebhookPayload {
    pub transaction: Option<WebhookTransaction>,
}

#[derive(Deserialize, Debug)]
pub struct WebhookTransaction {
    pub status: String,
    pub invoice: WebhookInvoice,
    pub subscription: Option<WebhookSubscriptionRef>,
}

#[derive(Deserialize, Debug)]
pub struct WebhookInvoice {
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct WebhookSubscriptionRef {
    pub id: i64,
}

/// Parses `user_id:plan` back out of the referenceId we set on gateway creation.
fn parse_reference_id(reference_id: &str) -> Option<(Uuid, String)> {
    let (id_str, plan) = reference_id.split_once(':')?;
    let user_id = Uuid::parse_str(id_str).ok()?;
    Some((user_id, plan.to_string()))
}

pub async fn handle_webhook(payload: WebhookPayload, pool: &DbPool) -> Result<(), ServerError> {
    let Some(transaction) = payload.transaction else {
        // Not a transaction webhook (e.g. payout) — nothing to do here.
        return Ok(());
    };

    let Some(reference_id) = transaction.invoice.reference_id else {
        return Ok(());
    };

    let Some((user_id, plan)) = parse_reference_id(&reference_id) else {
        return Ok(());
    };

    match transaction.status.as_str() {
        "confirmed" => {
            crate::server::connected::activate_subscription(
                user_id,
                &plan,
                transaction.subscription.map(|s| s.id),
                pool,
            )?;
        }
        "cancelled" | "declined" | "refunded" | "expired" => {
            crate::server::connected::deactivate_subscription(user_id, pool)?;
        }
        // "waiting" and other intermediate states: no-op.
        _ => {}
    }

    Ok(())
}