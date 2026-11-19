//! Subscription lifecycle: `server::payment::handle_webhook` and the
//! `server::connected` subscription helpers against a real database.

use serde_json::json;
use uuid::Uuid;

use super::support::*;
use crate::api_handlers::misc::DbPool;
use crate::server::connected::*;
use crate::server::payment::{handle_webhook, StripeEvent};

async fn deliver(pool: &DbPool, event: serde_json::Value) {
    let event: StripeEvent = serde_json::from_value(event).unwrap();
    handle_webhook(event, pool, &mailer()).await.unwrap();
}

async fn subscribe(pool: &DbPool, user_id: Uuid) -> String {
    let sub_id = format!("sub_{}", Uuid::new_v4().simple());
    deliver(
        pool,
        json!({
            "type": "checkout.session.completed",
            "data": {"object": {
                "client_reference_id": user_id.to_string(),
                "subscription": sub_id,
                "customer": "cus_test",
            }}
        }),
    )
    .await;
    sub_id
}

fn role(pool: &DbPool, user_id: Uuid) -> String {
    load_user(pool, user_id).unwrap().role
}

#[tokio::test]
async fn completed_checkout_upgrades_the_user_to_premium() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");

    let sub_id = subscribe(&pool, user.id).await;

    let stored = load_user(&pool, user.id).unwrap();
    assert_eq!(stored.role, "premium");
    assert_eq!(
        stored.stripe_subscription_id.as_deref(),
        Some(sub_id.as_str())
    );
    assert_eq!(stored.stripe_customer_id.as_deref(), Some("cus_test"));
    assert_eq!(
        get_stripe_subscription_id(user.id, &pool).unwrap(),
        Some(sub_id.clone())
    );
    assert_eq!(
        find_user_by_stripe_subscription_id(&sub_id, &pool).unwrap(),
        Some(user.id)
    );
}

#[tokio::test]
async fn deleted_subscription_downgrades_the_user() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    let sub_id = subscribe(&pool, user.id).await;

    deliver(
        &pool,
        json!({"type": "customer.subscription.deleted", "data": {"object": {"id": sub_id}}}),
    )
    .await;

    let stored = load_user(&pool, user.id).unwrap();
    assert_eq!(stored.role, "user");
    assert_eq!(stored.stripe_subscription_id, None);
    assert_eq!(stored.current_period_end, None);
    assert_eq!(
        find_user_by_stripe_subscription_id(&sub_id, &pool).unwrap(),
        None
    );
}

#[tokio::test]
async fn subscription_updates_downgrade_only_on_terminal_statuses() {
    let pool = require_db!();
    let updated = |sub_id: &str, status: &str| {
        json!({"type": "customer.subscription.updated",
               "data": {"object": {"id": sub_id, "status": status}}})
    };

    for status in ["active", "past_due", "trialing"] {
        let user = insert_user(&pool, "user");
        let sub_id = subscribe(&pool, user.id).await;
        deliver(&pool, updated(&sub_id, status)).await;
        assert_eq!(role(&pool, user.id), "premium", "{status}");
    }
    for status in ["canceled", "unpaid", "incomplete_expired"] {
        let user = insert_user(&pool, "user");
        let sub_id = subscribe(&pool, user.id).await;
        deliver(&pool, updated(&sub_id, status)).await;
        assert_eq!(role(&pool, user.id), "user", "{status}");
    }
}

#[tokio::test]
async fn events_for_unknown_subscriptions_are_ignored() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    subscribe(&pool, user.id).await;

    let unknown = "sub_does_not_exist";
    deliver(
        &pool,
        json!({"type": "customer.subscription.deleted", "data": {"object": {"id": unknown}}}),
    )
    .await;
    deliver(
        &pool,
        json!({"type": "customer.subscription.updated",
                          "data": {"object": {"id": unknown, "status": "canceled"}}}),
    )
    .await;

    assert_eq!(role(&pool, user.id), "premium");
}

#[tokio::test]
async fn scheduled_cancellation_records_the_period_end() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    subscribe(&pool, user.id).await;
    let end = chrono::DateTime::from_timestamp(1_900_000_000, 0).unwrap();

    update_subscription_end(user.id, end, &pool, &mailer()).unwrap();

    let stored = load_user(&pool, user.id).unwrap();
    assert_eq!(stored.current_period_end, Some(end));
    assert_eq!(
        stored.role, "premium",
        "keeps premium until the period ends"
    );
    assert_eq!(
        get_user(&user.email, &pool).unwrap().current_period_end,
        Some(end)
    );
}

#[tokio::test]
async fn subscription_lookups_for_users_without_one() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    assert_eq!(get_stripe_subscription_id(user.id, &pool).unwrap(), None);
    assert!(get_stripe_subscription_id(Uuid::new_v4(), &pool).is_err());
}
