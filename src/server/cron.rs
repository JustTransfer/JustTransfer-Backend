use chrono::{Datelike, TimeZone, Utc};

use crate::api_handlers::misc::AppState;
use crate::consts::SERVER_MODE;
use crate::error::ServerError;
use crate::server;

pub fn next_monthly_run(now: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    let year = if now.month() == 12 {
        now.year() + 1
    } else {
        now.year()
    };
    let month = if now.month() == 12 {
        1
    } else {
        now.month() + 1
    };
    Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).unwrap()
}

pub fn next_daily_run(now: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    let next_midnight = (now + std::time::Duration::from_secs(24 * 60 * 60))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    Utc.from_utc_datetime(&next_midnight)
}

pub fn start_monthly_task(app_state: AppState) -> Result<(), ServerError> {
    let server_mode = SERVER_MODE.get().unwrap().to_string();

    // If server mode is "slave", do not run the monthly task
    if server_mode == "slave" {
        tracing::info!("Server mode is 'slave', monthly task will not run");
        return Ok(());
    }

    // Run the monthly task in a background task
    let db_clone = app_state.db.clone();
    tokio::spawn(async move {
        loop {
            let duration = match server_mode.as_str() {
                // For testing, run the task every 2 minutes
                "development" => std::time::Duration::from_secs(120),

                // For production, run the task at the 1st of every month at 00:00:00 UTC
                "master" => {
                    let now = Utc::now();

                    // Calculate next 1st of month at 00:00:00 UTC
                    let next_run = next_monthly_run(now);

                    let time_next_month = (next_run - now)
                        .to_std()
                        .unwrap_or(std::time::Duration::from_secs(0));

                    tracing::info!(
                        "Server mode is 'master'. Monthly task will run in {:?} at {}",
                        time_next_month,
                        next_run
                    );

                    time_next_month
                }
                _ => {
                    tracing::error!(
                        "Unknown server mode: {}. Monthly task will not run.",
                        server_mode
                    );
                    panic!(
                        "Unknown server mode: {}. Monthly task will not run.",
                        server_mode
                    );
                }
            };

            tokio::time::sleep(duration).await;

            // Run the monthly task
            if let Err(e) = server::connected::reset_transfer_counter_all_users(&db_clone).await {
                tracing::error!("Error running monthly task: {:?}", e);
            } else {
                tracing::info!("Monthly task completed successfully");
            }
        }
    });

    Ok(())
}

pub fn start_daily_cleanup_task(app_state: AppState) -> Result<(), ServerError> {
    let server_mode = SERVER_MODE.get().unwrap().to_string();

    if server_mode == "slave" {
        tracing::info!("Server mode is 'slave', daily cleanup task will not run");
        return Ok(());
    }

    let db_clone = app_state.db.clone();
    let s3_clone = app_state.s3.clone();

    tokio::spawn(async move {
        loop {
            let duration = match server_mode.as_str() {
                // For testing, run every minute
                "development" => std::time::Duration::from_secs(60),

                // For production, run the task at midnight UTC every day
                "master" => {
                    let now = Utc::now();
                    let next_run = next_daily_run(now);

                    let time_until = (next_run - now)
                        .to_std()
                        .unwrap_or(std::time::Duration::from_secs(0));

                    tracing::info!(
                        "Server mode is 'master'. Daily cleanup task will run in {:?} at {}",
                        time_until,
                        next_run
                    );

                    time_until
                }
                _ => {
                    tracing::error!(
                        "Unknown server mode: {}. Daily cleanup task will not run.",
                        server_mode
                    );
                    panic!(
                        "Unknown server mode: {}. Daily cleanup task will not run.",
                        server_mode
                    );
                }
            };

            tokio::time::sleep(duration).await;

            match server::link::delete_expired_link_transfers(&db_clone, &s3_clone).await {
                Ok(count) => tracing::info!(
                    "Daily cleanup task completed successfully, deleted {} expired transfers",
                    count
                ),
                Err(e) => tracing::error!("Error running daily cleanup task: {:?}", e),
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
    }

    #[test]
    fn monthly_run_is_the_first_of_next_month_at_midnight() {
        let cases = [
            (at(2026, 1, 15, 12, 0, 0), at(2026, 2, 1, 0, 0, 0)),
            (at(2026, 1, 31, 23, 59, 59), at(2026, 2, 1, 0, 0, 0)),
            // Exactly on a run instant: the next run is a month later, not now.
            (at(2026, 3, 1, 0, 0, 0), at(2026, 4, 1, 0, 0, 0)),
            (at(2026, 12, 31, 23, 59, 59), at(2027, 1, 1, 0, 0, 0)),
        ];
        for (now, expected) in cases {
            assert_eq!(next_monthly_run(now), expected, "now = {now}");
        }
    }

    #[test]
    fn daily_run_is_the_next_midnight() {
        let cases = [
            (at(2026, 1, 1, 12, 30, 0), at(2026, 1, 2, 0, 0, 0)),
            (at(2026, 1, 1, 0, 0, 0), at(2026, 1, 2, 0, 0, 0)),
            (at(2026, 2, 28, 23, 59, 59), at(2026, 3, 1, 0, 0, 0)),
            (at(2028, 2, 28, 10, 0, 0), at(2028, 2, 29, 0, 0, 0)),
            (at(2026, 12, 31, 18, 0, 0), at(2027, 1, 1, 0, 0, 0)),
        ];
        for (now, expected) in cases {
            assert_eq!(next_daily_run(now), expected, "now = {now}");
        }
    }
}
