use chrono::{Datelike, TimeZone, Utc};

use crate::api_handlers::misc::AppState;
use crate::consts::SERVER_MODE;
use crate::error::ServerError;
use crate::server;

pub fn start_monthly_task(app_state: AppState) -> Result<(), ServerError> {

    let server_mode = SERVER_MODE
        .get()
        .unwrap()
        .to_string();
    
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

                // For testing, run the task every minute
                "development" => std::time::Duration::from_secs(60),

                // For production, run the task at the 1st of every month at 00:00:00 UTC
                "master" => {
                    let now = Utc::now();

                    // Calculate next 1st of month at 00:00:00 UTC
                    let next_run = {
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
                    };

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
