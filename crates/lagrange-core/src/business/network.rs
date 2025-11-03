use crate::{BotContext, Error, internal::services::system::{AliveEventReq, AliveService}};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

impl BotContext {
    pub async fn connect(self: &Arc<Self>) -> Result<bool, Error> {
        let result = self.socket.connect(
            self.config.use_ipv6_network,
            self.packet.clone()
        ).await;

        if result.is_err() {
            Err(Error::NetworkError("Failed to connect to server".to_string()))
        } else {
            self.clone().start_heartbeat();
            Ok(true)
        }
    }

    /// Start sending heartbeat packets at 5-second intervals
    pub fn start_heartbeat(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                if !self.socket.is_connected().await {
                    tracing::debug!("Socket not connected, skipping heartbeat");
                    continue;
                }

                // Use new type-safe send API
                if let Err(e) = self.event.send::<AliveService>(AliveEventReq {}, self.clone()).await {
                    tracing::warn!(error = %e, "Failed to send heartbeat");
                }
            }
        })
    }

    pub fn start_connection_monitor(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if !self.config.auto_reconnect {
                tracing::info!("Auto-reconnect disabled, connection monitor not started");
                return;
            }

            tracing::info!("Starting connection monitor with auto-reconnect enabled");
            let mut check_interval = time::interval(Duration::from_secs(3));
            check_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            let mut retry_count = 0u32;
            let max_backoff_secs = 60; // Max 60 seconds between retries

            loop {
                check_interval.tick().await;

                if self.socket.is_connected().await {
                    if retry_count > 0 {
                        retry_count = 0;
                        tracing::info!("Connection restored, retry count reset");
                    }
                    continue;
                }

                tracing::warn!(retry_count, "Socket disconnected, attempting to reconnect");
                let backoff_secs = (1u64 << retry_count.min(6)).min(max_backoff_secs);

                if retry_count > 0 {
                    tracing::info!(backoff_secs, "Waiting before reconnection attempt");
                    time::sleep(Duration::from_secs(backoff_secs)).await;
                }

                match self.socket.connect(
                    self.config.use_ipv6_network,
                    self.packet.clone()
                ).await {
                    Ok(_) => {
                        tracing::info!("Successfully reconnected to server");
                        self.clone().start_heartbeat();
                        retry_count = 0;
                    }
                    Err(e) => {
                        retry_count += 1;
                        tracing::error!(
                            error = %e,
                            retry_count,
                            next_backoff_secs = (1u64 << retry_count.min(6)).min(max_backoff_secs),
                            "Failed to reconnect"
                        );
                    }
                }
            }
        })
    }
}