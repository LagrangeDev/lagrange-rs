use anyhow::Result;
use lagrange_core::{
    common::sign::{DefaultSignProvider, SignProvider},
    config::BotConfig,
    protocol::Protocols,
    BotContext,
};
use std::sync::Arc;
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const BOT_UIN: Option<u64> = None;
const BOT_PROTOCOL: Protocols = Protocols::Linux;
const BOT_VERBOSE: bool = false;
const AUTO_RECONNECT: bool = true;
const AUTO_RELOGIN: bool = true;
const LOG_LEVEL: Level = Level::TRACE;
const COLORED_LOGS: bool = true;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing()?;

    info!("Starting Lagrange Core Development Runner");
    info!("Protocol: {:?}", BOT_PROTOCOL);
    info!("Log Level: {:?}", LOG_LEVEL);

    // Initialize sign provider
    let sign_provider = Arc::new(DefaultSignProvider::new());
    info!("Using sign provider: {}", sign_provider.platform());

    let config = BotConfig::builder()
        .protocol(BOT_PROTOCOL)
        .verbose(BOT_VERBOSE)
        .auto_reconnect(AUTO_RECONNECT)
        .auto_re_login(AUTO_RELOGIN)
        .sign_provider(sign_provider)
        .build();

    info!("Building bot context...");
    let context = BotContext::builder()
        .config(config)
        .build();

    setup_event_handlers(context.clone());

    info!("Starting main event loop...");
    info!("Press Ctrl+C to shutdown gracefully");

    context.connect().await.expect("Failed to establish initial connection");
    context.clone().start_connection_monitor();

    let qrcode = context.fetch_qrcode().await?;
    info!("QR Code URL: {}", qrcode.len());

    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal, cleaning up...");
        }
        Err(err) => {
            error!("Error listening for shutdown signal: {}", err);
        }
    }

    info!("Shutdown complete");

    Ok(())
}

fn setup_tracing() -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(LOG_LEVEL.as_str()));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(COLORED_LOGS);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(())
}

fn setup_event_handlers(_context: Arc<BotContext>) {
    info!("Event handlers ready (add custom handlers as needed)");
}
