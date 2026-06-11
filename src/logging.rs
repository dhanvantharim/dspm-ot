use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json())
        .init();

    Ok(())
}
