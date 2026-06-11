use anyhow::{Context, Result};
use std::path::Path;
use tracing::info;

use crate::{capture, config::Config, db::Database};

pub fn run(file: &Path, db_path: &Path, config_path: Option<&Path>) -> Result<()> {
    let _config = Config::load_or_default(config_path)?;
    let db = Database::open(db_path)?;

    info!(file = %file.display(), "starting offline analysis");

    let mut cap = pcap::Capture::from_file(file)
        .with_context(|| format!("opening pcap file: {}", file.display()))?;

    loop {
        match cap.next_packet() {
            Ok(packet) => capture::process_packet(packet.data, &db),
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
    }

    info!("offline analysis complete");
    Ok(())
}
