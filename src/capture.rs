use anyhow::Result;
use std::path::Path;
use tracing::{info, warn};

use crate::{config::Config, db::Database, protocol::ProtocolKind};

pub fn run(
    interface: &str,
    duration: Option<u64>,
    extra_filter: Option<&str>,
    db_path: &Path,
    config_path: Option<&Path>,
) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    let db = Database::open(db_path)?;

    let bpf = match extra_filter {
        Some(f) => format!("({}) and ({})", config.capture.bpf_filter, f),
        None => config.capture.bpf_filter.clone(),
    };

    info!(interface, %bpf, "starting live capture");

    let mut cap = pcap::Capture::from_device(interface)?
        .promisc(true)
        .open()?;

    cap.filter(&bpf, true)?;

    let deadline = duration.map(|d| std::time::Instant::now() + std::time::Duration::from_secs(d));

    loop {
        if let Some(dl) = deadline {
            if std::time::Instant::now() >= dl {
                info!("capture duration elapsed, stopping");
                break;
            }
        }

        match cap.next_packet() {
            Ok(packet) => process_packet(packet.data, &db),
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                warn!(error = %e, "capture error");
                break;
            }
        }
    }

    Ok(())
}

pub fn process_packet(data: &[u8], db: &Database) {
    use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet};

    let Some(eth) = EthernetPacket::new(data) else { return };
    let Some(ipv4) = Ipv4Packet::new(eth.payload()) else { return };

    let src = ipv4.get_source().to_string();
    let dst = ipv4.get_destination().to_string();

    let (dst_port, payload) = match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp) = TcpPacket::new(ipv4.payload()) else { return };
            (tcp.get_destination(), tcp.payload().to_vec())
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp) = UdpPacket::new(ipv4.payload()) else { return };
            (udp.get_destination(), udp.payload().to_vec())
        }
        _ => return,
    };

    let Some(kind) = ProtocolKind::from_port(dst_port) else { return };
    let proto = kind.as_str();
    let bytes = payload.len() as u64;

    let _ = db.upsert_asset(&src, proto);
    let _ = db.upsert_asset(&dst, proto);
    let _ = db.upsert_flow(&src, &dst, proto, bytes);
}
