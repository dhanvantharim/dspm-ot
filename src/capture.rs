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

#[cfg(test)]
mod tests {
    use super::process_packet;
    use crate::db::Database;

    fn modbus_tcp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let ip_header_len = 20;
        let tcp_header_len = 20;
        let eth_header_len = 14;
        let total_len = eth_header_len + ip_header_len + tcp_header_len + payload.len();

        let mut frame = vec![0u8; total_len];

        frame[12] = 0x08;
        frame[13] = 0x00;

        let ip_off = eth_header_len;
        frame[ip_off] = 0x45;
        frame[ip_off + 9] = 6; // TCP
        frame[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip);
        frame[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip);
        let ip_len = (ip_header_len + tcp_header_len + payload.len()) as u16;
        frame[ip_off + 2] = (ip_len >> 8) as u8;
        frame[ip_off + 3] = (ip_len & 0xff) as u8;

        let tcp_off = ip_off + ip_header_len;
        frame[tcp_off + 2] = 0x01;
        frame[tcp_off + 3] = 0xF6; // dst port 502
        frame[tcp_off + 12] = 0x50; // data offset = 5 (20-byte header)

        let payload_off = tcp_off + tcp_header_len;
        frame[payload_off..].copy_from_slice(payload);
        frame
    }

    #[test]
    fn process_packet_records_modbus_flow() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("test.db")).unwrap();

        let payload = [0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00];
        let frame = modbus_tcp_frame([192, 168, 1, 10], [192, 168, 1, 20], &payload);

        process_packet(&frame, &db);

        let assets = db.list_assets(None).unwrap();
        assert_eq!(assets.len(), 2);
        let ips: Vec<_> = assets.iter().map(|a| a.ip_address.as_str()).collect();
        assert!(ips.contains(&"192.168.1.10"));
        assert!(ips.contains(&"192.168.1.20"));

        let flows = db.list_flows().unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].protocol, "modbus");
        assert_eq!(flows[0].src_ip, "192.168.1.10");
        assert_eq!(flows[0].dst_ip, "192.168.1.20");
        assert_eq!(flows[0].byte_volume, payload.len() as i64);
    }

    #[test]
    fn process_packet_ignores_non_ot_ports() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("test.db")).unwrap();

        let mut frame = modbus_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], &[0x00]);
        // Change destination port to HTTP
        frame[36] = 0x00;
        frame[37] = 0x50;

        process_packet(&frame, &db);

        assert!(db.list_assets(None).unwrap().is_empty());
        assert!(db.list_flows().unwrap().is_empty());
    }
}
