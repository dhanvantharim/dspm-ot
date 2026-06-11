use ot_dspm::{capture, db::Database, report};
use std::io::Write;

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
    frame[ip_off + 9] = 6;
    frame[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip);
    frame[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip);
    let ip_len = (ip_header_len + tcp_header_len + payload.len()) as u16;
    frame[ip_off + 2] = (ip_len >> 8) as u8;
    frame[ip_off + 3] = (ip_len & 0xff) as u8;

    let tcp_off = ip_off + ip_header_len;
    frame[tcp_off + 2] = 0x01;
    frame[tcp_off + 3] = 0xF6;
    frame[tcp_off + 12] = 0x50;

    let payload_off = tcp_off + tcp_header_len;
    frame[payload_off..].copy_from_slice(payload);
    frame
}

#[test]
fn capture_to_report_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("pipeline.db");
    let json_path = dir.path().join("assets.json");
    let csv_path = dir.path().join("flows.csv");

    let db = Database::open(&db_path).unwrap();
    let payload = [0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x03, 0x00];
    let frame = modbus_tcp_frame([10, 10, 1, 1], [10, 10, 1, 2], &payload);
    capture::process_packet(&frame, &db);
    drop(db);

    report::run("json", Some(&json_path), "assets", None, &db_path).unwrap();
    report::run("csv", Some(&csv_path), "flows", None, &db_path).unwrap();

    let json = std::fs::read_to_string(json_path).unwrap();
    assert!(json.contains("10.10.1.1"));
    assert!(json.contains("modbus"));

    let csv = std::fs::read_to_string(csv_path).unwrap();
    assert!(csv.starts_with("src_ip,dst_ip,protocol"));
    assert!(csv.contains("10.10.1.1,10.10.1.2,modbus"));
}

#[test]
fn config_loads_from_file_in_integration() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let mut file = std::fs::File::create(&config_path).unwrap();
    write!(
        file,
        r#"
[[zones.subnets]]
subnet = "10.0.0.0/24"
purdue_level = 1
label = "field"
"#
    )
    .unwrap();

    let config = ot_dspm::config::Config::load(&config_path).unwrap();
    assert_eq!(config.zones.subnets.len(), 1);
    assert_eq!(config.zones.subnets[0].purdue_level, 1);
    assert_eq!(config.zones.subnets[0].label.as_deref(), Some("field"));
}
