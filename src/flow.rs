use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub id: Uuid,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_volume: u64,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub asset_id: Option<Uuid>,
    pub flow_id: Option<Uuid>,
    pub severity: Severity,
    pub category: FindingCategory,
    pub description: String,
    pub evidence: String,
    pub first_seen: DateTime<Utc>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    CleartextSensitiveData,
    UnauthenticatedWrite,
    CrossZoneFlow,
    BroadcastWrite,
    StaleAsset,
    DeprecatedFunctionCode,
    UnexpectedProtocol,
}

impl DataFlow {
    pub fn new(src_ip: String, dst_ip: String, protocol: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            src_ip,
            dst_ip,
            protocol,
            first_seen: now,
            last_seen: now,
            packet_count: 0,
            byte_volume: 0,
            findings: Vec::new(),
        }
    }

    pub fn record_packet(&mut self, bytes: u64) {
        self.last_seen = Utc::now();
        self.packet_count += 1;
        self.byte_volume += bytes;
    }
}
