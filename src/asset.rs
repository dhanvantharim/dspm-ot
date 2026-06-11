use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub inferred_role: DeviceRole,
    pub protocols: Vec<String>,
    pub purdue_level: Option<u8>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub posture_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum DeviceRole {
    Plc,
    Rtu,
    Hmi,
    Scada,
    Historian,
    Engineering,
    #[default]
    Unknown,
}

impl Asset {
    pub fn new(ip_address: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            ip_address,
            mac_address: None,
            vendor: None,
            inferred_role: DeviceRole::Unknown,
            protocols: Vec::new(),
            purdue_level: None,
            first_seen: now,
            last_seen: now,
            posture_score: 0.0,
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
    }

    pub fn add_protocol(&mut self, proto: &str) {
        if !self.protocols.iter().any(|p| p == proto) {
            self.protocols.push(proto.to_string());
        }
    }
}
