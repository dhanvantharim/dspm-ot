use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub capture: CaptureConfig,

    #[serde(default)]
    pub classification: ClassificationConfig,

    #[serde(default)]
    pub scoring: ScoringConfig,

    #[serde(default)]
    pub zones: ZoneConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct CaptureConfig {
    #[serde(default = "default_bpf_filter")]
    pub bpf_filter: String,

    #[serde(default = "default_batch_size")]
    pub db_batch_size: usize,
}

#[derive(Debug, Deserialize, Default)]
pub struct ClassificationConfig {
    pub rules_file: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ScoringConfig {
    #[serde(default = "default_weight")]
    pub cleartext_sensitive_weight: f32,

    #[serde(default = "default_weight")]
    pub unauthenticated_write_weight: f32,

    #[serde(default = "default_weight")]
    pub cross_zone_weight: f32,

    #[serde(default = "default_stale_threshold_hours")]
    pub stale_threshold_hours: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct ZoneConfig {
    pub subnets: Vec<SubnetZone>,
}

#[derive(Debug, Deserialize)]
pub struct SubnetZone {
    pub subnet: String,
    pub purdue_level: u8,
    pub label: Option<String>,
}

fn default_bpf_filter() -> String {
    "port 502 or port 44818 or port 2222 or port 20000 or port 102 or port 2404 or port 47808".to_string()
}

fn default_batch_size() -> usize {
    100
}

fn default_weight() -> f32 {
    1.0
}

fn default_stale_threshold_hours() -> u64 {
    24
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("parsing config file: {}", path.display()))
    }

    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => Self::load(p),
            None => Ok(Self::default()),
        }
    }
}
