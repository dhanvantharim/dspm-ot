use crate::config::ScoringConfig;

pub struct Scorer {
    config: ScoringConfig,
}

impl Scorer {
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    pub fn score_asset(
        &self,
        cleartext_sensitive_flows: u64,
        unauthenticated_writes: u64,
        cross_zone_flows: u64,
        is_stale: bool,
    ) -> f32 {
        let mut score: f32 = 0.0;

        if cleartext_sensitive_flows > 0 {
            score += self.config.cleartext_sensitive_weight * 30.0;
        }
        if unauthenticated_writes > 0 {
            score += self.config.unauthenticated_write_weight * 40.0;
        }
        if cross_zone_flows > 0 {
            score += self.config.cross_zone_weight * 20.0;
        }
        if is_stale {
            score += 10.0;
        }

        score.min(100.0)
    }
}
