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

#[cfg(test)]
mod tests {
    use super::Scorer;
    use crate::config::ScoringConfig;

    #[test]
    fn score_sums_weighted_risk_factors() {
        let scorer = Scorer::new(ScoringConfig {
            cleartext_sensitive_weight: 1.0,
            unauthenticated_write_weight: 1.0,
            cross_zone_weight: 1.0,
            stale_threshold_hours: 24,
        });
        let score = scorer.score_asset(1, 1, 1, true);
        assert_eq!(score, 100.0);
    }

    #[test]
    fn score_caps_at_100_with_high_weights() {
        let scorer = Scorer::new(ScoringConfig {
            cleartext_sensitive_weight: 2.0,
            unauthenticated_write_weight: 2.0,
            cross_zone_weight: 2.0,
            stale_threshold_hours: 24,
        });
        let score = scorer.score_asset(1, 1, 1, true);
        assert_eq!(score, 100.0);
    }

    #[test]
    fn score_is_zero_with_no_risk_factors() {
        let scorer = Scorer::new(ScoringConfig::default());
        assert_eq!(scorer.score_asset(0, 0, 0, false), 0.0);
    }
}
