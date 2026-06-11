use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLabel {
    L1, // public process state
    L2, // operational data
    L3, // configuration / engineering
    L4, // credentials / firmware
}

#[derive(Debug, Deserialize)]
pub struct ClassificationRule {
    pub protocol: String,
    pub function_codes: Vec<u8>,
    pub data_type: String,
    pub sensitivity: u8,
}

pub struct Classifier {
    rules: Vec<ClassificationRule>,
}

impl Classifier {
    pub fn new(rules: Vec<ClassificationRule>) -> Self {
        Self { rules }
    }

    pub fn classify(&self, protocol: &str, function_code: u8) -> SensitivityLabel {
        for rule in &self.rules {
            if rule.protocol == protocol && rule.function_codes.contains(&function_code) {
                return match rule.sensitivity {
                    1 => SensitivityLabel::L1,
                    2 => SensitivityLabel::L2,
                    3 => SensitivityLabel::L3,
                    4 => SensitivityLabel::L4,
                    _ => SensitivityLabel::L1,
                };
            }
        }
        SensitivityLabel::L1
    }

    pub fn is_high_sensitivity(&self, label: SensitivityLabel) -> bool {
        label >= SensitivityLabel::L3
    }
}

#[cfg(test)]
mod tests {
    use super::{ClassificationRule, Classifier, SensitivityLabel};

    fn sample_rules() -> Vec<ClassificationRule> {
        vec![
            ClassificationRule {
                protocol: "modbus".to_string(),
                function_codes: vec![3, 4],
                data_type: "measurement".to_string(),
                sensitivity: 2,
            },
            ClassificationRule {
                protocol: "modbus".to_string(),
                function_codes: vec![16],
                data_type: "configuration".to_string(),
                sensitivity: 3,
            },
        ]
    }

    #[test]
    fn classify_matches_protocol_and_function_code() {
        let classifier = Classifier::new(sample_rules());
        assert_eq!(
            classifier.classify("modbus", 4),
            SensitivityLabel::L2
        );
        assert_eq!(
            classifier.classify("modbus", 16),
            SensitivityLabel::L3
        );
    }

    #[test]
    fn classify_defaults_to_l1_for_unknown() {
        let classifier = Classifier::new(sample_rules());
        assert_eq!(classifier.classify("modbus", 99), SensitivityLabel::L1);
        assert_eq!(classifier.classify("dnp3", 1), SensitivityLabel::L1);
    }

    #[test]
    fn is_high_sensitivity_from_l3_upward() {
        let classifier = Classifier::new(vec![]);
        assert!(!classifier.is_high_sensitivity(SensitivityLabel::L2));
        assert!(classifier.is_high_sensitivity(SensitivityLabel::L3));
        assert!(classifier.is_high_sensitivity(SensitivityLabel::L4));
    }
}
