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
