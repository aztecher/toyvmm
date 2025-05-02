// Copyright 2025 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Errors associated with load and initialize about features
#[derive(Debug, thiserror::Error, derive_more::From)]
pub enum FeatureError {
    /// Invalid feature error.
    #[error("Invalid feature error: {0}")]
    InvalidFeature(String),
}

/// This represents part of the guest's configuration fikle in json format
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// feature name
    pub feature: String,
    /// If set true, the feature is used in this guest
    pub enable: bool,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct AcpiFeatureGate {
    enable: bool,
}

impl AcpiFeatureGate {
    pub fn new(config: &FeatureConfig) -> Self {
        AcpiFeatureGate {
            enable: config.enable,
        }
    }
}

impl FeatureGate for AcpiFeatureGate {
    fn enable(&self) -> bool {
        self.enable
    }
}

pub trait FeatureGate {
    fn enable(&self) -> bool;
}

pub struct FeatureGateController {
    pub features: HashMap<String, Box<dyn FeatureGate>>,
}

impl FeatureGateController {
    pub fn from_config(configs: &[FeatureConfig]) -> Result<Self, FeatureError> {
        let mut features: HashMap<String, Box<dyn FeatureGate>> = HashMap::new();
        for (_, config) in configs.iter().enumerate() {
            match &config.feature[..] {
                "acpi" => {
                    let _ = features.insert(
                        config.feature.clone(),
                        Box::new(AcpiFeatureGate::new(config)),
                    );
                }
                _ => return Err(FeatureError::InvalidFeature(config.feature.clone())),
            }
        }
        Ok(FeatureGateController { features })
    }

    pub fn feature_gate(&self, key: &str) -> Option<&Box<dyn FeatureGate>> {
        self.features.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_gate_controller() {
        let feature_config: Vec<FeatureConfig> = vec![FeatureConfig {
            feature: "acpi".to_string(),
            enable: true,
        }];
        let fg = FeatureGateController::from_config(&feature_config).unwrap();
        assert!(fg.feature_gate("acpi").is_some());
    }

    #[test]
    fn test_feature_gate_controller_invalid() {
        let feature_config: Vec<FeatureConfig> = vec![FeatureConfig {
            feature: "test".to_string(),
            enable: true,
        }];
        assert!(FeatureGateController::from_config(&feature_config).is_err());
    }
}
