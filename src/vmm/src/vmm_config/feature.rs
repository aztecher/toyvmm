// Copyright 2025 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub fn new() -> Self {
        FeatureGateController {
            features: HashMap::new(),
        }
    }

    pub fn from_config(configs: &[FeatureConfig]) -> Self {
        let mut features: HashMap<String, Box<dyn FeatureGate>> = HashMap::new();
        for (_, config) in configs.iter().enumerate() {
            match &config.feature[..] {
                "acpi" => {
                    let _ = features.insert(
                        config.feature.clone(),
                        Box::new(AcpiFeatureGate::new(config)),
                    );
                }
                _ => panic!("Failed to handle feature gates: {0}", config.feature),
            }
        }
        FeatureGateController { features }
    }

    pub fn feature_gate(&self, key: &str) -> Option<&Box<dyn FeatureGate>> {
        self.features.get(key)
    }
}
