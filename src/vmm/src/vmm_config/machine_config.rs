// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub const DEFAULT_MEM_SIZE_MIB: usize = 128;

/// Errors associated with actions on `VmConfigError`.
#[derive(Debug, thiserror::Error)]
pub enum VmConfigError {
    /// The memory size is invalid. The memory can only be an unsigned integer.
    #[error("The memory size (MiB) is invalid.")]
    InvalidMemorySize,
    /// The vcpu number is invalid.
    #[error("The vcpu count is invalid.")]
    InvalidVcpuCount,
}

/// This represents part of the guest's configuration file in json format.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineConfig {
    /// Number of vcpus from configuration file.
    pub vcpu_count: u8,
    /// The memory size in MiB from configuration file.
    pub mem_size_mib: usize,
    /// Enable tracking dirty page or not from configuration file.
    pub track_dirty_page: bool,
}

/// Configuration of the vm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmConfig {
    /// Number of vcpu on vm.
    pub vcpu_count: u8,
    /// The memory size in MiB on vm.
    pub mem_size_mib: usize,
    /// Enable tracking dirty page or not on vm.
    pub track_dirty_page: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
            vcpu_count: 1,
            mem_size_mib: DEFAULT_MEM_SIZE_MIB,
            track_dirty_page: false,
        }
    }
}
