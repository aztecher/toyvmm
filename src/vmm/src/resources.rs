// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::vmm_config::boot_source::{
    BootConfig, BootSource, BootSourceConfig, BootSourceConfigError,
};
use crate::vmm_config::drive::{BlockDeviceBuilder, BlockDeviceConfig, DriveError};
use crate::vmm_config::machine_config::{MachineConfig, VmConfig, VmConfigError};

/// Errors associated with actions on configuring VM resources.
#[derive(Debug, thiserror::Error, derive_more::From)]
pub enum ResourcesError {
    /// Block device configuration error.
    #[error("Block device error: {0}")]
    BlockDevice(DriveError),
    /// Boot source configuration error.
    #[error("Boot source error: {0}")]
    BootSource(BootSourceConfigError),
    /// JSON is invalid.
    #[error("Invalid JSON: {0}")]
    InvalidJson(serde_json::Error),
    /// Vm vcpus or memory configuration error.
    #[error("VM config error: {0}")]
    VmConfig(VmConfigError),
}

/// Used for configuring a vmm from json.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmmConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSourceConfig,
    #[serde(rename = "drives")]
    block_devices: Vec<BlockDeviceConfig>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
}

/// A data structure that encapsulates the device configurations held in the Vmm.
#[derive(Debug, Default)]
pub struct VmResources {
    pub vm_config: VmConfig,
    pub boot_source: BootSource,
    pub block: BlockDeviceBuilder,
}

impl VmResources {
    pub fn from_json(config_json: &str) -> std::result::Result<Self, ResourcesError> {
        let vmm_config: VmmConfig = serde_json::from_str::<VmmConfig>(config_json)?;
        let mut resources: Self = Default::default();

        resources.build_vm_config(vmm_config.machine_config)?;
        resources.build_boot_source(vmm_config.boot_source)?;
        resources.set_block_device_builder(vmm_config.block_devices)?;
        Ok(resources)
    }

    pub fn boot_source_config(&self) -> &BootSourceConfig {
        &self.boot_source.config
    }

    /// Construct the vm config.
    pub fn build_vm_config(&mut self, machine_config: MachineConfig) -> Result<(), VmConfigError> {
        let vcpu_count = machine_config.vcpu_count;
        if vcpu_count == 0 {
            return Err(VmConfigError::InvalidVcpuCount);
        }
        let mem_size_mib = machine_config.mem_size_mib;
        if mem_size_mib == 0 {
            return Err(VmConfigError::InvalidMemorySize);
        }
        self.vm_config = VmConfig {
            vcpu_count,
            mem_size_mib,
            track_dirty_page: machine_config.track_dirty_page,
        };
        Ok(())
    }

    /// Constract the boot source.
    pub fn build_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<(), BootSourceConfigError> {
        self.set_boot_source_config(boot_source_cfg);
        self.boot_source.builder = Some(BootConfig::new(self.boot_source_config())?);
        Ok(())
    }

    /// Set the boot source configuration.
    pub fn set_boot_source_config(&mut self, boot_source_cfg: BootSourceConfig) {
        self.boot_source.config = boot_source_cfg
    }

    /// Set the block devices builder.
    pub fn set_block_device_builder(
        &mut self,
        devices: Vec<BlockDeviceConfig>,
    ) -> Result<(), DriveError> {
        self.block = BlockDeviceBuilder::from(devices)?;
        Ok(())
    }

    ///
    pub fn boot_config(&self) -> &BootConfig {
        self.boot_source.builder.as_ref().unwrap()
    }

    /// Get
    pub fn boot_config_mut(&mut self) -> &mut BootConfig {
        self.boot_source.builder.as_mut().unwrap()
    }

    /// Get cmdline
    pub fn cmdline(&self) -> &linux_loader::cmdline::Cmdline {
        let boot_config = self.boot_config();
        &boot_config.cmdline
    }

    /// Get cmdline
    pub fn cmdline_mut(&mut self) -> &mut linux_loader::cmdline::Cmdline {
        let boot_config = self.boot_config_mut();
        &mut boot_config.cmdline
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ::utils::tempfile::TempFile;

    #[test]
    fn test_from_json() {
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();

        // Invalid JSON string must yield a `serde_json` error.
        match VmResources::from_json(r#"}"#) {
            Err(ResourcesError::InvalidJson(_)) => (),
            _ => unreachable!(),
        }

        // Valid JSON string without the configuration for kernel or rootfs
        // result in an invalid JSON error.
        match VmResources::from_json(r#"{}"#) {
            Err(ResourcesError::InvalidJson(_)) => (),
            _ => unreachable!(),
        }

        // Invalid JSON string that has invalid kernel_path.
        let mut json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "/invalid/path",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "{}",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 1,
                    "mem_size_mib": 128,
                    "track_dirty_page": false
                }}
            }}"#,
            rootfs_file.as_path().to_str().unwrap()
        );

        // The above invalid JSON string is expected to cause the InvalidKernelPath error.
        match VmResources::from_json(json.as_str()) {
            Err(ResourcesError::BootSource(BootSourceConfigError::InvalidKernelPath(_))) => (),
            _ => unreachable!(),
        }

        // Invalid JSON string that has invalid initrd path.
        json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "{}",
                    "initrd_path": "/invalid/path",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "{}",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 1,
                    "mem_size_mib": 128,
                    "track_dirty_page": false
                }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        // The above invalid JSON string is expected to cause the InvalidInitrdPath error
        match VmResources::from_json(json.as_str()) {
            Err(ResourcesError::BootSource(BootSourceConfigError::InvalidInitrdPath(_))) => (),
            _ => unreachable!(),
        }

        // Invalid JSON string that has invalid rootfs path.
        json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "/invalid/path",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 1,
                    "mem_size_mib": 128,
                    "track_dirty_page": false
                }}
            }}"#,
            kernel_file.as_path().to_str().unwrap()
        );

        // The above invalid JSON string is expected to cause the InvalidBlockDevicePath error.
        match VmResources::from_json(json.as_str()) {
            Err(ResourcesError::BlockDevice(DriveError::InvalidBlockDevicePath(_))) => (),
            _ => unreachable!(),
        }

        // Invalid JSON string that has invalid vcpu count.
        json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "{}",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 0,
                    "mem_size_mib": 128,
                    "track_dirty_page": false
                }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        // The above invalid JSON string is expected to cause the InvalidBlockDevicePath error.
        match VmResources::from_json(json.as_str()) {
            Err(ResourcesError::VmConfig(VmConfigError::InvalidVcpuCount)) => (),
            _ => unreachable!(),
        }

        // Invalid JSON string that has invalid memory size.
        json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "{}",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 1,
                    "mem_size_mib": 0,
                    "track_dirty_page": false
                }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        // The above invalid JSON string is expected to cause the InvalidMemorySize error.
        match VmResources::from_json(json.as_str()) {
            Err(ResourcesError::VmConfig(VmConfigError::InvalidMemorySize)) => (),
            _ => unreachable!(),
        }

        // Valid JSON string.
        json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1"
                }},
                "drives": [
                    {{
                        "path_on_host": "{}",
                        "is_root_device": true
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 1,
                    "mem_size_mib": 128,
                    "track_dirty_page": false
                }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        assert!(VmResources::from_json(json.as_str()).is_ok())
    }
}
