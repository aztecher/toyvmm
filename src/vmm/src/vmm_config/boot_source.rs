// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::arch;
use serde::{Deserialize, Serialize};
use std::fs::File;

pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodules";

/// This represents part of the guest's configuration file in json format.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootSourceConfig {
    /// Path of the kernel image.
    pub kernel_path: String,
    /// Path of the initrd.
    pub initrd_path: Option<String>,
    /// The boot arguments to pass to the guest kernel.
    /// If this field is uninitialized, the default value is used:
    /// `reboot=k panic=1 pci=off nomodules`
    pub boot_args: Option<String>,
}

/// Errors associated with actions on `BootSourceConfig`.
#[derive(Debug, thiserror::Error)]
pub enum BootSourceConfigError {
    /// The kernel file cannot be opened.
    #[error("The kernel file cannot be opened: {0}")]
    InvalidKernelPath(std::io::Error),
    /// The initrd file cannot be opened.
    #[error("The initrd file cannot be opened: {0}")]
    InvalidInitrdPath(std::io::Error),
    /// The kernel command line is invalid.
    #[error("The kernel command line is invalid: {0}")]
    InvalidKernelCommandLine(String),
}

/// The guest's boot configuration from given configuration.
#[derive(Debug)]
pub struct BootConfig {
    /// The command line object.
    pub cmdline: linux_loader::cmdline::Cmdline,
    /// The descriptor to the kernel file.
    pub kernel_file: File,
    /// The descriptor to the initrd file.
    pub initrd_file: Option<File>,
}

/// The guest's builder from boot configuration.
#[derive(Debug, Default)]
pub struct BootSource {
    /// The boot source configuration.
    pub config: BootSourceConfig,
    /// The boot builder.
    pub builder: Option<BootConfig>,
}

impl BootConfig {
    /// Creates the BootConfig from given configuration.
    pub fn new(cfg: &BootSourceConfig) -> std::result::Result<Self, BootSourceConfigError> {
        use self::BootSourceConfigError::{
            InvalidInitrdPath, InvalidKernelCommandLine, InvalidKernelPath,
        };

        let kernel_file = File::open(&cfg.kernel_path).map_err(InvalidKernelPath)?;
        let initrd_file: Option<File> = match &cfg.initrd_path {
            Some(path) => Some(File::open(path).map_err(InvalidInitrdPath)?),
            None => None,
        };
        let cmdline_str = match cfg.boot_args.as_ref() {
            None => DEFAULT_KERNEL_CMDLINE,
            Some(str) => str.as_str(),
        };
        let cmdline =
            linux_loader::cmdline::Cmdline::try_from(cmdline_str, arch::x86_64::CMDLINE_MAX_SIZE)
                .map_err(|e| InvalidKernelCommandLine(e.to_string()))?;
        Ok(BootConfig {
            cmdline,
            kernel_file,
            initrd_file,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ::utils::tempfile::TempFile;

    #[test]
    fn test_boot_config() {
        let kernel_file = TempFile::new().unwrap();
        let kernel_path = kernel_file.as_path().to_str().unwrap().to_string();

        let boot_src_cfg = BootSourceConfig {
            kernel_path,
            initrd_path: None,
            boot_args: None,
        };
        let boot_cfg = BootConfig::new(&boot_src_cfg).unwrap();
        assert!(boot_cfg.initrd_file.is_none());
        assert_eq!(
            boot_cfg.cmdline.as_cstring().unwrap().as_bytes_with_nul(),
            [DEFAULT_KERNEL_CMDLINE.as_bytes(), &[b'\0']].concat()
        );
    }
}
