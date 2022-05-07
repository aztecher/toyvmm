use serde::{de, Deserialize, Serialize};
use std::fs::File;
use std::fmt;

use crate::{
    arch,
    kvm::vcpu::VcpuConfig,
};

type Result<E> = std::result::Result<(), E>;
pub const DEFAULT_MEM_SIZE_MIB: usize = 128;
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 \
                                          i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";

#[derive(Debug)]
pub enum Error {
    InvalidJson(serde_json::Error),
    VmConfig(VmConfigError),
}

#[derive(Debug, PartialEq)]
pub enum VmConfigError {
    InvalidMemorySize,
    InvalidVcpuCount,
}

impl fmt::Display for VmConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmConfigError::*;
        match *self {
            InvalidMemorySize => write!(f, "The memory size (MiGB) is invalid."),
            InvalidVcpuCount => write!(f, "The vCpu number is invalid."),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VmConfig {
    pub vcpu_count: u8,
    pub mem_size_mib: usize,
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

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct VmmConfig {
}


#[derive(Default)]
pub struct VmResources {
    vm_config: VmConfig,
    boot_config: Option<BootConfig>,
}

impl VmResources {
    pub fn from_json(
        config_json: &str,
    ) -> std::result::Result<Self, Error> {
        // let vm_config: VmmConfig = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
        //     .map_err(Error::InvalidJson)?;
        let resources: Self = Self::default();
        Ok(resources)
    }

    pub fn vcpu_config(&self) -> VcpuConfig {
        VcpuConfig {
            vcpu_count: self.vm_config().vcpu_count,
        }
    }

    pub fn track_dirty_pages(&self) -> bool {
        self.vm_config().track_dirty_page
    }

    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    pub fn boot_source(&self) -> Option<&BootConfig> {
        self.boot_config.as_ref()
    }

    pub fn set_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<BootSourceConfigError> {
        self.boot_config = Some(BootConfig::new(boot_source_cfg)?);
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct BootSourceConfig {
    pub kernel_image_path: String,
    pub initrd_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

impl From<&BootConfig> for BootSourceConfig {
    fn from(cfg: &BootConfig) -> Self {
        cfg.description.clone()
    }
}

#[derive(Debug)]
pub enum BootSourceConfigError {
    InvalidKernelPath(std::io::Error),
    InvalidInitrdPath(std::io::Error),
    InvalidKernelCommandLine(String),
}

impl fmt::Display for BootSourceConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BootSourceConfigError::*;
        match *self {
            InvalidKernelPath(ref e) => write!(
                f,
                "The kernel file cannot be opened: {}",
                e,
            ),
            InvalidInitrdPath(ref e) => write!(
                f,
                "The initrd file cannot be opened due to invalid path or \
                 invalid permissions. {}",
                e,
            ),
            InvalidKernelCommandLine(ref e) => write!(
                f,
                "The kernel command line is invalid: {}",
                e.as_str(),
            )
        }
    }
}

pub struct BootConfig {
    pub cmdline: linux_loader::cmdline::Cmdline,
    pub kernel_file: File,
    pub initrd_file: Option<File>,
    pub description: BootSourceConfig
}

impl BootConfig {
    pub fn new(cfg: BootSourceConfig) -> std::result::Result<Self, BootSourceConfigError> {
        use self::BootSourceConfigError::*;

        let kernel_file = File::open(&cfg.kernel_image_path)
            .map_err(InvalidKernelPath)?;
        let initrd_file: Option<File> = match &cfg.initrd_path {
            Some(path) => Some(File::open(path).map_err(InvalidInitrdPath)?),
            None => None,
        };
        let mut cmdline = linux_loader::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        let boot_args = match cfg.boot_args.as_ref() {
            None => DEFAULT_KERNEL_CMDLINE,
            Some(str) => str.as_str(),
        };
        cmdline
            .insert_str(boot_args)
            .map_err(|e| InvalidKernelCommandLine(e.to_string()))?;
        Ok(BootConfig {
            cmdline,
            kernel_file,
            initrd_file,
            description: cfg,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{VmResources, VmConfig, BootConfig, DEFAULT_KERNEL_CMDLINE};

    pub fn create_vm_resources() -> VmResources {
        VmResources {
            vm_config: VmConfig::default(),
            boot_config: Some(default_boot_config()),
        }
    }
    
    fn default_boot_config() -> BootConfig {
        use vmm_sys_util::tempfile::TempFile;
        use std::fs::File;
    
        let mut kernel_cmdline = linux_loader::cmdline::Cmdline::new(4096);
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
        let tmp_file = TempFile::new().unwrap();
        BootConfig {
            cmdline: kernel_cmdline,
            kernel_file: File::open(tmp_file.as_path()).unwrap(),
            initrd_file: Some(File::open(tmp_file.as_path()).unwrap()),
            description: Default::default(),
        }
    }
}
