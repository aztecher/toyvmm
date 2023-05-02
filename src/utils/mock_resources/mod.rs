use std::path::PathBuf;
use crate::vm_resources::{VmResources, BootSourceConfig, VmConfig};

// pub const DEFAULT_BOOT_ARGS: &str = "reboot=k panic=1 pci=off";
// pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";
pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0";
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_KERNEL_IMAGE: &str = "test_elf.bin";

fn kernel_image_path(kernel_image: Option<&str>) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src/utils/mock_resources");
    path.push(kernel_image.unwrap_or(DEFAULT_KERNEL_IMAGE));
    path.as_os_str().to_str().unwrap().to_string()
}

pub struct MockBootSourceConfig(BootSourceConfig);

impl MockBootSourceConfig {
    pub fn new() -> MockBootSourceConfig {
        MockBootSourceConfig(BootSourceConfig {
            kernel_image_path: kernel_image_path(None),
            initrd_path: None,
            boot_args: None,
        })
    }

    pub fn with_default_boot_args(mut self) -> Self {
        self.0.boot_args = Some(DEFAULT_BOOT_ARGS.to_string());
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_kernel(mut self, kernel_image: &str) -> Self {
        self.0.kernel_image_path = kernel_image_path(Some(kernel_image));
        self
    }
}

impl Default for MockBootSourceConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct MockVmResources(VmResources);

impl MockVmResources {
    pub fn new() -> MockVmResources {
        MockVmResources::default()
    }

    pub fn with_boot_source(mut self, boot_source_cfg: BootSourceConfig) -> Self {
        self.0.set_boot_source(boot_source_cfg).unwrap();
        self
    }
}

#[derive(Default)]
pub struct MockVmConfig(VmConfig);

impl MockVmConfig {
    pub fn new() -> MockVmConfig {
        MockVmConfig::default()
    }

    pub fn with_dirty_page_tracking(mut self) -> Self {
        self.0.track_dirty_page = true;
        self
    }
}

// automatically implement From trait
macro_rules! generate_from {
    ($src_type: ty, $dst_type: ty) => {
        impl From<$src_type> for $dst_type {
            fn from(src: $src_type) -> $dst_type {
                src.0
            }
        }
    };
}

generate_from!(MockBootSourceConfig, BootSourceConfig);
generate_from!(MockVmResources, VmResources);
generate_from!(MockVmConfig, VmConfig);
