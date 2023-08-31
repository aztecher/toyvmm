use serde::{Deserialize, Serialize};
use std::fs::File;

/// Errors associated with actions on `BlockDeviceConfig`
#[derive(Debug, thiserror::Error)]
pub enum DriveError {
    /// The block device path is invalid.
    #[error("Invalid block device path: {0}")]
    InvalidBlockDevicePath(std::io::Error),
    /// A root block device was already exists.
    #[error("A root block device already exists!")]
    RootBlockDeviceAlreadyExists,
}

/// This represents part of the guest's configuration file in json format.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockDeviceConfig {
    /// Path of the drive.
    pub path_on_host: String,
    /// If set true, this device is mounted as /dev/vda on the guest.
    pub is_root_device: bool,
}

/// Wrapper for the block device collections.
///
/// TODO)
/// We would like to initialize and list the Block structure from BlockDeviceConfig /// when this structure is initialized, but due to the way EventFd is handled,
/// this cannot be accomplished without significant changes to the current code.
/// Therefore, in the current implementation, BlockDeviceConfig should be retained
/// so that it can be converted to a Block structure when necessary.
#[derive(Debug, Default)]
pub struct BlockDeviceBuilder {
    /// The collections of block device.
    pub devices: Vec<BlockDeviceConfig>,
}

impl BlockDeviceBuilder {
    pub fn from(devices: Vec<BlockDeviceConfig>) -> Result<Self, DriveError> {
        for dev in devices.iter() {
            // Only try to open device file on host for input validation.
            File::open(dev.path_on_host.as_str()).map_err(DriveError::InvalidBlockDevicePath)?;
        }
        Ok(BlockDeviceBuilder { devices })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::utils::tempfile::TempFile;

    #[test]
    fn test_block_device_builder() {
        let drive_file = TempFile::new().unwrap();
        // Invalid input of 'path_on_host'
        let mut devices = vec![BlockDeviceConfig {
            path_on_host: String::from("/invalid/path"),
            is_root_device: false,
        }];

        // The above invalid input expected to cause the InvalidBlockDevicePath.
        match BlockDeviceBuilder::from(devices) {
            Err(DriveError::InvalidBlockDevicePath(_)) => (),
            _ => unreachable!(),
        }

        // Valid input.
        devices = vec![BlockDeviceConfig {
            path_on_host: drive_file.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
        }];

        assert!(BlockDeviceBuilder::from(devices).is_ok())
    }
}
