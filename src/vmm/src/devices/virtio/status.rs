// [Device Status Field](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html#x1-110001)
pub const ACKNOWLEDGE: u32 = 0x01;
pub const DRIVER: u32 = 0x02;
pub const FAILED: u32 = 0x80; // 128
pub const FEATURES_OK: u32 = 0x08;
pub const DRIVER_OK: u32 = 0x04;
pub const DEVICE_NEEDS_RESET: u32 = 0x40; // 64
