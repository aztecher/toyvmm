/* automatically generated by rust-bindgen */

//actually, only kept the things currently borrowed by firecracker

pub const VIRTIO_F_VERSION_1: ::std::os::raw::c_uint = 32;

pub const VIRTIO_NET_F_CSUM: ::std::os::raw::c_uint = 0;
pub const VIRTIO_NET_F_GUEST_CSUM: ::std::os::raw::c_uint = 1;
pub const VIRTIO_NET_F_GUEST_TSO4: ::std::os::raw::c_uint = 7;
pub const VIRTIO_NET_F_GUEST_UFO: ::std::os::raw::c_uint = 10;
pub const VIRTIO_NET_F_HOST_TSO4: ::std::os::raw::c_uint = 11;
pub const VIRTIO_NET_F_HOST_UFO: ::std::os::raw::c_uint = 14;

pub type U8 = ::std::os::raw::c_uchar;
pub type U16 = ::std::os::raw::c_ushort;
pub type Virtio16 = U16;

impl Clone for virtio_net_hdr_v1 {
    fn clone(&self) -> Self {
        *self
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Copy)]
pub struct virtio_net_hdr_v1 {
    pub flags: U8,
    pub gso_type: U8,
    pub hdr_len: Virtio16,
    pub gso_size: Virtio16,
    pub csum_start: Virtio16,
    pub csum_offset: Virtio16,
    pub num_buffers: Virtio16,
}
