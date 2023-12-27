// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem::{size_of, transmute};

pub mod amd;
pub mod common;
pub mod intel;
pub mod normalize;

pub use normalize::{FeatureInformationError, GetMaxCpusPerPackageError, NormalizeCpuidError};

/// Intel brand string.
pub const VENDOR_ID_INTEL: &[u8; 12] = b"GenuineIntel";

/// AMD brand string.
pub const VENDOR_ID_AMD: &[u8; 12] = b"AuthenticAMD";

/// Intel brand string.
#[allow(clippy::undocumented_unsafe_blocks)]
pub const VENDOR_ID_INTEL_STR: &str = unsafe { std::str::from_utf8_unchecked(VENDOR_ID_INTEL) };

/// AMD brand string.
#[allow(clippy::undocumented_unsafe_blocks)]
pub const VENDOR_ID_AMD_STR: &str = unsafe { std::str::from_utf8_unchecked(VENDOR_ID_AMD) };

/// To store the brand string we have 3 leaves, each with 4 registers, each with 4 bytes.
pub const BRAND_STRING_LENGTH: usize = 3 * 4 * 4;

/// Error type for [`apply_brand_string`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("Missing brand string leaves 0x80000002, 0x80000003 and 0x80000004.")]
pub struct MissingBrandStringLeaves;

/// Error type for conversion from `kvm_bindings::CpuId` to `Cpuid`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CpuidTryFromKvmCpuid {
    #[error("Leaf 0 not found in the given `kvm_bindings::CpuId`.")]
    MissingLeaf0,
    #[error("Unsupported CPUID manufacturer id: \"{0:?}\" (only 'GenuineIntel' and 'AuthenticAMD' are supported).")]
    UnsupportedVendor([u8; 12]),
}

/// Mimics of [`std::arch::x86_64::__cpuid`] that wraps [`cpuid_count1`]
fn cpuid(leaf: u32) -> std::arch::x86_64::CpuidResult {
    cpuid_count(leaf, 0)
}

/// Safe wrapper around [`std::arch::x86_64::__cpuid_count`].
fn cpuid_count(leaf: u32, subleaf: u32) -> std::arch::x86_64::CpuidResult {
    unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) }
}

pub trait CpuidTrait {
    fn vendor_id(&self) -> Option<[u8; 12]> {
        let leaf_0 = self.get(&CpuidKey::leaf(0x0))?;
        let (ebx, edx, ecx) = (
            leaf_0.result.ebx.to_ne_bytes(),
            leaf_0.result.edx.to_ne_bytes(),
            leaf_0.result.ecx.to_ne_bytes(),
        );
        let arr: [u8; 12] = [
            ebx[0], ebx[1], ebx[2], ebx[3], edx[0], edx[1], edx[2], edx[3], ecx[0], ecx[1], ecx[2],
            ecx[3],
        ];
        Some(arr)
    }
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry>;
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry>;

    /// Applies a given brand string to CPUID.
    ///
    /// # Errors
    ///
    /// When any of the leaves 0x80000002, 0x80000003 or 0x80000004 are not present.
    #[inline]
    fn apply_brand_string(
        &mut self,
        brand_string: &[u8; BRAND_STRING_LENGTH],
    ) -> Result<(), MissingBrandStringLeaves> {
        // 0x80000002
        {
            let leaf: &mut CpuidEntry = self
                .get_mut(&CpuidKey::leaf(0x80000002))
                .ok_or(MissingBrandStringLeaves)?;
            leaf.result.eax = u32::from_ne_bytes([
                brand_string[0],
                brand_string[1],
                brand_string[2],
                brand_string[3],
            ]);
            leaf.result.ebx = u32::from_ne_bytes([
                brand_string[4],
                brand_string[5],
                brand_string[6],
                brand_string[7],
            ]);
            leaf.result.ecx = u32::from_ne_bytes([
                brand_string[8],
                brand_string[9],
                brand_string[10],
                brand_string[11],
            ]);
            leaf.result.edx = u32::from_ne_bytes([
                brand_string[12],
                brand_string[13],
                brand_string[14],
                brand_string[15],
            ]);
        }

        // 0x80000003
        {
            let leaf: &mut CpuidEntry = self
                .get_mut(&CpuidKey::leaf(0x80000003))
                .ok_or(MissingBrandStringLeaves)?;
            leaf.result.eax = u32::from_ne_bytes([
                brand_string[16],
                brand_string[17],
                brand_string[18],
                brand_string[19],
            ]);
            leaf.result.ebx = u32::from_ne_bytes([
                brand_string[20],
                brand_string[21],
                brand_string[22],
                brand_string[23],
            ]);
            leaf.result.ecx = u32::from_ne_bytes([
                brand_string[24],
                brand_string[25],
                brand_string[26],
                brand_string[27],
            ]);
            leaf.result.edx = u32::from_ne_bytes([
                brand_string[28],
                brand_string[29],
                brand_string[30],
                brand_string[31],
            ]);
        }

        // 0x80000004
        {
            let leaf: &mut CpuidEntry = self
                .get_mut(&CpuidKey::leaf(0x80000004))
                .ok_or(MissingBrandStringLeaves)?;
            leaf.result.eax = u32::from_ne_bytes([
                brand_string[32],
                brand_string[33],
                brand_string[34],
                brand_string[35],
            ]);
            leaf.result.ebx = u32::from_ne_bytes([
                brand_string[36],
                brand_string[37],
                brand_string[38],
                brand_string[39],
            ]);
            leaf.result.ecx = u32::from_ne_bytes([
                brand_string[40],
                brand_string[41],
                brand_string[42],
                brand_string[43],
            ]);
            leaf.result.edx = u32::from_ne_bytes([
                brand_string[44],
                brand_string[45],
                brand_string[46],
                brand_string[47],
            ]);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuidKey {
    pub leaf: u32,
    pub subleaf: u32,
}

impl CpuidKey {
    pub fn leaf(leaf: u32) -> Self {
        Self { leaf, subleaf: 0 }
    }

    pub fn subleaf(leaf: u32, subleaf: u32) -> Self {
        Self { leaf, subleaf }
    }
}

impl std::cmp::PartialOrd for CpuidKey {
    #[allow(clippy::incorrect_partial_ord_impl_on_ord_type)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.leaf
                .cmp(&other.leaf)
                .then(self.subleaf.cmp(&other.subleaf)),
        )
    }
}

impl std::cmp::Ord for CpuidKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.leaf
            .cmp(&other.leaf)
            .then(self.subleaf.cmp(&other.subleaf))
    }
}

/// Definition from 'kvm/arch/x86/include/uapi/asm/kvm.h'
#[derive(
    Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash,
)]
pub struct KvmCpuidFlags(pub u32);
impl KvmCpuidFlags {
    /// Zero
    pub const EMPTY: Self = Self(0);
    /// Indicates if the `inbox` field is used for indexing sub-leaves (if false, this CPUID leaf
    /// has no subleaves).
    pub const SIGNIFICANT_INDEX: Self = Self(1 << 0);
}

#[allow(clippy::derivable_impls)]
impl Default for KvmCpuidFlags {
    fn default() -> Self {
        Self(0)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct CpuidRegisters {
    /// EAX
    pub eax: u32,
    /// EBX
    pub ebx: u32,
    /// ECX
    pub ecx: u32,
    /// EDX
    pub edx: u32,
}

impl From<core::arch::x86_64::CpuidResult> for CpuidRegisters {
    fn from(
        core::arch::x86_64::CpuidResult { eax, ebx, ecx, edx }: core::arch::x86_64::CpuidResult,
    ) -> Self {
        Self { eax, ebx, ecx, edx }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct CpuidEntry {
    pub flags: KvmCpuidFlags,
    pub result: CpuidRegisters,
}

impl CpuidTrait for kvm_bindings::CpuId {
    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn get(&self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&CpuidEntry> {
        let entry_opt = self
            .as_slice()
            .iter()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);

        entry_opt.map(|entry| {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: The `kvm_cpuid_entry2` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &[u8; size_of::<kvm_bindings::kvm_cpuid_entry2>()] = transmute(entry);
                let arr2: &[u8; size_of::<CpuidEntry>()] = arr[8..28].try_into().unwrap();
                transmute::<_, &CpuidEntry>(arr2)
            }
        })
    }

    /// Gets a given sub-leaf.
    #[allow(clippy::transmute_ptr_to_ptr, clippy::unwrap_used)]
    #[inline]
    fn get_mut(&mut self, CpuidKey { leaf, subleaf }: &CpuidKey) -> Option<&mut CpuidEntry> {
        let entry_opt = self
            .as_mut_slice()
            .iter_mut()
            .find(|entry| entry.function == *leaf && entry.index == *subleaf);
        entry_opt.map(|entry| {
            // JUSTIFICATION: There is no safe alternative.
            // SAFETY: The `kvm_cpuid_entry2` and `CpuidEntry` are `repr(C)` with known sizes.
            unsafe {
                let arr: &mut [u8; size_of::<kvm_bindings::kvm_cpuid_entry2>()] = transmute(entry);
                let arr2: &mut [u8; size_of::<CpuidEntry>()] =
                    (&mut arr[8..28]).try_into().unwrap();
                transmute::<_, &mut CpuidEntry>(arr2)
            }
        })
    }
}

/// CPUID information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cpuid {
    /// Intel CPUID specific information.
    Intel(intel::IntelCpuid),
    /// AMD CPUID specific information.
    Amd(amd::AmdCpuid),
}

impl Cpuid {
    pub fn inner(&self) -> &std::collections::BTreeMap<CpuidKey, CpuidEntry> {
        match self {
            Self::Intel(intel_cpuid) => &intel_cpuid.0,
            Self::Amd(amd_cpuid) => &amd_cpuid.0,
        }
    }
    pub fn inner_mut(&mut self) -> &mut std::collections::BTreeMap<CpuidKey, CpuidEntry> {
        match self {
            Self::Intel(intel_cpuid) => &mut intel_cpuid.0,
            Self::Amd(amd_cpuid) => &mut amd_cpuid.0,
        }
    }
}

impl TryFrom<kvm_bindings::CpuId> for Cpuid {
    type Error = CpuidTryFromKvmCpuid;

    fn try_from(kvm_cpuid: kvm_bindings::CpuId) -> Result<Self, Self::Error> {
        let vendor_id = kvm_cpuid
            .vendor_id()
            .ok_or(CpuidTryFromKvmCpuid::MissingLeaf0)?;
        match std::str::from_utf8(&vendor_id) {
            Ok(VENDOR_ID_INTEL_STR) => Ok(Cpuid::Intel(intel::IntelCpuid::from(kvm_cpuid))),
            Ok(VENDOR_ID_AMD_STR) => Ok(Cpuid::Amd(amd::AmdCpuid::from(kvm_cpuid))),
            _ => Err(CpuidTryFromKvmCpuid::UnsupportedVendor(vendor_id)),
        }
    }
}

impl TryFrom<Cpuid> for kvm_bindings::CpuId {
    type Error = utils::fam::Error;

    fn try_from(cpuid: Cpuid) -> Result<Self, Self::Error> {
        let entries = cpuid
            .inner()
            .iter()
            .map(|(key, entry)| kvm_bindings::kvm_cpuid_entry2 {
                function: key.leaf,
                index: key.subleaf,
                flags: entry.flags.0,
                eax: entry.result.eax,
                ebx: entry.result.ebx,
                ecx: entry.result.ecx,
                edx: entry.result.edx,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        kvm_bindings::CpuId::from_entries(&entries)
    }
}

impl CpuidTrait for Cpuid {
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry> {
        match self {
            Self::Intel(intel_cpuid) => intel_cpuid.get(key),
            Self::Amd(amd_cpuid) => amd_cpuid.get(key),
        }
    }
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry> {
        match self {
            Self::Intel(intel_cpuid) => intel_cpuid.get_mut(key),
            Self::Amd(amd_cpuid) => amd_cpuid.get_mut(key),
        }
    }
}
