// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    common::get_vendor_id_from_host,
    cpuid, cpuid_count,
    normalize::{
        get_range, set_bit, set_range, ExtendedApicIdError, ExtendedCacheTopologyError,
        FeatureEntryError, PassthroughCacheTopologyError,
    },
    CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags, NormalizeCpuidError,
    BRAND_STRING_LENGTH, VENDOR_ID_AMD,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AmdCpuid(pub std::collections::BTreeMap<CpuidKey, CpuidEntry>);

impl CpuidTrait for AmdCpuid {
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry> {
        self.0.get(key)
    }

    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry> {
        self.0.get_mut(key)
    }
}

impl From<kvm_bindings::CpuId> for AmdCpuid {
    fn from(kvm_cpuid: kvm_bindings::CpuId) -> Self {
        let map = kvm_cpuid
            .as_slice()
            .iter()
            .map(|entry| {
                (
                    CpuidKey {
                        leaf: entry.function,
                        subleaf: entry.index,
                    },
                    CpuidEntry {
                        flags: KvmCpuidFlags(entry.flags),
                        result: CpuidRegisters {
                            eax: entry.eax,
                            ebx: entry.ebx,
                            ecx: entry.ecx,
                            edx: entry.edx,
                        },
                    },
                )
            })
            .collect();
        Self(map)
    }
}

impl AmdCpuid {
    /// We always use this brand string.
    const DEFAULT_BRAND_STRING: &[u8; BRAND_STRING_LENGTH] =
        b"AMD EPYC\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    pub fn normalize(
        &mut self,
        cpu_index: u8,
        cpu_count: u8,
        cpus_per_core: u8,
    ) -> Result<(), NormalizeCpuidError> {
        self.passthrough_cache_topology()?;
        self.update_structured_extended_entry()?;
        self.update_largest_extended_fn_entry()?;
        self.update_extended_feature_fn_entry()?;
        self.update_amd_feature_entry(cpu_count)?;
        self.update_extended_cache_topology_entry(cpu_count, cpus_per_core)?;
        self.update_extended_apic_id_entry(cpu_index, cpus_per_core)?;
        self.update_brand_string_entry()?;
        Ok(())
    }

    /// Passthrough cache topology.
    ///
    /// # Errors
    ///
    /// This function passes through leaves from the host CPUID, if this does not match the AMD
    /// specification it is possible to enter an indefinite loop. To avoid this, this will return an
    /// error when the host CPUID vendor id does not match the AMD CPUID vendor id.
    fn passthrough_cache_topology(&mut self) -> Result<(), PassthroughCacheTopologyError> {
        if get_vendor_id_from_host().map_err(PassthroughCacheTopologyError::NoVendorId)?
            != *VENDOR_ID_AMD
        {
            return Err(PassthroughCacheTopologyError::BadVendorId);
        }

        // Pass-through host CPUID for leaves 0x8000001e and 0x8000001d.
        {
            // 0x8000001e - Processor Topology Information
            self.0.insert(
                CpuidKey::leaf(0x8000001e),
                CpuidEntry {
                    flags: KvmCpuidFlags::EMPTY,
                    result: CpuidRegisters::from(cpuid(0x8000001e)),
                },
            );

            // 0x8000001d - Cache Topology Information
            for subleaf in 0.. {
                let result = CpuidRegisters::from(cpuid_count(0x8000001d, subleaf));
                // From 'AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose and System
                // Instructions':
                //
                // > To gather information for all cache levels, software must repeatedly execute
                // > CPUID with 8000_001Dh in EAX and ECX set to increasing values beginning with 0
                // > until a value of 00h is returned in the field CacheType (EAX[4:0]) indicating
                // > no more cache descriptions are available for this processor. If CPUID
                // > Fn8000_0001_ECX[TopologyExtensions] = 0, then CPUID Fn8000_001Dh is reserved.
                //
                // On non-AMD hosts this condition may never be true thus this loop may be
                // indefinite.

                // Cache type. Identifies the type of cache.
                // ```text
                // Bits Description
                // 00h Null; no more caches.
                // 01h Data cache
                // 02h Instruction cache
                // 03h Unified cache
                // 1Fh-04h Reserved.
                // ```
                //
                // cache_type: 0..4,
                let cache_type = result.eax & 15;
                if cache_type == 0 {
                    break;
                }
                self.0.insert(
                    CpuidKey::subleaf(0x8000001d, subleaf),
                    CpuidEntry {
                        flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                        result,
                    },
                );
            }
        }
        Ok(())
    }

    /// Update largest extended fn entry.
    #[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
    fn update_largest_extended_fn_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        // KVM sets the largest extended function to 0x80000000. Change it to 0x8000001f
        // Since we also use the leaf 0x8000001d (Extended Cache Topology).
        let leaf_80000000 = self
            .get_mut(&CpuidKey::leaf(0x80000000))
            .ok_or(NormalizeCpuidError::MissingLeaf0x80000000)?;

        // Largest extended function. The largest CPUID extended function input value supported by
        // the processor implementation.
        //
        // l_func_ext: 0..32,
        set_range(&mut leaf_80000000.result.eax, 0..32, 0x8000_001f).unwrap();
        Ok(())
    }

    /// Updated extended feature fn entry.
    fn update_extended_feature_fn_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        // set the Topology Extension bit since we use the Extended Cache Topology leaf
        let leaf_80000001 = self
            .get_mut(&CpuidKey::leaf(0x80000001))
            .ok_or(NormalizeCpuidError::MissingLeaf0x80000001)?;
        // Topology extensions support. Indicates support for CPUID Fn8000_001D_EAX_x[N:0]-CPUID
        // Fn8000_001E_EDX.
        //
        // topology_extensions: 22,
        set_bit(&mut leaf_80000001.result.ecx, 22, true);
        Ok(())
    }

    // Update structured extended feature entry.
    fn update_structured_extended_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        let leaf_7_subleaf_0 = self
            .get_mut(&CpuidKey::subleaf(0x7, 0x0))
            .ok_or(NormalizeCpuidError::MissingLeaf0x7Subleaf0)?;

        // According to AMD64 Architecture Programmer’s Manual, IA32_ARCH_CAPABILITIES MSR is not
        // available on AMD. The availability of IA32_ARCH_CAPABILITIES MSR is controlled via
        // CPUID.07H(ECX=0):EDX[bit 29]. KVM sets this bit no matter what but this feature is not
        // supported by hardware.
        set_bit(&mut leaf_7_subleaf_0.result.edx, 29, false);
        Ok(())
    }

    /// Update AMD feature entry.
    #[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
    fn update_amd_feature_entry(&mut self, cpu_count: u8) -> Result<(), FeatureEntryError> {
        /// This value allows at most 64 logical threads within a package.
        const THREAD_ID_MAX_SIZE: u32 = 7;

        // We don't support more then 128 threads right now.
        // It's safe to put them all on the same processor.
        let leaf_80000008 = self
            .get_mut(&CpuidKey::leaf(0x80000008))
            .ok_or(FeatureEntryError::MissingLeaf0x80000008)?;

        // APIC ID size. The number of bits in the initial APIC20[ApicId] value that indicate
        // logical processor ID within a package. The size of this field determines the
        // maximum number of logical processors (MNLP) that the package could
        // theoretically support, and not the actual number of logical processors that are
        // implemented or enabled in the package, as indicated by CPUID
        // Fn8000_0008_ECX[NC]. A value of zero indicates that legacy methods must be
        // used to determine the maximum number of logical processors, as indicated by
        // CPUID Fn8000_0008_ECX[NC].
        //
        // apic_id_size: 12..16,
        set_range(&mut leaf_80000008.result.ecx, 12..16, THREAD_ID_MAX_SIZE).unwrap();

        // Number of physical threads - 1. The number of threads in the processor is NT+1
        // (e.g., if NT = 0, then there is one thread). See “Legacy Method” on page 633.
        //
        // nt: 0..8,
        //
        let sub = cpu_count
            .checked_sub(1)
            .ok_or(FeatureEntryError::NumberOfPhysicalThreadsOverflow)?;
        set_range(&mut leaf_80000008.result.ecx, 0..8, u32::from(sub))
            .map_err(FeatureEntryError::NumberOfPhysicalThreads)?;

        Ok(())
    }

    /// Update extended cache topology entry.
    #[allow(clippy::unwrap_in_result, clippy::unwrap_used)]
    fn update_extended_cache_topology_entry(
        &mut self,
        cpu_count: u8,
        cpus_per_core: u8,
    ) -> Result<(), ExtendedCacheTopologyError> {
        for i in 0.. {
            if let Some(subleaf) = self.get_mut(&CpuidKey::subleaf(0x8000001d, i)) {
                // Cache level. Identifies the level of this cache. Note that the enumeration value
                // is not necessarily equal to the cache level.
                // ```text
                // Bits Description
                // 000b Reserved.
                // 001b Level 1
                // 010b Level 2
                // 011b Level 3
                // 111b-100b Reserved.
                // ```
                //
                // cache_level: 5..8
                let cache_level = get_range(subleaf.result.eax, 5..8);

                // Specifies the number of logical processors sharing the cache enumerated by N,
                // the value passed to the instruction in ECX. The number of logical processors
                // sharing this cache is the value of this field incremented by 1. To determine
                // which logical processors are sharing a cache, determine a Share
                // Id for each processor as follows:
                //
                // ShareId = LocalApicId >> log2(NumSharingCache+1)
                //
                // Logical processors with the same ShareId then share a cache. If
                // NumSharingCache+1 is not a power of two, round it up to the next power of two.
                //
                // num_sharing_cache: 14..26,

                match cache_level {
                    // L1 & L2 Cache
                    // The L1 & L2 cache is shared by at most 2 hyper-threads
                    1 | 2 => {
                        // SAFETY: We know `cpus_per_core > 0` therefore this is always safe.
                        let sub = u32::from(cpus_per_core.checked_sub(1).unwrap());
                        set_range(&mut subleaf.result.eax, 14..26, sub)
                            .map_err(ExtendedCacheTopologyError::NumSharingCache)?;
                    }
                    // L3 Cache
                    // The L3 cache is shared among all the logical threads
                    3 => {
                        let sub = cpu_count
                            .checked_sub(1)
                            .ok_or(ExtendedCacheTopologyError::NumSharingCacheOverflow)?;
                        set_range(&mut subleaf.result.eax, 14..26, u32::from(sub))
                            .map_err(ExtendedCacheTopologyError::NumSharingCache)?;
                    }
                    _ => (),
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Update extended apic id entry
    #[allow(clippy::unwrap_used, clippy::unwrap_in_result)]
    fn update_extended_apic_id_entry(
        &mut self,
        cpu_index: u8,
        cpus_per_core: u8,
    ) -> Result<(), ExtendedApicIdError> {
        /// 1 node per processor.
        const NODES_PER_PROCESSOR: u32 = 0;

        // When hyper-threading is enabled each pair of 2 consecutive logical CPUs
        // will have the same core id since they represent 2 threads in the same core.
        // For Example:
        // logical CPU 0 -> core id: 0
        // logical CPU 1 -> core id: 0
        // logical CPU 2 -> core id: 1
        // logical CPU 3 -> core id: 1
        //
        // SAFETY: We know `cpus_per_core != 0` therefore this is always safe.
        let core_id = u32::from(cpu_index.checked_div(cpus_per_core).unwrap());

        let leaf_8000001e = self
            .get_mut(&CpuidKey::leaf(0x8000001e))
            .ok_or(ExtendedApicIdError::MissingLeaf0x8000001e)?;

        // Extended APIC ID. If MSR0000_001B[ApicEn] = 0, this field is reserved.
        //
        // extended_apic_id: 0..32,
        set_range(&mut leaf_8000001e.result.eax, 0..32, u32::from(cpu_index))
            .map_err(ExtendedApicIdError::ExtendedApicId)?;

        // compute_unit_id: 0..8,
        set_range(&mut leaf_8000001e.result.ebx, 0..8, core_id)
            .map_err(ExtendedApicIdError::ComputeUnitId)?;

        // Threads per compute unit (zero-based count). The actual number of threads
        // per compute unit is the value of this field + 1. To determine which logical
        // processors (threads) belong to a given Compute Unit, determine a ShareId
        // for each processor as follows:
        //
        // ShareId = LocalApicId >> log2(ThreadsPerComputeUnit+1)
        //
        // Logical processors with the same ShareId then belong to the same Compute
        // Unit. (If ThreadsPerComputeUnit+1 is not a power of two, round it up to the
        // next power of two).
        //
        // threads_per_compute_unit: 8..16,
        //
        // SAFETY: We know `cpus_per_core > 0` therefore this is always safe.
        let sub = u32::from(cpus_per_core.checked_sub(1).unwrap());
        set_range(&mut leaf_8000001e.result.ebx, 8..16, sub)
            .map_err(ExtendedApicIdError::ThreadPerComputeUnit)?;

        // Specifies the number of nodes in the package/socket in which this logical
        // processor resides. Node in this context corresponds to a processor die.
        // Encoding is N-1, where N is the number of nodes present in the socket.
        //
        // nodes_per_processor: 8..11,
        //
        // SAFETY: We know the value always fits within the range and thus is always safe.
        // Set nodes per processor.
        set_range(&mut leaf_8000001e.result.ecx, 8..11, NODES_PER_PROCESSOR).unwrap();

        // Specifies the ID of the node containing the current logical processor. NodeId
        // values are unique across the system.
        //
        // node_id: 0..8,
        //
        // Put all the cpus in the same node.
        set_range(&mut leaf_8000001e.result.ecx, 0..8, 0).unwrap();

        Ok(())
    }

    /// Update brand string entry
    fn update_brand_string_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        self.apply_brand_string(Self::DEFAULT_BRAND_STRING)
            .map_err(NormalizeCpuidError::BrandString)?;
        Ok(())
    }
}
