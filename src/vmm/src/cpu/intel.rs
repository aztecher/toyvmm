use super::{CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags, NormalizeCpuidError};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IntelCpuid(pub std::collections::BTreeMap<CpuidKey, CpuidEntry>);

impl CpuidTrait for IntelCpuid {
    fn get(&self, key: &CpuidKey) -> Option<&CpuidEntry> {
        self.0.get(key)
    }
    fn get_mut(&mut self, key: &CpuidKey) -> Option<&mut CpuidEntry> {
        self.0.get_mut(key)
    }
}

impl From<kvm_bindings::CpuId> for IntelCpuid {
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

impl IntelCpuid {
    pub fn normalize(
        &mut self,
        _cpu_index: u8,
        _cpu_count: u8,
        _cpus_per_core: u8,
    ) -> Result<(), NormalizeCpuidError> {
        Ok(())
    }
}
