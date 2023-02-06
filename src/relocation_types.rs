#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub type RelocType = u32;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub type RelocType = u8;

pub enum RelocationType {
    Absolute,
    GlobalData,
    JumpSlot,
    Relative,
    Unknown(RelocType)
}

impl From<RelocType> for RelocationType {
    #[cfg(target_arch = "x86_64")]
    fn from(reloc: RelocType) -> RelocationType {
        match reloc {
            1 => RelocationType::Absolute,
            6 => RelocationType::GlobalData,
            7 => RelocationType::JumpSlot,
            8 => RelocationType::Relative,
            _ => RelocationType::Unknown(reloc)
        }
    }

    #[cfg(target_arch = "x86")]
    fn from(reloc: RelocType) -> RelocationType {
        match reloc {
            1 => RelocationType::Absolute,
            6 => RelocationType::GlobalData,
            7 => RelocationType::JumpSlot,
            8 => RelocationType::Relative,
            _ => RelocationType::Unknown(reloc)
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn from(reloc: RelocType) -> RelocationType {
        match reloc {
            257 => RelocationType::Absolute,
            1025 => RelocationType::GlobalData,
            1026 => RelocationType::JumpSlot,
            1027 => RelocationType::Relative,
            _ => RelocationType::Unknown(reloc)
        }
    }

    #[cfg(target_arch = "arm")]
    fn from(reloc: RelocType) -> RelocationType {
        match reloc {
            2 => RelocationType::Absolute,
            21 => RelocationType::GlobalData,
            22 => RelocationType::JumpSlot,
            23 => RelocationType::Relative,
            _ => RelocationType::Unknown(reloc)
        }
    }
}
