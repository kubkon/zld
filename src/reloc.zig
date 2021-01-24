pub const reloc_type_arm64 = extern enum(u4) {
    /// For pointers.
    ARM64_RELOC_UNSIGNED = 0,

    /// Must be followed by a ARM64_RELOC_UNSIGNED.
    ARM64_RELOC_SUBTRACTOR,

    /// A B/BL instruction with 26-bit displacement.
    ARM64_RELOC_BRANCH26,

    /// Pc-rel distance to page of target.
    ARM64_RELOC_PAGE21,

    /// Offset within page, scaled by r_length.
    ARM64_RELOC_PAGEOFF12,

    /// Pc-rel distance to page of GOT slot.
    ARM64_RELOC_GOT_LOAD_PAGE21,

    /// Offset within page of GOT slot, scaled by r_length.
    ARM64_RELOC_GOT_LOAD_PAGEOFF12,

    /// For pointers to GOT slots.
    ARM64_RELOC_POINTER_TO_GOT,

    /// Pc-rel distance to page of TLVP slot.
    ARM64_RELOC_TLVP_LOAD_PAGE21,

    /// Offset within page of TLVP slot, scaled by r_length.
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12,

    /// Must be followed by PAGE21 or PAGEOFF12.
    ARM64_RELOC_ADDEND,
};

/// Format of a relocation entry of a Mach-O file.  Modified from the 4.3BSD
/// format.  The modifications from the original format were changing the value
/// of the r_symbolnum field for "local" (r_extern == 0) relocation entries.
/// This modification is required to support symbols in an arbitrary number of
/// sections not just the three sections (text, data and bss) in a 4.3BSD file.
/// Also the last 4 bits have had the r_type tag added to them.
pub const relocation_info = packed struct {
    /// Offset in the section to what is being relocated.
    r_address: i32,

    /// Symbol index if r_extern == 1 or section ordinal if r_extern == 0.
    r_symbolnum: u24,

    /// Was relocated pc relative already.
    r_pcrel: u1,

    /// 0=byte, 1=word, 2=long, 3=quad.
    r_length: u2,

    /// Does not include value of sym referenced.
    r_extern: u1,

    /// If not 0, machine specific relocations type.
    r_type: u4,
};
