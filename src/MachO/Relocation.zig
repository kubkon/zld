tag: enum { @"extern", local },
offset: u32,
target: u32,
addend: i64,
type: Type,
meta: packed struct {
    pcrel: bool,
    has_subtractor: bool,
    length: u2,
    symbolnum: u24,
},

pub fn getTargetSymbol(rel: Relocation, macho_file: *MachO) *Symbol {
    assert(rel.tag == .@"extern");
    return macho_file.getSymbol(rel.target);
}

pub fn getTargetAtom(rel: Relocation, macho_file: *MachO) *Atom {
    assert(rel.tag == .local);
    return macho_file.getAtom(rel.target).?;
}

pub fn getTargetAddress(rel: Relocation, macho_file: *MachO) u64 {
    return switch (rel.tag) {
        .local => rel.getTargetAtom(macho_file).value,
        .@"extern" => rel.getTargetSymbol(macho_file).getAddress(.{}, macho_file),
    };
}

pub fn getGotTargetAddress(rel: Relocation, macho_file: *MachO) u64 {
    return switch (rel.tag) {
        .local => 0,
        .@"extern" => rel.getTargetSymbol(macho_file).getGotAddress(macho_file),
    };
}

pub inline fn getRelocAddend(rel: Relocation) u3 {
    return switch (rel.type) {
        .signed => 0,
        .signed1 => 1,
        .signed2 => 2,
        .signed4 => 4,
        else => 0,
    };
}

pub fn lessThan(ctx: void, lhs: Relocation, rhs: Relocation) bool {
    _ = ctx;
    return lhs.offset < rhs.offset;
}

pub const Type = enum {
    /// Represents either .X86_64_RELOC_SUBTRACTOR or .ARM64_RELOC_SUBTRACTOR
    subtractor,
    /// Represents either .X86_64_RELOC_UNSIGNED or .ARM64_RELOC_UNSIGNED
    unsigned,
    /// Represents either .X86_64_RELOC_BRANCH or .ARM64_RELOC_BRANCH26
    branch,
    /// Represents either .X86_64_RELOC_GOT or .ARM64_RELOC_POINTER_TO_GOT
    got,
    /// Represents .X86_64_RELOC_GOT_LOAD
    got_load,
    /// Represents .ARM64_RELOC_GOT_LOAD_PAGE21
    got_load_page,
    /// Represents .ARM64_RELOC_GOT_LOAD_PAGEOFF12
    got_load_pageoff,
    /// Represents .X86_64_RELOC_SIGNED
    signed,
    /// Represents .X86_64_RELOC_SIGNED_1
    signed1,
    /// Represents .X86_64_RELOC_SIGNED_2
    signed2,
    /// Represents .X86_64_RELOC_SIGNED_4
    signed4,
    /// Represents .ARM64_RELOC_PAGE21
    page,
    /// Represents .ARM64_RELOC_PAGEOFF12
    pageoff,
    /// Represents .X86_64_RELOC_TLV
    tlv,
    /// Represents .ARM64_RELOC_TLVP_PAGE21
    tlvp_page,
    /// Represents .ARM64_RELOC_TLVP_PAGEOFF12
    tlvp_pageoff,

    pub fn fromInt(raw: u4, arch: std.Target.Cpu.Arch) Type {
        return switch (arch) {
            .x86_64 => switch (@as(macho.reloc_type_x86_64, @enumFromInt(raw))) {
                .X86_64_RELOC_UNSIGNED => .unsigned,
                .X86_64_RELOC_SIGNED => .signed,
                .X86_64_RELOC_SIGNED_1 => .signed1,
                .X86_64_RELOC_SIGNED_2 => .signed2,
                .X86_64_RELOC_SIGNED_4 => .signed4,
                .X86_64_RELOC_BRANCH => .branch,
                .X86_64_RELOC_GOT_LOAD => .got_load,
                .X86_64_RELOC_GOT => .got,
                .X86_64_RELOC_SUBTRACTOR => .subtractor,
                .X86_64_RELOC_TLV => .tlv,
            },
            .aarch64 => switch (@as(macho.reloc_type_arm64, @enumFromInt(raw))) {
                .ARM64_RELOC_UNSIGNED => .unsigned,
                .ARM64_RELOC_SUBTRACTOR => .subtractor,
                .ARM64_RELOC_BRANCH26 => .branch,
                .ARM64_RELOC_PAGE21 => .page,
                .ARM64_RELOC_PAGEOFF12 => .pageoff,
                .ARM64_RELOC_GOT_LOAD_PAGE21 => .got_load_page,
                .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => .got_load_pageoff,
                .ARM64_RELOC_TLVP_LOAD_PAGE21 => .tlvp_page,
                .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => .tlvp_pageoff,
                .ARM64_RELOC_POINTER_TO_GOT => .got,
                .ARM64_RELOC_ADDEND => unreachable, // We make it part of addend field
            },
            else => unreachable,
        };
    }
};

const assert = std.debug.assert;
const macho = std.macho;
const std = @import("std");

const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Relocation = @This();
const Symbol = @import("Symbol.zig");
