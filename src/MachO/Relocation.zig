tag: enum { @"extern", local },
offset: u32,
target: u32,
addend: i64,
meta: packed struct {
    pcrel: bool,
    length: u2,
    type: u4,
    symbolnum: u24,
    has_subtractor: bool,
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

pub fn lessThan(ctx: void, lhs: Relocation, rhs: Relocation) bool {
    _ = ctx;
    return lhs.offset < rhs.offset;
}

const assert = std.debug.assert;
const std = @import("std");

const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Relocation = @This();
const Symbol = @import("Symbol.zig");
