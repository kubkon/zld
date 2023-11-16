/// Address allocated for this Atom.
value: u64 = 0,

/// Name of this Atom.
name: u32 = 0,

/// Index into linker's input file table.
file: File.Index = 0,

/// Size of this atom
size: u64 = 0,

/// Alignment of this atom as a power of two.
alignment: u8 = 0,

/// Index of the input section.
n_sect: u32 = 0,

/// Index of the output section.
out_n_sect: u16 = 0,

relocs: Loc = .{},

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

flags: Flags = .{},

pub fn getName(self: Atom, macho_file: *MachO) [:0]const u8 {
    return macho_file.string_intern.getAssumeExists(self.name);
}

pub fn getObject(self: Atom, macho_file: *MachO) *Object {
    return macho_file.getFile(self.file).?.object;
}

pub fn getInputSection(self: Atom, macho_file: *MachO) macho.section_64 {
    const object = self.getObject(macho_file);
    return object.sections[self.n_sect];
}

pub fn getPriority(self: Atom, macho_file: *MachO) u64 {
    const object = self.getObject(macho_file);
    return (@as(u64, @intCast(object.index)) << 32) | @as(u64, @intCast(self.n_sect));
}

pub fn getRelocs(self: Atom, macho_file: *MachO) []const macho.relocation_info {
    const object = self.getObject(macho_file);
    return object.relocations.items[self.relocs.pos..][0..self.relocs.len];
}

pub fn format(
    atom: Atom,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = atom;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format symbols directly");
}

pub fn fmt(atom: Atom, macho_file: *MachO) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .macho_file = macho_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
    macho_file: *MachO,
};

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const atom = ctx.atom;
    const macho_file = ctx.macho_file;
    try writer.print("atom({d}) : {s} : @{x} : sect({d}) : align({x}) : size({x})", .{
        atom.atom_index, atom.getName(macho_file), atom.value,
        atom.out_n_sect, atom.alignment,           atom.size,
    });
    if (macho_file.options.dead_strip and !atom.flags.alive) {
        try writer.writeAll(" : [*]");
    }
}

pub const Index = u32;

pub const Flags = packed struct {
    /// Specifies whether this atom is alive or has been garbage collected.
    alive: bool = true,

    /// Specifies if the atom has been visited during garbage collection.
    visited: bool = false,
};

const Loc = struct {
    pos: usize = 0,
    len: usize = 0,
};

const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const macho = std.macho;
const log = std.log.scoped(.link);
const relocs_log = std.log.scoped(.relocs);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
