/// Allocated address for this Atom.
/// Value is relative to the output section address.
/// Use `getAddress()` to get full absolute address of this Atom.
value: u64 = 0,

/// Name of this Atom.
name: u32 = 0,

/// Index into linker's input file table.
file: File.Index = 0,

/// Size of this Atom.
size: u64 = 0,

/// Alignment of this Atom as a power of 2.
alignment: u32 = 0,

/// Index of the input section.
section_number: u16 = 0,

/// Index of the output section.
out_section_number: u16 = 0,

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

flags: Flags = .{},

pub fn getName(self: Atom, coff_file: *Coff) [:0]const u8 {
    return self.getObject(coff_file).getString(self.name);
}

pub fn getObject(self: Atom, coff_file: *Coff) *Object {
    return coff_file.getFile(self.file).?.object;
}

pub fn getInputSection(self: Atom, coff_file: *Coff) Object.SectionHeader {
    assert(self.section_number > 0);
    const object = self.getObject(coff_file);
    return object.sections.items(.header)[self.section_number - 1];
}

pub fn getAddress(self: Atom, coff_file: *Coff) u64 {
    if (self.out_section_number == 0) return self.value;
    const header = coff_file.sections.items(.header)[self.out_section_number];
    return header.virtual_address + self.value;
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
    @compileError("do not format Atom directly");
}

pub fn fmt(atom: Atom, coff_file: *Coff) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .coff_file = coff_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
    coff_file: *Coff,
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
    const coff_file = ctx.coff_file;
    try writer.print("atom({d}) : {s} : @{x} : sect({d}) : align({x}) : size({x})", .{
        atom.atom_index,         atom.getName(coff_file), atom.getAddress(coff_file),
        atom.out_section_number, atom.alignment,          atom.size,
    });
    if (!atom.flags.alive) try writer.writeAll(" : [*]");
}

pub const Index = u32;

pub const Flags = packed struct {
    /// Specifies whether this atom is alive or has been garbage collected.
    alive: bool = true,

    /// Specifies if the atom has been visited during garbage collection.
    visited: bool = false,
};

const assert = std.debug.assert;
const coff = std.coff;
const std = @import("std");

const Atom = @This();
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const Object = @import("Object.zig");
