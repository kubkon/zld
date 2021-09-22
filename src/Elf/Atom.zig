const Atom = @This();

const std = @import("std");
const elf = std.elf;

/// Each decl always gets a local symbol with the fully qualified name.
/// The vaddr and size are found here directly.
/// The file offset is found by computing the vaddr offset from the section vaddr
/// the symbol references, and adding that to the file offset of the section.
/// If this field is 0, it means the codegen size = 0 and there is no symbol or
/// offset table entry.
local_sym_index: u32,

/// List of symbol aliases pointing to the same atom via different entries
aliases: std.ArrayListUnmanaged(u32) = .{},

/// List of symbols contained within this atom
contained: std.ArrayListUnmanaged(SymbolAtOffset) = .{},

/// Code (may be non-relocated) this atom represents
code: std.ArrayListUnmanaged(u8) = .{},

/// Alignment of this atom as a power of 2.
/// For instance, aligmment of 0 should be read as 2^0 = 1 byte aligned.
alignment: u32,

/// List of relocations belonging to this atom.
relocs: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},

/// Points to the previous and next neighbours
next: ?*Atom,
prev: ?*Atom,

pub const SymbolAtOffset = struct {
    local_sym_index: u32,
    offset: u64,

    pub fn format(
        self: SymbolAtOffset,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "{{ {d}: .offset = {d} }}", .{ self.local_sym_index, self.offset });
    }
};
