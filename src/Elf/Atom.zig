const Atom = @This();

const std = @import("std");
const elf = std.elf;
const mem = std.mem;

const Allocator = mem.Allocator;

/// Each decl always gets a local symbol with the fully qualified name.
/// The vaddr and size are found here directly.
/// The file offset is found by computing the vaddr offset from the section vaddr
/// the symbol references, and adding that to the file offset of the section.
/// If this field is 0, it means the codegen size = 0 and there is no symbol or
/// offset table entry.
local_sym_index: u32,

file: u32,

/// List of symbol aliases pointing to the same atom via different entries
aliases: std.ArrayListUnmanaged(u32) = .{},

/// List of symbols contained within this atom
contained: std.ArrayListUnmanaged(SymbolAtOffset) = .{},

/// Code (may be non-relocated) this atom represents
code: std.ArrayListUnmanaged(u8) = .{},

/// Alignment of this atom. Unlike in MachO, minimum alignment is 1.
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

pub fn createEmpty(allocator: *Allocator) !*Atom {
    const self = try allocator.create(Atom);
    self.* = .{
        .local_sym_index = 0,
        .file = undefined,
        .alignment = 0,
        .prev = null,
        .next = null,
    };
    return self;
}

pub fn deinit(self: *Atom, allocator: *Allocator) void {
    self.relocs.deinit(allocator);
    self.code.deinit(allocator);
    self.contained.deinit(allocator);
    self.aliases.deinit(allocator);
}

pub fn format(self: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    try std.fmt.format(writer, "Atom {{ ", .{});
    try std.fmt.format(writer, "  .local_sym_index = {d}, ", .{self.local_sym_index});
    try std.fmt.format(writer, "  .file = {d}, ", .{self.file});
    try std.fmt.format(writer, "  .aliases = {any}, ", .{self.aliases.items});
    try std.fmt.format(writer, "  .contained = {any}, ", .{self.contained.items});
    try std.fmt.format(writer, "  .code = {x}, ", .{std.fmt.fmtSliceHexLower(if (self.code.items.len > 64)
        self.code.items[0..64]
    else
        self.code.items)});
    try std.fmt.format(writer, "  .alignment = {d}, ", .{self.alignment});
    try std.fmt.format(writer, "  .relocs = {any}, ", .{self.relocs.items});
    try std.fmt.format(writer, "}}", .{});
}
