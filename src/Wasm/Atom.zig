const Atom = @This();

const std = @import("std");
const types = @import("types.zig");
const Wasm = @import("../Wasm.zig");
const Symbol = @import("Symbol.zig");

const leb = std.leb;
const log = std.log.scoped(.wasm);
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Index = enum(u32) {
    none = std.math.maxInt(u32),
    _,
};

/// Local symbol index
sym_index: u32,
/// Index into a list of object files
file: ?u16,
/// Size of the atom, used to calculate section sizes in the final binary
size: u32,
/// List of relocations belonging to this atom
relocs: []const types.Relocation = &.{},
/// Contains the binary data of an atom, which can be non-relocated
data: [*]u8,
/// For code this is 1, for data this is set to the highest value of all segments
alignment: u32,
/// Offset into the section where the atom lives, this already accounts
/// for alignment.
offset: u32,
/// The original offset within the object file. This value is substracted from
/// relocation offsets to determine where in the `data` to rewrite the value
original_offset: u32,
/// Previous atom in relation to this atom.
/// is null when this atom is the first in its order
prev: Index,

/// Represents a default empty wasm `Atom`
pub const empty: Atom = .{
    .alignment = 0,
    .file = null,
    .offset = 0,
    .prev = .none,
    .size = 0,
    .sym_index = undefined,
    .data = undefined,
    .original_offset = 0,
};

/// Returns an `Atom` from a given index. Asserts index is not `none`.
pub fn fromIndex(wasm: *const Wasm, index: Atom.Index) Atom {
    std.debug.assert(index != .none);
    return wasm.managed_atoms.items[@intFromEnum(index)];
}

/// Returns a pointer to an `Atom` in the managed atoms list from a given `Index`.
/// Asserts index is not `none`.
pub fn ptrFromIndex(wasm: *const Wasm, index: Atom.Index) *Atom {
    std.debug.assert(index != .none);
    return &wasm.managed_atoms.items[@intFromEnum(index)];
}

pub fn format(atom: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    writer.print("Atom{{ .sym_index = {d}, .alignment = {d}, .size = {d}, .offset = 0x{x:0>8} }}", .{
        atom.sym_index,
        atom.alignment,
        atom.size,
        atom.offset,
    });
}

/// Returns the location of the symbol that represents this `Atom`
pub fn symbolLoc(atom: *const Atom) Wasm.SymbolWithLoc {
    return .{ .file = atom.file, .sym_index = atom.sym_index };
}

/// Resolves the relocations within the atom, writing the new value
/// at the calculated offset.
pub fn resolveRelocs(atom: *Atom, wasm_bin: *const Wasm) void {
    if (atom.relocs.len == 0) return;

    for (atom.relocs) |reloc| {
        const value = atom.relocationValue(reloc, wasm_bin);
        switch (reloc.relocation_type) {
            .R_WASM_TABLE_INDEX_I32,
            .R_WASM_FUNCTION_OFFSET_I32,
            .R_WASM_GLOBAL_INDEX_I32,
            .R_WASM_MEMORY_ADDR_I32,
            .R_WASM_SECTION_OFFSET_I32,
            => std.mem.writeInt(u32, atom.data[reloc.offset - atom.original_offset ..][0..4], @as(u32, @truncate(value)), .little),
            .R_WASM_TABLE_INDEX_I64,
            .R_WASM_MEMORY_ADDR_I64,
            => std.mem.writeInt(u64, atom.data[reloc.offset - atom.original_offset ..][0..8], value, .little),
            .R_WASM_GLOBAL_INDEX_LEB,
            .R_WASM_EVENT_INDEX_LEB,
            .R_WASM_FUNCTION_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_LEB,
            .R_WASM_MEMORY_ADDR_SLEB,
            .R_WASM_TABLE_INDEX_SLEB,
            .R_WASM_TABLE_NUMBER_LEB,
            .R_WASM_TYPE_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_TLS_SLEB,
            => leb.writeUnsignedFixed(5, atom.data[reloc.offset - atom.original_offset ..][0..5], @as(u32, @truncate(value))),
            .R_WASM_MEMORY_ADDR_LEB64,
            .R_WASM_MEMORY_ADDR_SLEB64,
            .R_WASM_TABLE_INDEX_SLEB64,
            .R_WASM_MEMORY_ADDR_TLS_SLEB64,
            => leb.writeUnsignedFixed(10, atom.data[reloc.offset - atom.original_offset ..][0..10], value),
        }
    }
}

/// From a given `relocation` will return the new value to be written.
/// All values will be represented as a `u64` as all values can fit within it.
/// The final value must be casted to the correct size.
fn relocationValue(atom: *Atom, relocation: types.Relocation, wasm_bin: *const Wasm) u64 {
    const target_loc = (Wasm.SymbolWithLoc{ .file = atom.file, .sym_index = relocation.index }).finalLoc(wasm_bin);
    const symbol = target_loc.getSymbol(wasm_bin);

    if (relocation.relocation_type != .R_WASM_TYPE_INDEX_LEB and
        symbol.tag != .section and
        symbol.isDead())
    {
        const val = atom.thombstone(wasm_bin) orelse relocation.addend;
        return @bitCast(val);
    }
    switch (relocation.relocation_type) {
        .R_WASM_FUNCTION_INDEX_LEB => return symbol.index,
        .R_WASM_TABLE_NUMBER_LEB => return symbol.index,
        .R_WASM_TABLE_INDEX_I32,
        .R_WASM_TABLE_INDEX_I64,
        .R_WASM_TABLE_INDEX_SLEB,
        .R_WASM_TABLE_INDEX_SLEB64,
        => return wasm_bin.elements.indirect_functions.get(target_loc) orelse 0,
        .R_WASM_TYPE_INDEX_LEB => {
            const original_type = wasm_bin.objects.items[atom.file.?].func_types[relocation.index];
            return wasm_bin.func_types.find(original_type).?;
        },
        .R_WASM_GLOBAL_INDEX_I32,
        .R_WASM_GLOBAL_INDEX_LEB,
        => return symbol.index,
        .R_WASM_MEMORY_ADDR_I32,
        .R_WASM_MEMORY_ADDR_I64,
        .R_WASM_MEMORY_ADDR_LEB,
        .R_WASM_MEMORY_ADDR_LEB64,
        .R_WASM_MEMORY_ADDR_SLEB,
        .R_WASM_MEMORY_ADDR_SLEB64,
        => {
            std.debug.assert(symbol.tag == .data);
            if (symbol.isUndefined()) {
                return 0;
            }
            const va: i33 = @intCast(symbol.virtual_address);
            return @intCast(va + relocation.addend);
        },
        .R_WASM_EVENT_INDEX_LEB => return symbol.index,
        .R_WASM_SECTION_OFFSET_I32 => {
            const target_atom_index = wasm_bin.symbol_atom.get(target_loc).?;
            const target_atom = fromIndex(wasm_bin, target_atom_index);
            const rel_value: i33 = @intCast(target_atom.offset);
            return @intCast(rel_value + relocation.addend);
        },
        .R_WASM_FUNCTION_OFFSET_I32 => {
            if (symbol.isUndefined()) {
                const val = atom.thombstone(wasm_bin) orelse relocation.addend;
                return @bitCast(val);
            }
            const target_atom_index = wasm_bin.symbol_atom.get(target_loc).?;
            const target_atom = fromIndex(wasm_bin, target_atom_index);
            const rel_value: i33 = @intCast(target_atom.offset);
            return @intCast(rel_value + relocation.addend);
        },
        .R_WASM_MEMORY_ADDR_TLS_SLEB,
        .R_WASM_MEMORY_ADDR_TLS_SLEB64,
        => {
            const va: i33 = @intCast(symbol.virtual_address);
            return @intCast(va + relocation.addend);
        },
    }
}

/// For a given `Atom` returns whether it has a thombstone value or not.
/// This defines whether we want a specific value when a section is dead.
fn thombstone(atom: Atom, wasm: *const Wasm) ?i64 {
    const atom_name = atom.symbolLoc().getName(wasm);
    if (std.mem.eql(u8, atom_name, ".debug_ranges") or std.mem.eql(u8, atom_name, ".debug_loc")) {
        return -2;
    } else if (std.mem.startsWith(u8, atom_name, ".debug_")) {
        return -1;
    }
    return null;
}
