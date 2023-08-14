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
relocs: std.ArrayListUnmanaged(types.Relocation) = .{},
/// Contains the binary data of an atom, which can be non-relocated
data: [*]u8,
/// For code this is 1, for data this is set to the highest value of all segments
alignment: u32,
/// Offset into the section where the atom lives, this already accounts
/// for alignment.
offset: u32,

/// Next atom in relation to this atom.
/// When null, this atom is the last atom
next: Index,
/// Previous atom in relation to this atom.
/// is null when this atom is the first in its order
prev: Index,

/// Represents a default empty wasm `Atom`
pub const empty: Atom = .{
    .alignment = 0,
    .file = null,
    .next = .none,
    .offset = 0,
    .prev = .none,
    .size = 0,
    .sym_index = undefined,
    .data = undefined,
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

/// Returns the first atom's `Index` from a given `Index`.
pub fn firstAtom(index: Index, wasm: *const Wasm) Index {
    var current = index;
    while (true) {
        const atom = fromIndex(wasm, current);
        if (atom.prev == .none) {
            return current;
        }
        current = atom.prev;
    }
    unreachable;
}

/// Frees all resources owned by this `Atom`.
/// Also destroys itatom, making any usage of this atom illegal.
pub fn deinit(atom: *Atom, gpa: Allocator) void {
    atom.relocs.deinit(gpa);
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
    if (atom.relocs.items.len == 0) return;

    for (atom.relocs.items) |reloc| {
        const value = atom.relocationValue(reloc, wasm_bin);
        switch (reloc.relocation_type) {
            .R_WASM_TABLE_INDEX_I32,
            .R_WASM_FUNCTION_OFFSET_I32,
            .R_WASM_GLOBAL_INDEX_I32,
            .R_WASM_MEMORY_ADDR_I32,
            .R_WASM_SECTION_OFFSET_I32,
            => std.mem.writeIntLittle(u32, atom.data[reloc.offset..][0..4], @as(u32, @truncate(value))),
            .R_WASM_TABLE_INDEX_I64,
            .R_WASM_MEMORY_ADDR_I64,
            => std.mem.writeIntLittle(u64, atom.data[reloc.offset..][0..8], value),
            .R_WASM_GLOBAL_INDEX_LEB,
            .R_WASM_EVENT_INDEX_LEB,
            .R_WASM_FUNCTION_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_LEB,
            .R_WASM_MEMORY_ADDR_SLEB,
            .R_WASM_TABLE_INDEX_SLEB,
            .R_WASM_TABLE_NUMBER_LEB,
            .R_WASM_TYPE_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_TLS_SLEB,
            => leb.writeUnsignedFixed(5, atom.data[reloc.offset..][0..5], @as(u32, @truncate(value))),
            .R_WASM_MEMORY_ADDR_LEB64,
            .R_WASM_MEMORY_ADDR_SLEB64,
            .R_WASM_TABLE_INDEX_SLEB64,
            .R_WASM_MEMORY_ADDR_TLS_SLEB64,
            => leb.writeUnsignedFixed(10, atom.data[reloc.offset..][0..10], value),
        }
    }
}

/// From a given `relocation` will return the new value to be written.
/// All values will be represented as a `u64` as all values can fit within it.
/// The final value must be casted to the correct size.
fn relocationValue(atom: *Atom, relocation: types.Relocation, wasm_bin: *const Wasm) u64 {
    const target_loc = (Wasm.SymbolWithLoc{ .file = atom.file, .sym_index = relocation.index }).finalLoc(wasm_bin);
    const symbol = target_loc.getSymbol(wasm_bin);
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
            const va = @as(i32, @intCast(symbol.virtual_address));
            return @intCast(va + relocation.addend);
        },
        .R_WASM_EVENT_INDEX_LEB => return symbol.index,
        .R_WASM_SECTION_OFFSET_I32 => {
            const target_atom_index = wasm_bin.symbol_atom.get(target_loc).?;
            const target_atom = fromIndex(wasm_bin, target_atom_index);
            const rel_value: i32 = @intCast(target_atom.offset);
            return @intCast(rel_value + relocation.addend);
        },
        .R_WASM_FUNCTION_OFFSET_I32 => {
            if (symbol.isDead()) {
                const atom_name = atom.symbolLoc().getName(wasm_bin);
                if (std.mem.eql(u8, atom_name, ".debug_ranges") or std.mem.eql(u8, atom_name, ".debug_loc")) {
                    return @bitCast(@as(i64, -2));
                }
                return @bitCast(@as(i64, -1));
            }
            const target_atom_index = wasm_bin.symbol_atom.get(target_loc).?;
            const target_atom = fromIndex(wasm_bin, target_atom_index);
            const offset: u32 = 11 + Wasm.getULEB128Size(target_atom.size); // Header (11 bytes fixed-size) + body size (leb-encoded)
            const rel_value: i32 = @intCast(target_atom.offset + offset);
            return @intCast(rel_value + relocation.addend);
        },
        .R_WASM_MEMORY_ADDR_TLS_SLEB,
        .R_WASM_MEMORY_ADDR_TLS_SLEB64,
        => {
            const va: i32 = @intCast(symbol.virtual_address);
            return @intCast(va + relocation.addend);
        },
    }
}
