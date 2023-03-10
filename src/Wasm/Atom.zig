const Atom = @This();

const std = @import("std");
const types = @import("types.zig");
const Wasm = @import("../Wasm.zig");
const Symbol = @import("Symbol.zig");

const leb = std.leb;
const log = std.log.scoped(.wasm);
const mem = std.mem;
const Allocator = mem.Allocator;

/// Local symbol index
sym_index: u32,
/// Index into a list of object files
file: ?u16,
/// Size of the atom, used to calculate section sizes in the final binary
size: u32,
/// List of relocations belonging to this atom
relocs: std.ArrayListUnmanaged(types.Relocation) = .{},
/// Contains the binary data of an atom, which can be non-relocated
code: std.ArrayListUnmanaged(u8) = .{},
/// For code this is 1, for data this is set to the highest value of all segments
alignment: u32,
/// Offset into the section where the atom lives, this already accounts
/// for alignment.
offset: u32,

/// Next atom in relation to this atom.
/// When null, this atom is the last atom
next: ?*Atom,
/// Previous atom in relation to this atom.
/// is null when this atom is the first in its order
prev: ?*Atom,

/// Represents a default empty wasm `Atom`
pub const empty: Atom = .{
    .alignment = 0,
    .file = null,
    .next = null,
    .offset = 0,
    .prev = null,
    .size = 0,
    .sym_index = undefined,
};

/// Creates a new Atom with default fields
pub fn create(gpa: Allocator) !*Atom {
    const atom = try gpa.create(Atom);
    atom.* = .{
        .sym_index = undefined,
        .alignment = 0,
        .file = null,
        .next = null,
        .offset = 0,
        .prev = null,
        .size = 0,
    };
    return atom;
}

/// Frees all resources owned by this `Atom`.
/// Also destroys itatom, making any usage of this atom illegal.
pub fn deinit(atom: *Atom, gpa: Allocator) void {
    atom.relocs.deinit(gpa);
    atom.code.deinit(gpa);
    gpa.destroy(atom);
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

/// Returns the first `Atom` from a given atom
pub fn getFirst(atom: *Atom) *Atom {
    var tmp = atom;
    while (tmp.prev) |prev| tmp = prev;
    return tmp;
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
            => std.mem.writeIntLittle(u32, atom.code.items[reloc.offset..][0..4], @intCast(u32, value)),
            .R_WASM_TABLE_INDEX_I64,
            .R_WASM_MEMORY_ADDR_I64,
            => std.mem.writeIntLittle(u64, atom.code.items[reloc.offset..][0..8], value),
            .R_WASM_GLOBAL_INDEX_LEB,
            .R_WASM_EVENT_INDEX_LEB,
            .R_WASM_FUNCTION_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_LEB,
            .R_WASM_MEMORY_ADDR_SLEB,
            .R_WASM_TABLE_INDEX_SLEB,
            .R_WASM_TABLE_NUMBER_LEB,
            .R_WASM_TYPE_INDEX_LEB,
            .R_WASM_MEMORY_ADDR_TLS_SLEB,
            => leb.writeUnsignedFixed(5, atom.code.items[reloc.offset..][0..5], @intCast(u32, value)),
            .R_WASM_MEMORY_ADDR_LEB64,
            .R_WASM_MEMORY_ADDR_SLEB64,
            .R_WASM_TABLE_INDEX_SLEB64,
            .R_WASM_MEMORY_ADDR_TLS_SLEB64,
            => leb.writeUnsignedFixed(10, atom.code.items[reloc.offset..][0..10], value),
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
            const va = @intCast(i32, symbol.virtual_address);
            return @intCast(u32, va + relocation.addend);
        },
        .R_WASM_EVENT_INDEX_LEB => return symbol.index,
        .R_WASM_SECTION_OFFSET_I32 => {
            const target_atom = wasm_bin.symbol_atom.get(target_loc).?;
            const rel_value = @intCast(i32, target_atom.offset) + relocation.addend;
            return @intCast(u32, rel_value);
        },
        .R_WASM_FUNCTION_OFFSET_I32 => {
            const target_atom = wasm_bin.symbol_atom.get(target_loc).?;
            const offset: u32 = 11 + Wasm.getULEB128Size(target_atom.size); // Header (11 bytes fixed-size) + body size (leb-encoded)
            const rel_value = @intCast(i32, target_atom.offset + offset) + relocation.addend;
            return @intCast(u32, rel_value);
        },
        .R_WASM_MEMORY_ADDR_TLS_SLEB,
        .R_WASM_MEMORY_ADDR_TLS_SLEB64,
        => {
            @panic("TODO: Implement TLS relocations");
        },
    }
}
