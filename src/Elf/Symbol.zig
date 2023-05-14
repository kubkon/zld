//! Represents a defined symbol.

/// Allocated address value of this symbol.
value: u64 = 0,

/// Offset into the linker's intern table.
name: u32 = 0,

/// File where this symbol is defined.
file: u32 = 0,

/// Atom containing this symbol if any.
/// Index of 0 means there is no associated atom with this symbol.
/// Use `getAtom` to get the pointer to the atom.
atom: Atom.Index = 0,

/// Assigned output section index for this atom.
shndx: u16 = 0,

/// Index of the source symbol this symbol references.
/// Use `getSourceSymbol` to pull the source symbol from the relevant file.
sym_idx: u32 = 0,

/// Whether the symbol is imported from a shared object at runtime.
import: bool = false,

pub fn isUndef(symbol: Symbol, elf_file: *Elf) bool {
    const sym = symbol.getSourceSymbol(elf_file);
    return sym.st_shndx == elf.SHN_UNDEF;
}

pub fn isWeak(symbol: Symbol, elf_file: *Elf) bool {
    const sym = symbol.getSourceSymbol(elf_file);
    return sym.st_bind() == elf.STB_WEAK;
}

pub fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return elf_file.string_intern.getAssumeExists(symbol.name);
}

pub fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.getAtom(symbol.atom);
}

pub fn getInternalObject(symbol: Symbol, elf_file: *Elf) ?*InternalObject {
    const internal = elf_file.getInternalObject() orelse return null;
    if (internal.index != symbol.file) return null;
    return internal;
}

pub inline fn getObject(symbol: Symbol, elf_file: *Elf) ?*Object {
    return elf_file.getObject(symbol.file);
}

pub inline fn getSharedObject(symbol: Symbol, elf_file: *Elf) ?*SharedObject {
    return elf_file.getSharedObject(symbol.file);
}

pub fn getSourceSymbol(symbol: Symbol, elf_file: *Elf) elf.Elf64_Sym {
    if (symbol.getInternalObject(elf_file)) |internal| {
        return internal.symtab.items[symbol.sym_idx];
    } else if (symbol.getObject(elf_file)) |object| {
        return object.getSourceSymbol(symbol.sym_idx);
    } else if (symbol.getSharedObject(elf_file)) |shared| {
        return shared.getSourceSymbol(symbol.sym_idx);
    } else unreachable;
}

pub fn getSymbolRank(symbol: Symbol, elf_file: *Elf) u4 {
    const sym = symbol.getSourceSymbol(elf_file);
    return Object.getSymbolRank(sym);
}

pub fn format(
    symbol: Symbol,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = symbol;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format symbols directly");
}

pub fn fmt(symbol: Symbol, elf_file: *Elf) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .symbol = symbol,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    symbol: Symbol,
    elf_file: *Elf,
};

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const symbol = ctx.symbol;
    try writer.print("%{d} : {s} : @{x}", .{ symbol.sym_idx, symbol.getName(ctx.elf_file), symbol.value });

    if (symbol.isUndef(ctx.elf_file)) {
        try writer.writeAll(" : undefined");
    } else {
        if (symbol.shndx == 0) {
            try writer.writeAll(" : absolute");
        } else {
            try writer.print(" : sect({d})", .{symbol.shndx});
        }
        if (symbol.getInternalObject(ctx.elf_file)) |internal| {
            try writer.print(" : internal({d})", .{internal.index});
        } else if (symbol.getObject(ctx.elf_file)) |object| {
            if (symbol.getAtom(ctx.elf_file)) |atom| {
                try writer.print(" : atom({d})", .{atom.atom_index});
            }
            try writer.print(" : file({d})", .{object.index});
        } else if (symbol.getSharedObject(ctx.elf_file)) |shared| {
            try writer.print(" : file({d})", .{shared.index});
        } else unreachable;
    }
}

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const InternalObject = @import("InternalObject.zig");
const Object = @import("Object.zig");
const SharedObject = @import("SharedObject.zig");
const Symbol = @This();
