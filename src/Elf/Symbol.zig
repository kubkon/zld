//! Represents a defined symbol.

value: u64 = 0,

name: u32 = 0,

file: u32 = 0,

atom: Atom.Index = 0,

sym_idx: u32 = 0,

pub inline fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return elf_file.getString(symbol.name);
}

pub inline fn getFile(symbol: Symbol, elf_file: *Elf) ?*Object {
    return elf_file.getFile(symbol.file);
}

pub inline fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.getAtom(symbol.atom);
}

pub fn getSourceSymbol(symbol: Symbol, elf_file: *Elf) ?elf.Elf64_Sym {
    const object = symbol.getFile(elf_file) orelse return null;
    return object.s_symtab[symbol.sym_idx];
}

pub fn getSymbolPrecedence(symbol: Symbol, elf_file: *Elf) u4 {
    const sym = symbol.getSourceSymbol(elf_file) orelse return 0xf;
    return Object.getSymbolPrecedence(sym);
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
    if (symbol.getAtom(ctx.elf_file)) |atom| {
        try writer.print(" : defined in atom %%%{d}", .{atom.atom_index});
    } else if (symbol.getFile(ctx.elf_file)) |file| {
        try writer.print(" : absolute in file >>>{d}", .{file.object_id});
    } else {
        try writer.writeAll(" : undefined");
    }
}

const std = @import("std");
const elf = std.elf;

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");
const Symbol = @This();
