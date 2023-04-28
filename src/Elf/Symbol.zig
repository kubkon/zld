//! Represents a defined symbol.

value: u64 = 0,

name: u32 = 0,

/// File where this symbol is defined.
/// null means linker-defined synthetic symbol.
file: ?u32 = null,

atom: Atom.Index = 0,

sym_idx: u32 = 0,

pub fn isUndef(symbol: Symbol, elf_file: *Elf) bool {
    const sym = symbol.getSourceSymbol(elf_file);
    return sym.st_shndx == elf.SHN_UNDEF;
}

pub fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return elf_file.strtab.getAssumeExists(symbol.name);
}

pub fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.getAtom(symbol.atom);
}

pub fn getObject(symbol: Symbol, elf_file: *Elf) ?*Object {
    const file = symbol.file orelse return null;
    return &elf_file.objects.items[file];
}

pub fn getSourceSymbol(symbol: Symbol, elf_file: *Elf) elf.Elf64_Sym {
    if (symbol.getObject(elf_file)) |object| {
        return object.symtab[symbol.sym_idx];
    } else {
        return elf_file.internal_object.?.symtab.items[symbol.sym_idx];
    }
}

pub fn getSymbolPrecedence(symbol: Symbol, elf_file: *Elf) u4 {
    const sym = symbol.getSourceSymbol(elf_file);
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

    if (symbol.isUndef(ctx.elf_file)) {
        try writer.writeAll(" : undefined");
    } else {
        if (symbol.getObject(ctx.elf_file)) |object| {
            if (symbol.getAtom(ctx.elf_file)) |atom| {
                try writer.print(" : in atom({d})", .{atom.atom_index});
            } else {
                try writer.writeAll(" : absolute");
            }
            try writer.print(" : in file({d})", .{object.object_id});
        } else {
            try writer.writeAll(" : synthetic");
        }
    }
}

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");
const Symbol = @This();
