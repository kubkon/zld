//! Represents a defined symbol.

/// Allocated address value of this symbol.
value: u64 = 0,

/// Offset into the linker's intern table.
name: u32 = 0,

/// File where this symbol is defined.
file: Elf.File.Index = 0,

/// Atom containing this symbol if any.
/// Index of 0 means there is no associated atom with this symbol.
/// Use `getAtom` to get the pointer to the atom.
atom: Atom.Index = 0,

/// Assigned output section index for this atom.
shndx: u16 = 0,

/// Index of the source symbol this symbol references.
/// Use `getSourceSymbol` to pull the source symbol from the relevant file.
sym_idx: u32 = 0,

/// Whether the symbol is imported at runtime.
import: bool = false,

/// Whether the symbol is exported at runtime.
@"export": bool = false,

flags: Flags = .{},

extra: u32 = 0,

pub fn isAbs(symbol: Symbol, elf_file: *Elf) bool {
    const file = symbol.getFile(elf_file).?;
    if (file == .shared)
        return symbol.getSourceSymbol(elf_file).st_shndx == elf.SHN_ABS;

    return !symbol.import and symbol.getAtom(elf_file) == null and symbol.shndx == 0;
}

pub fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return elf_file.string_intern.getAssumeExists(symbol.name);
}

pub fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.getAtom(symbol.atom);
}

pub inline fn getFile(symbol: Symbol, elf_file: *Elf) ?Elf.FilePtr {
    return elf_file.getFile(symbol.file);
}

pub fn getSourceSymbol(symbol: Symbol, elf_file: *Elf) elf.Elf64_Sym {
    const file = symbol.getFile(elf_file).?;
    return switch (file) {
        .internal => |x| x.symtab.items[symbol.sym_idx],
        inline else => |x| x.symtab[symbol.sym_idx],
    };
}

pub fn getSymbolRank(symbol: Symbol, elf_file: *Elf) u32 {
    const file = symbol.getFile(elf_file) orelse return std.math.maxInt(u32);
    const sym = symbol.getSourceSymbol(elf_file);
    const in_archive = switch (file) {
        .object => |x| !x.alive,
        else => false,
    };
    return file.deref().getSymbolRank(sym, in_archive);
}

pub fn addExtra(symbol: *Symbol, extra: Extra, elf_file: *Elf) !void {
    symbol.extra = try elf_file.addSymbolExtra(extra);
}

pub inline fn getExtra(symbol: Symbol, elf_file: *Elf) ?Extra {
    return elf_file.getSymbolExtra(symbol.extra);
}

pub inline fn setExtra(symbol: Symbol, extra: Extra, elf_file: *Elf) void {
    elf_file.setSymbolExtra(symbol.extra, extra);
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
    if (symbol.getFile(ctx.elf_file)) |file| {
        if (symbol.isAbs(ctx.elf_file)) {
            try writer.writeAll(" : absolute");
        } else if (symbol.shndx != 0) {
            try writer.print(" : sect({d})", .{symbol.shndx});
        }
        if (symbol.getAtom(ctx.elf_file)) |atom| {
            try writer.print(" : atom({d})", .{atom.atom_index});
        }
        if (symbol.@"export" and symbol.import) {
            try writer.writeAll(" : EI");
        } else if (symbol.@"export" and !symbol.import) {
            try writer.writeAll(" : E_");
        } else if (!symbol.@"export" and symbol.import) {
            try writer.writeAll(" : _I");
        } else {
            try writer.writeAll(" : __");
        }
        switch (file) {
            .internal => |x| try writer.print(" : internal({d})", .{x.index}),
            .object => |x| try writer.print(" : object({d})", .{x.index}),
            .shared => |x| try writer.print(" : shared({d})", .{x.index}),
        }
    } else try writer.writeAll(" : unresolved");
}

pub const Flags = packed struct {
    got: bool = false,
    plt: bool = false,
};

pub const Extra = struct {
    got: u32,
};

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const InternalObject = @import("InternalObject.zig");
const Object = @import("Object.zig");
const SharedObject = @import("SharedObject.zig");
const Symbol = @This();
