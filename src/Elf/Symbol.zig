//! Represents a defined symbol.

/// Allocated address value of this symbol.
value: u64 = 0,

/// Offset into the linker's intern table.
name: u32 = 0,

/// File where this symbol is defined.
file: File.Index = 0,

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

/// Whether the symbol makes into the output symtab or not.
output_symtab: bool = false,

flags: Flags = .{},

extra: u32 = 0,

pub fn isAbs(symbol: Symbol, elf_file: *Elf) bool {
    const file = symbol.getFile(elf_file).?;
    if (file == .shared)
        return symbol.getSourceSymbol(elf_file).st_shndx == elf.SHN_ABS;

    return !symbol.import and symbol.getAtom(elf_file) == null and symbol.shndx == 0;
}

pub fn isLocal(symbol: Symbol) bool {
    return !(symbol.import or symbol.@"export");
}

pub fn isIFunc(symbol: Symbol, elf_file: *Elf) bool {
    const file = symbol.getFile(elf_file).?;
    const s_sym = symbol.getSourceSymbol(elf_file);
    const is_ifunc = s_sym.st_type() == elf.STT_GNU_IFUNC;
    return is_ifunc and file != .shared;
}

pub fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return elf_file.string_intern.getAssumeExists(symbol.name);
}

pub fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.getAtom(symbol.atom);
}

pub inline fn getFile(symbol: Symbol, elf_file: *Elf) ?File {
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
    return file.getSymbolRank(sym, in_archive);
}

pub fn getAddress(symbol: Symbol, elf_file: *Elf) u64 {
    if (symbol.flags.copy_rel) {
        const shdr = elf_file.sections.items(.shdr)[elf_file.copy_rel_sect_index.?];
        return shdr.sh_addr + symbol.value;
    }
    if (symbol.flags.plt) {
        const extra = symbol.getExtra(elf_file).?;
        if (symbol.flags.got) {
            return elf_file.getPltGotEntryAddress(extra.plt_got);
        }
        return elf_file.getPltEntryAddress(extra.plt);
    }
    return symbol.value;
}

pub fn getGotAddress(symbol: Symbol, elf_file: *Elf) u64 {
    if (!symbol.flags.got) return 0;
    const extra = symbol.getExtra(elf_file).?;
    return elf_file.getGotEntryAddress(extra.got);
}

pub fn getAlignment(symbol: Symbol, elf_file: *Elf) u64 {
    if (symbol.getFile(elf_file) == null) return 0;
    const s_sym = symbol.getSourceSymbol(elf_file);
    return @ctz(s_sym.st_value);
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

pub inline fn asElfSym(symbol: Symbol, st_name: u32, elf_file: *Elf) elf.Elf64_Sym {
    const s_sym = symbol.getSourceSymbol(elf_file);
    const st_type = switch (s_sym.st_type()) {
        elf.STT_GNU_IFUNC => elf.STT_FUNC,
        else => |st_type| st_type,
    };
    const st_bind: u8 = if (symbol.isLocal()) 0 else elf.STB_GLOBAL;
    const st_shndx = blk: {
        if (symbol.flags.copy_rel) break :blk elf_file.copy_rel_sect_index.?;
        if (symbol.import) break :blk elf.SHN_UNDEF;
        break :blk symbol.shndx;
    };
    const st_value = blk: {
        if (symbol.flags.copy_rel) break :blk symbol.getAddress(elf_file);
        if (symbol.import) break :blk 0;
        break :blk symbol.value;
    };
    return elf.Elf64_Sym{
        .st_name = st_name,
        .st_info = (st_bind << 4) | st_type,
        .st_other = s_sym.st_other,
        .st_shndx = st_shndx,
        .st_value = st_value,
        .st_size = s_sym.st_size,
    };
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
    copy_rel: bool = false,
};

pub const Extra = struct {
    got: u32 = 0,
    plt: u32 = 0,
    plt_got: u32 = 0,
    dynamic: u32 = 0,
    copy_rel: u32 = 0,
};

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const InternalObject = @import("InternalObject.zig");
const Object = @import("Object.zig");
const SharedObject = @import("SharedObject.zig");
const Symbol = @This();
