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
out_n_sect: u16 = 0,

/// Index of the source nlist this symbol references.
/// Use `getNlist` to pull the nlist from the relevant file.
nlist_idx: u32 = 0,

/// Misc flags for the symbol packaged as packed struct for compression.
flags: Flags = .{},

extra: u32 = 0,

pub fn isAbs(symbol: Symbol, macho_file: *MachO) bool {
    const file = symbol.getFile(macho_file).?;
    if (file == .dylib) return symbol.getNlist(macho_file).abs();
    return !symbol.flags.import and symbol.getAtom(macho_file) == null and symbol.out_n_sect == 0 and file != .internal;
}

pub fn isLocal(symbol: Symbol) bool {
    return !(symbol.flags.import or symbol.flags.@"export");
}

pub fn isTlvInit(self: Symbol, macho_file: *MachO) bool {
    const name = self.getName(macho_file);
    return std.mem.indexOf(u8, name, "$tlv$init") != null;
}

pub fn getName(symbol: Symbol, macho_file: *MachO) [:0]const u8 {
    return macho_file.string_intern.getAssumeExists(symbol.name);
}

pub fn getAtom(symbol: Symbol, macho_file: *MachO) ?*Atom {
    return macho_file.getAtom(symbol.atom);
}

pub fn getFile(symbol: Symbol, macho_file: *MachO) ?File {
    return macho_file.getFile(symbol.file);
}

pub fn getNlist(symbol: Symbol, macho_file: *MachO) macho.nlist_64 {
    const file = symbol.getFile(macho_file).?;
    return switch (file) {
        inline else => |x| x.symtab.items[symbol.nlist_idx],
    };
}

pub fn getSymbolRank(symbol: Symbol, macho_file: *MachO) u32 {
    const file = symbol.getFile(macho_file) orelse return std.math.maxInt(u32);
    const nlist = symbol.getNlist(macho_file);
    const in_archive = switch (file) {
        .object => |x| !x.alive,
        else => false,
    };
    return file.getSymbolRank(nlist, in_archive);
}

pub fn getAddress(symbol: Symbol, opts: struct {
    stubs: bool = true,
}, macho_file: *MachO) u64 {
    if (symbol.flags.stubs and opts.stubs) {
        return symbol.getStubsAddress(macho_file);
    }
    return symbol.value;
}

pub fn getGotAddress(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.got) return 0;
    const extra = symbol.getExtra(macho_file).?;
    return macho_file.got.getAddress(extra.got, macho_file);
}

pub fn getStubsAddress(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.stubs) return 0;
    const extra = symbol.getExtra(macho_file).?;
    return macho_file.stubs.getAddress(extra.stubs, macho_file);
}

pub fn getTlvPtrAddress(symbol: Symbol, macho_file: *MachO) u64 {
    if (!symbol.flags.tlv_ptr) return 0;
    const extra = symbol.getExtra(macho_file).?;
    return macho_file.tlv_ptr.getAddress(extra.tlv_ptr, macho_file);
}

// pub fn getOutputSymtabIndex(symbol: Symbol, elf_file: *Elf) ?u32 {
//     if (!symbol.flags.output_symtab) return null;
//     const file = symbol.getFile(elf_file).?;
//     const symtab_ctx = switch (file) {
//         inline else => |x| x.output_symtab_ctx,
//     };
//     const idx = symbol.getExtra(elf_file).?.symtab;
//     return if (symbol.isLocal(elf_file)) idx + symtab_ctx.ilocal else idx + symtab_ctx.iglobal;
// }

// pub fn setOutputSymtabIndex(symbol: *Symbol, index: u32, elf_file: *Elf) !void {
//     if (symbol.getExtra(elf_file)) |extra| {
//         var new_extra = extra;
//         new_extra.symtab = index;
//         symbol.setExtra(new_extra, elf_file);
//     } else try symbol.addExtra(.{ .symtab = index }, elf_file);
// }

const AddExtraOpts = struct {
    got: ?u32 = null,
    stubs: ?u32 = null,
    tlv_ptr: ?u32 = null,
    symtab: ?u32 = null,
};

pub fn addExtra(symbol: *Symbol, opts: AddExtraOpts, macho_file: *MachO) !void {
    if (symbol.getExtra(macho_file) == null) {
        symbol.extra = try macho_file.addSymbolExtra(.{});
    }
    var extra = symbol.getExtra(macho_file).?;
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extra, field.name) = x;
        }
    }
    symbol.setExtra(extra, macho_file);
}

pub inline fn getExtra(symbol: Symbol, macho_file: *MachO) ?Extra {
    return macho_file.getSymbolExtra(symbol.extra);
}

pub inline fn setExtra(symbol: Symbol, extra: Extra, macho_file: *MachO) void {
    macho_file.setSymbolExtra(symbol.extra, extra);
}

// pub fn setOutputSym(symbol: Symbol, elf_file: *Elf, out: *elf.Elf64_Sym) void {
//     const file = symbol.getFile(elf_file).?;
//     const s_sym = symbol.getSourceSymbol(elf_file);
//     const st_type = symbol.getType(elf_file);
//     const st_bind: u8 = blk: {
//         if (symbol.isLocal(elf_file)) break :blk 0;
//         if (symbol.flags.weak) break :blk elf.STB_WEAK;
//         if (file == .shared) break :blk elf.STB_GLOBAL;
//         break :blk s_sym.st_bind();
//     };
//     const st_shndx = blk: {
//         if (symbol.flags.copy_rel) break :blk elf_file.copy_rel_sect_index.?;
//         if (file == .shared or s_sym.st_shndx == elf.SHN_UNDEF) break :blk elf.SHN_UNDEF;
//         if (elf_file.options.relocatable and s_sym.st_shndx == elf.SHN_COMMON) break :blk elf.SHN_COMMON;
//         if (symbol.getAtom(elf_file) == null and file != .internal) break :blk elf.SHN_ABS;
//         break :blk symbol.shndx;
//     };
//     const st_value = blk: {
//         if (symbol.flags.copy_rel) break :blk symbol.getAddress(.{}, elf_file);
//         if (file == .shared or s_sym.st_shndx == elf.SHN_UNDEF) {
//             if (symbol.flags.is_canonical) break :blk symbol.getAddress(.{}, elf_file);
//             break :blk 0;
//         }
//         if (st_shndx == elf.SHN_ABS or st_shndx == elf.SHN_COMMON) break :blk symbol.value;
//         const shdr = &elf_file.sections.items(.shdr)[st_shndx];
//         if (Elf.shdrIsTls(shdr)) break :blk symbol.value - elf_file.getTlsAddress();
//         break :blk symbol.value;
//     };
//     out.st_info = (st_bind << 4) | st_type;
//     out.st_other = s_sym.st_other;
//     out.st_shndx = st_shndx;
//     out.st_value = st_value;
//     out.st_size = s_sym.st_size;
// }

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

const FormatContext = struct {
    symbol: Symbol,
    macho_file: *MachO,
};

pub fn fmt(symbol: Symbol, macho_file: *MachO) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .symbol = symbol,
        .macho_file = macho_file,
    } };
}

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const symbol = ctx.symbol;
    try writer.print("%{d} : {s} : @{x}", .{ symbol.nlist_idx, symbol.getName(ctx.macho_file), symbol.value });
    if (symbol.getFile(ctx.macho_file)) |file| {
        if (symbol.out_n_sect != 0) {
            try writer.print(" : sect({d})", .{symbol.out_n_sect});
        }
        if (symbol.getAtom(ctx.macho_file)) |atom| {
            try writer.print(" : atom({d})", .{atom.atom_index});
        }
        var buf: [2]u8 = .{'_'} ** 2;
        if (symbol.flags.@"export") buf[0] = 'E';
        if (symbol.flags.import) buf[1] = 'I';
        try writer.print(" : {s}", .{&buf});
        if (symbol.flags.weak) try writer.writeAll(" : weak");
        switch (file) {
            .internal => |x| try writer.print(" : internal({d})", .{x.index}),
            .object => |x| try writer.print(" : object({d})", .{x.index}),
            .dylib => |x| try writer.print(" : dylib({d})", .{x.index}),
        }
    } else try writer.writeAll(" : unresolved");
}

pub const Flags = packed struct {
    /// Whether the symbol is imported at runtime.
    import: bool = false,

    /// Whether the symbol is exported at runtime.
    @"export": bool = false,

    /// Whether this symbol is weak.
    weak: bool = false,

    /// Whether the symbol makes into the output symtab or not.
    output_symtab: bool = false,

    /// Whether the symbol contains __got indirection.
    got: bool = false,

    /// Whether the symbols contains __stubs indirection.
    stubs: bool = false,

    /// Whether the symbol has a TLV pointer.
    tlv_ptr: bool = false,
};

pub const Extra = struct {
    got: u32 = 0,
    stubs: u32 = 0,
    tlv_ptr: u32 = 0,
    symtab: u32 = 0,
};

pub const Index = u32;

const assert = std.debug.assert;
const macho = std.macho;
const std = @import("std");

const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @This();
