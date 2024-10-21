//! Represents a defined symbol.

/// Allocated address value of this symbol.
value: i64 = 0,

/// Offset into the linker's intern table.
name: u32 = 0,

/// File where this symbol is defined.
file: File.Index = 0,

/// Atom containing this symbol if any.
/// Use `getAtom` to get the pointer to the atom.
ref: Elf.Ref = .{},

/// Assigned output section index for this symbol.
shndx: u32 = 0,

/// Index of the source symbol this symbol references.
/// Use `getElfSym` to pull the source symbol from the relevant file.
esym_idx: Index = 0,

/// Index of the source version symbol this symbol references if any.
/// If the symbol is unversioned it will have either VER_NDX_LOCAL or VER_NDX_GLOBAL.
ver_idx: elf.Elf64_Versym = elf.VER_NDX_LOCAL,

/// Misc flags for the symbol packaged as packed struct for compression.
flags: Flags = .{},

extra: u32 = 0,

pub fn isAbs(symbol: Symbol, elf_file: *Elf) bool {
    const file = symbol.getFile(elf_file).?;
    if (file == .shared) return symbol.getElfSym(elf_file).st_shndx == elf.SHN_ABS;
    return !symbol.flags.import and symbol.getAtom(elf_file) == null and symbol.getMergeSubsection(elf_file) == null and symbol.getShndx(elf_file) == null and file != .internal;
}

pub fn isLocal(symbol: Symbol, elf_file: *Elf) bool {
    if (elf_file.options.relocatable) return symbol.getElfSym(elf_file).st_bind() == elf.STB_LOCAL;
    return !(symbol.flags.import or symbol.flags.@"export");
}

pub fn isIFunc(symbol: Symbol, elf_file: *Elf) bool {
    return symbol.getType(elf_file) == elf.STT_GNU_IFUNC;
}

pub fn getType(symbol: Symbol, elf_file: *Elf) u4 {
    const file = symbol.getFile(elf_file).?;
    const s_sym = symbol.getElfSym(elf_file);
    if (s_sym.st_type() == elf.STT_GNU_IFUNC and file == .shared) return elf.STT_FUNC;
    return s_sym.st_type();
}

pub fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return switch (symbol.getFile(elf_file).?) {
        inline else => |x| x.getString(symbol.name),
    };
}

pub fn getShndx(symbol: Symbol, elf_file: *Elf) ?u32 {
    if (symbol.getMergeSubsection(elf_file)) |msub|
        return if (msub.alive) msub.getMergeSection(elf_file).out_shndx else null;
    if (symbol.getAtom(elf_file)) |atom_ptr|
        return if (atom_ptr.flags.alive) atom_ptr.out_shndx else null;
    if (symbol.shndx == 0) return null;
    return symbol.shndx;
}

pub fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    if (symbol.flags.merge_subsection) return null;
    return elf_file.getAtom(symbol.ref);
}

pub fn getMergeSubsection(symbol: Symbol, elf_file: *Elf) ?*MergeSubsection {
    if (!symbol.flags.merge_subsection) return null;
    const msec = elf_file.getMergeSection(symbol.ref.file);
    return msec.getMergeSubsection(symbol.ref.index);
}

pub fn getFile(symbol: Symbol, elf_file: *Elf) ?File {
    return elf_file.getFile(symbol.file);
}

pub fn getElfSym(symbol: Symbol, elf_file: *Elf) elf.Elf64_Sym {
    const file = symbol.getFile(elf_file).?;
    return switch (file) {
        inline else => |x| x.symtab.items[symbol.esym_idx],
    };
}

pub fn getSymbolRank(symbol: Symbol, elf_file: *Elf) u32 {
    const file = symbol.getFile(elf_file) orelse return std.math.maxInt(u32);
    const sym = symbol.getElfSym(elf_file);
    const in_archive = switch (file) {
        .object => |x| !x.alive,
        else => false,
    };
    return file.getSymbolRank(sym, in_archive);
}

pub fn getAddress(symbol: Symbol, opts: struct {
    plt: bool = true,
}, elf_file: *Elf) i64 {
    if (symbol.getMergeSubsection(elf_file)) |msub| {
        if (!msub.alive) return 0;
        return msub.getAddress(elf_file) + symbol.value;
    }
    if (symbol.flags.copy_rel) {
        return symbol.getCopyRelAddress(elf_file);
    }
    if (symbol.flags.plt and opts.plt) {
        if (!symbol.flags.is_canonical and symbol.flags.got) {
            // We have a non-lazy bound function pointer, use that!
            return symbol.getPltGotAddress(elf_file);
        }
        // Lazy-bound function it is!
        return symbol.getPltAddress(elf_file);
    }
    if (symbol.getAtom(elf_file)) |atom| {
        if (!atom.flags.alive) {
            if (mem.eql(u8, atom.getName(elf_file), ".eh_frame")) {
                const sym_name = symbol.getName(elf_file);
                const sh_addr, const sh_size = blk: {
                    const shndx = elf_file.eh_frame_sect_index orelse break :blk .{ 0, 0 };
                    const shdr = elf_file.sections.items(.shdr)[shndx];
                    break :blk .{ shdr.sh_addr, shdr.sh_size };
                };
                if (mem.startsWith(u8, sym_name, "__EH_FRAME_BEGIN__") or
                    mem.startsWith(u8, sym_name, "__EH_FRAME_LIST__") or
                    mem.startsWith(u8, sym_name, ".eh_frame_seg") or
                    symbol.getElfSym(elf_file).st_type() == elf.STT_SECTION)
                {
                    return @intCast(sh_addr);
                }

                if (mem.startsWith(u8, sym_name, "__FRAME_END__") or
                    mem.startsWith(u8, sym_name, "__EH_FRAME_LIST_END__"))
                {
                    return @intCast(sh_addr + sh_size);
                }

                // TODO I think we potentially should error here
            }

            return 0;
        }
        return atom.getAddress(elf_file) + symbol.value;
    }
    return symbol.value;
}

pub fn getOutputSymtabIndex(symbol: Symbol, elf_file: *Elf) ?u32 {
    if (!symbol.flags.output_symtab) return null;
    const file = symbol.getFile(elf_file).?;
    const symtab_ctx = switch (file) {
        inline else => |x| x.output_symtab_ctx,
    };
    const idx = symbol.getExtra(elf_file).symtab;
    return if (symbol.isLocal(elf_file)) idx + symtab_ctx.ilocal else idx + symtab_ctx.iglobal;
}

pub fn getGotAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.got) return 0;
    const extra = symbol.getExtra(elf_file);
    const entry = elf_file.got.entries.items[extra.got];
    return entry.getAddress(elf_file);
}

pub fn getPltGotAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!(symbol.flags.plt and symbol.flags.got)) return 0;
    const extra = symbol.getExtra(elf_file);
    const shdr = elf_file.sections.items(.shdr)[elf_file.plt_got_sect_index.?];
    const cpu_arch = elf_file.options.cpu_arch.?;
    return @intCast(shdr.sh_addr + extra.plt_got * PltGotSection.entrySize(cpu_arch));
}

pub fn getPltAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.plt) return 0;
    const extra = symbol.getExtra(elf_file);
    const shdr = elf_file.sections.items(.shdr)[elf_file.plt_sect_index.?];
    const cpu_arch = elf_file.options.cpu_arch.?;
    return @intCast(shdr.sh_addr + extra.plt * PltSection.entrySize(cpu_arch) + PltSection.preambleSize(cpu_arch));
}

pub fn getGotPltAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.plt) return 0;
    const extra = symbol.getExtra(elf_file);
    const shdr = elf_file.sections.items(.shdr)[elf_file.got_plt_sect_index.?];
    return @intCast(shdr.sh_addr + extra.plt * 8 + GotPltSection.preamble_size);
}

pub fn getCopyRelAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.copy_rel) return 0;
    const shdr = elf_file.sections.items(.shdr)[elf_file.copy_rel_sect_index.?];
    return @as(i64, @intCast(shdr.sh_addr)) + symbol.value;
}

pub fn getTlsGdAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.tlsgd) return 0;
    const extra = symbol.getExtra(elf_file);
    const entry = elf_file.got.entries.items[extra.tlsgd];
    return entry.getAddress(elf_file);
}

pub fn getGotTpAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.gottp) return 0;
    const extra = symbol.getExtra(elf_file);
    const entry = elf_file.got.entries.items[extra.gottp];
    return entry.getAddress(elf_file);
}

pub fn getTlsDescAddress(symbol: Symbol, elf_file: *Elf) i64 {
    if (!symbol.flags.tlsdesc) return 0;
    const extra = symbol.getExtra(elf_file);
    const entry = elf_file.got.entries.items[extra.tlsdesc];
    return entry.getAddress(elf_file);
}

pub fn getAlignment(symbol: Symbol, elf_file: *Elf) !u64 {
    const file = symbol.getFile(elf_file) orelse return 0;
    const shared = file.shared;
    const s_sym = symbol.getElfSym(elf_file);
    const shdr = shared.shdrs.items[s_sym.st_shndx];
    const alignment = @max(1, shdr.sh_addralign);
    return if (s_sym.st_value == 0)
        alignment
    else
        @min(alignment, try std.math.powi(u64, 2, @ctz(s_sym.st_value)));
}

const AddExtraOpts = struct {
    got: ?u32 = null,
    plt: ?u32 = null,
    plt_got: ?u32 = null,
    dynamic: ?u32 = null,
    symtab: ?u32 = null,
    copy_rel: ?u32 = null,
    tlsgd: ?u32 = null,
    gottp: ?u32 = null,
    tlsdesc: ?u32 = null,
};

pub fn addExtra(symbol: *Symbol, opts: AddExtraOpts, elf_file: *Elf) void {
    var extra = symbol.getExtra(elf_file);
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extra, field.name) = x;
        }
    }
    symbol.setExtra(extra, elf_file);
}

pub fn getExtra(symbol: Symbol, elf_file: *Elf) Extra {
    return switch (symbol.getFile(elf_file).?) {
        inline else => |x| x.getSymbolExtra(symbol.extra),
    };
}

pub fn setExtra(symbol: Symbol, extra: Extra, elf_file: *Elf) void {
    return switch (symbol.getFile(elf_file).?) {
        inline else => |x| x.setSymbolExtra(symbol.extra, extra),
    };
}

pub fn setOutputSym(symbol: Symbol, elf_file: *Elf, out: *elf.Elf64_Sym) void {
    const file = symbol.getFile(elf_file).?;
    const s_sym = symbol.getElfSym(elf_file);
    const st_type = symbol.getType(elf_file);
    const st_bind: u8 = blk: {
        if (symbol.isLocal(elf_file)) break :blk 0;
        if (symbol.flags.weak) break :blk elf.STB_WEAK;
        if (file == .shared) break :blk elf.STB_GLOBAL;
        break :blk s_sym.st_bind();
    };
    const st_shndx: u16 = blk: {
        if (symbol.flags.copy_rel) break :blk @intCast(elf_file.copy_rel_sect_index.?);
        if (file == .shared or s_sym.st_shndx == elf.SHN_UNDEF) break :blk elf.SHN_UNDEF;
        if (elf_file.options.relocatable and s_sym.st_shndx == elf.SHN_COMMON) break :blk elf.SHN_COMMON;
        if (symbol.getMergeSubsection(elf_file)) |msub| break :blk @intCast(msub.getMergeSection(elf_file).out_shndx);
        if (symbol.getAtom(elf_file) == null and file != .internal) break :blk elf.SHN_ABS;
        break :blk @intCast(symbol.getShndx(elf_file) orelse elf.SHN_UNDEF);
    };
    const st_value = blk: {
        if (symbol.flags.copy_rel) break :blk symbol.getAddress(.{}, elf_file);
        if (file == .shared or s_sym.st_shndx == elf.SHN_UNDEF) {
            if (symbol.flags.is_canonical) break :blk symbol.getAddress(.{}, elf_file);
            break :blk 0;
        }
        if (st_shndx == elf.SHN_ABS or st_shndx == elf.SHN_COMMON) break :blk symbol.getAddress(.{ .plt = false }, elf_file);
        const shdr = elf_file.sections.items(.shdr)[st_shndx];
        if (Elf.shdrIsTls(shdr)) break :blk symbol.getAddress(.{ .plt = false }, elf_file) - elf_file.getTlsAddress();
        break :blk symbol.getAddress(.{ .plt = false }, elf_file);
    };
    out.st_info = (st_bind << 4) | st_type;
    out.st_other = s_sym.st_other;
    out.st_shndx = @intCast(st_shndx);
    out.st_value = @intCast(st_value);
    out.st_size = s_sym.st_size;
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

const FormatContext = struct {
    symbol: Symbol,
    elf_file: *Elf,
};

pub fn fmtName(symbol: Symbol, elf_file: *Elf) std.fmt.Formatter(formatName) {
    return .{ .data = .{
        .symbol = symbol,
        .elf_file = elf_file,
    } };
}

fn formatName(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const elf_file = ctx.elf_file;
    const symbol = ctx.symbol;
    try writer.writeAll(symbol.getName(elf_file));
    switch (symbol.ver_idx & elf.VERSYM_VERSION) {
        elf.VER_NDX_LOCAL, elf.VER_NDX_GLOBAL => {},
        else => {
            const shared = symbol.getFile(elf_file).?.shared;
            try writer.print("@{s}", .{shared.getVersionString(symbol.ver_idx)});
        },
    }
}

pub fn fmt(symbol: Symbol, elf_file: *Elf) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .symbol = symbol,
        .elf_file = elf_file,
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
    try writer.print("%{d} : {s} : @{x}", .{ symbol.esym_idx, symbol.fmtName(ctx.elf_file), symbol.getAddress(.{}, ctx.elf_file) });
    if (symbol.getFile(ctx.elf_file)) |file| {
        if (symbol.isAbs(ctx.elf_file)) {
            if (symbol.getElfSym(ctx.elf_file).st_shndx == elf.SHN_UNDEF) {
                try writer.writeAll(" : undef");
            } else {
                try writer.writeAll(" : absolute");
            }
        } else if (symbol.getShndx(ctx.elf_file)) |shndx| {
            try writer.print(" : sect({d})", .{shndx});
        }
        if (symbol.getAtom(ctx.elf_file)) |atom| {
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
            .shared => |x| try writer.print(" : shared({d})", .{x.index}),
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

    /// Whether the symbol contains GOT indirection.
    got: bool = false,

    /// Whether the symbol contains PLT indirection.
    plt: bool = false,
    /// Whether the PLT entry is canonical.
    is_canonical: bool = false,

    /// Whether the symbol contains COPYREL directive.
    copy_rel: bool = false,
    has_copy_rel: bool = false,
    has_dynamic: bool = false,

    /// Whether the symbol contains TLSGD indirection.
    tlsgd: bool = false,

    /// Whether the symbol contains GOTTP indirection.
    gottp: bool = false,

    /// Whether the symbol contains TLSDESC indirection.
    tlsdesc: bool = false,

    /// Whether the symbol is a merge subsection.
    merge_subsection: bool = false,
};

pub const Extra = struct {
    got: u32 = 0,
    plt: u32 = 0,
    plt_got: u32 = 0,
    dynamic: u32 = 0,
    symtab: u32 = 0,
    copy_rel: u32 = 0,
    tlsgd: u32 = 0,
    gottp: u32 = 0,
    tlsdesc: u32 = 0,
};

pub const Index = u32;

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const mem = std.mem;
const synthetic = @import("synthetic.zig");

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const InternalObject = @import("InternalObject.zig");
const GotSection = synthetic.GotSection;
const GotPltSection = synthetic.GotPltSection;
const MergeSubsection = @import("merge_section.zig").MergeSubsection;
const Object = @import("Object.zig");
const PltSection = synthetic.PltSection;
const PltGotSection = synthetic.PltGotSection;
const SharedObject = @import("SharedObject.zig");
const Symbol = @This();
