path: []const u8,
data: []const u8,
index: File.Index,

header: ?elf.Elf64_Ehdr = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},
/// Version symtab contains version strings of the symbols if present.
versyms: std.ArrayListUnmanaged(elf.Elf64_Versym) = .{},
verstrings: std.ArrayListUnmanaged(u32) = .{},

dynamic_sect_index: ?u16 = null,
versym_sect_index: ?u16 = null,
verdef_sect_index: ?u16 = null,

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
aliases: ?std.ArrayListUnmanaged(u32) = null,

needed: bool,
alive: bool,

output_symtab_ctx: Elf.SymtabCtx = .{},

pub fn isValidHeader(header: *const elf.Elf64_Ehdr) bool {
    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) {
        log.debug("invalid ELF magic '{s}', expected \x7fELF", .{header.e_ident[0..4]});
        return false;
    }
    if (header.e_ident[elf.EI_VERSION] != 1) {
        log.debug("unknown ELF version '{d}', expected 1", .{header.e_ident[elf.EI_VERSION]});
        return false;
    }
    if (header.e_type != elf.ET.DYN) {
        log.debug("invalid file type '{s}', expected ET.DYN", .{@tagName(header.e_type)});
        return false;
    }
    return true;
}

pub fn deinit(self: *SharedObject, allocator: Allocator) void {
    self.versyms.deinit(allocator);
    self.verstrings.deinit(allocator);
    self.symbols.deinit(allocator);
    if (self.aliases) |*aliases| aliases.deinit(allocator);
}

pub fn parse(self: *SharedObject, elf_file: *Elf) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);

    if (self.data.len < self.header.?.e_shoff or
        self.data.len < self.header.?.e_shoff + @as(u64, @intCast(self.header.?.e_shnum)) * @sizeOf(elf.Elf64_Shdr))
    {
        return elf_file.base.fatal("{s}: corrupt header: section header table extends past the end of file", .{
            self.path,
        });
    }

    const shdrs = self.getShdrs();

    var dynsym_index: ?u16 = null;
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_DYNSYM => dynsym_index = @as(u16, @intCast(i)),
        elf.SHT_DYNAMIC => self.dynamic_sect_index = @as(u16, @intCast(i)),
        elf.SHT_GNU_VERSYM => self.versym_sect_index = @as(u16, @intCast(i)),
        elf.SHT_GNU_VERDEF => self.verdef_sect_index = @as(u16, @intCast(i)),
        else => {},
    };

    if (dynsym_index) |index| {
        const shdr = shdrs[index];
        const symtab = self.getShdrContents(index);
        const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
        self.symtab = @as([*]align(1) const elf.Elf64_Sym, @ptrCast(symtab.ptr))[0..nsyms];
        self.strtab = self.getShdrContents(@as(u16, @intCast(shdr.sh_link)));
    }

    try self.parseVersions(elf_file);
    try self.initSymtab(elf_file);
}

fn parseVersions(self: *SharedObject, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    try self.verstrings.resize(gpa, 2);
    self.verstrings.items[elf.VER_NDX_LOCAL] = 0;
    self.verstrings.items[elf.VER_NDX_GLOBAL] = 0;

    if (self.verdef_sect_index) |shndx| {
        const verdefs = self.getShdrContents(shndx);
        const nverdefs = self.getVerdefNum();
        try self.verstrings.resize(gpa, self.verstrings.items.len + nverdefs);

        var i: u32 = 0;
        var offset: u32 = 0;
        while (i < nverdefs) : (i += 1) {
            const verdef = @as(*align(1) const elf.Elf64_Verdef, @ptrCast(verdefs.ptr + offset)).*;
            defer offset += verdef.vd_next;
            if (verdef.vd_flags == elf.VER_FLG_BASE) continue; // Skip BASE entry
            const vda_name = if (verdef.vd_cnt > 0)
                @as(*align(1) const elf.Elf64_Verdaux, @ptrCast(verdefs.ptr + offset + verdef.vd_aux)).vda_name
            else
                0;
            self.verstrings.items[verdef.vd_ndx] = vda_name;
        }
    }

    try self.versyms.ensureTotalCapacityPrecise(gpa, self.symtab.len);

    if (self.versym_sect_index) |shndx| {
        const versyms_raw = self.getShdrContents(shndx);
        const nversyms = @divExact(versyms_raw.len, @sizeOf(elf.Elf64_Versym));
        const versyms = @as([*]align(1) const elf.Elf64_Versym, @ptrCast(versyms_raw.ptr))[0..nversyms];
        for (versyms) |ver| {
            const normalized_ver = if (ver & elf.VERSYM_VERSION >= self.verstrings.items.len - 1)
                elf.VER_NDX_GLOBAL
            else
                ver;
            self.versyms.appendAssumeCapacity(normalized_ver);
        }
    } else for (0..self.symtab.len) |_| {
        self.versyms.appendAssumeCapacity(elf.VER_NDX_GLOBAL);
    }
}

fn initSymtab(self: *SharedObject, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    try self.symbols.ensureTotalCapacityPrecise(gpa, self.symtab.len);

    for (self.symtab, 0..) |sym, i| {
        const hidden = self.versyms.items[i] & elf.VERSYM_HIDDEN != 0;
        const name = self.getString(sym.st_name);
        // We need to garble up the name so that we don't pick this symbol
        // during symbol resolution. Thank you GNU!
        const off = if (hidden) try elf_file.internString("{s}@{s}", .{
            name,
            self.getVersionString(self.versyms.items[i]),
        }) else try elf_file.internString("{s}", .{name});
        const gop = try elf_file.getOrCreateGlobal(off);
        self.symbols.addOneAssumeCapacity().* = gop.index;
    }
}

pub fn resolveSymbols(self: *SharedObject, elf_file: *Elf) void {
    for (self.getGlobals(), 0..) |index, i| {
        const sym_idx = @as(Symbol.Index, @intCast(i));
        const this_sym = self.symtab[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getSymbol(index);
        if (self.asFile().getSymbolRank(this_sym, false) < global.getSymbolRank(elf_file)) {
            global.value = this_sym.st_value;
            global.atom = 0;
            global.sym_idx = sym_idx;
            global.ver_idx = self.versyms.items[sym_idx];
            global.file = self.index;
        }
    }
}

pub fn markLive(self: *SharedObject, elf_file: *Elf) void {
    for (self.symbols.items, 0..) |index, i| {
        const sym = self.symtab[i];
        if (sym.st_shndx != elf.SHN_UNDEF) continue;

        const global = elf_file.getSymbol(index);
        const file = global.getFile(elf_file) orelse continue;
        const should_drop = switch (file) {
            .shared => |sh| !sh.needed and sym.st_bind() == elf.STB_WEAK,
            else => false,
        };
        if (!should_drop and !file.isAlive()) {
            file.setAlive();
            file.markLive(elf_file);
        }
    }
}

pub inline fn getShdrs(self: *SharedObject) []align(1) const elf.Elf64_Shdr {
    const header = self.header orelse return &[0]elf.Elf64_Shdr{};
    return @as([*]align(1) const elf.Elf64_Shdr, @ptrCast(self.data.ptr + header.e_shoff))[0..header.e_shnum];
}

pub inline fn getShdrContents(self: *SharedObject, index: u16) []const u8 {
    const shdr = self.getShdrs()[index];
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

pub inline fn getString(self: *SharedObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.ptr + off)), 0);
}

pub inline fn getVersionString(self: *SharedObject, index: elf.Elf64_Versym) [:0]const u8 {
    const off = self.verstrings.items[index & elf.VERSYM_VERSION];
    return self.getString(off);
}

pub fn asFile(self: *SharedObject) File {
    return .{ .shared = self };
}

fn getDynamicTable(self: *SharedObject) []align(1) const elf.Elf64_Dyn {
    const shndx = self.dynamic_sect_index orelse return &[0]elf.Elf64_Dyn{};
    const raw = self.getShdrContents(shndx);
    const num = @divExact(raw.len, @sizeOf(elf.Elf64_Dyn));
    return @as([*]align(1) const elf.Elf64_Dyn, @ptrCast(raw.ptr))[0..num];
}

fn getVerdefNum(self: *SharedObject) u32 {
    const entries = self.getDynamicTable();
    for (entries) |entry| switch (entry.d_tag) {
        elf.DT_VERDEFNUM => return @as(u32, @intCast(entry.d_val)),
        else => {},
    };
    return 0;
}

pub fn getSoname(self: *SharedObject) []const u8 {
    const entries = self.getDynamicTable();
    for (entries) |entry| switch (entry.d_tag) {
        elf.DT_SONAME => return self.getString(@as(u32, @intCast(entry.d_val))),
        else => {},
    };
    return std.fs.path.basename(self.path);
}

pub fn calcSymtabSize(self: *SharedObject, elf_file: *Elf) !void {
    if (elf_file.options.strip_all) return;

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        const file_ptr = global.getFile(elf_file) orelse continue;
        if (file_ptr.getIndex() != self.index) continue;
        if (global.isLocal(elf_file)) continue;
        global.flags.output_symtab = true;
        try global.setOutputSymtabIndex(self.output_symtab_ctx.nglobals, elf_file);
        self.output_symtab_ctx.nglobals += 1;
        self.output_symtab_ctx.strsize += @as(u32, @intCast(global.getName(elf_file).len + 1));
    }
}

pub fn writeSymtab(self: SharedObject, elf_file: *Elf) void {
    if (elf_file.options.strip_all) return;

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        const file_ptr = global.getFile(elf_file) orelse continue;
        if (file_ptr.getIndex() != self.index) continue;
        const idx = global.getOutputSymtabIndex(elf_file) orelse continue;
        const st_name = @as(u32, @intCast(elf_file.strtab.items.len));
        elf_file.strtab.appendSliceAssumeCapacity(global.getName(elf_file));
        elf_file.strtab.appendAssumeCapacity(0);
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = st_name;
        global.setOutputSym(elf_file, out_sym);
    }
}

pub inline fn getGlobals(self: SharedObject) []const Symbol.Index {
    return self.symbols.items;
}

pub fn initSymbolAliases(self: *SharedObject, elf_file: *Elf) !void {
    assert(self.aliases == null);

    const SortAlias = struct {
        pub fn lessThan(ctx: *Elf, lhs: Symbol.Index, rhs: Symbol.Index) bool {
            const lhs_sym = ctx.getSymbol(lhs).getSourceSymbol(ctx);
            const rhs_sym = ctx.getSymbol(rhs).getSourceSymbol(ctx);
            return lhs_sym.st_value < rhs_sym.st_value;
        }
    };

    const gpa = elf_file.base.allocator;
    var aliases = std.ArrayList(Symbol.Index).init(gpa);
    defer aliases.deinit();
    try aliases.ensureTotalCapacityPrecise(self.getGlobals().len);

    for (self.getGlobals()) |index| {
        const global = elf_file.getSymbol(index);
        const global_file = global.getFile(elf_file) orelse continue;
        if (global_file.getIndex() != self.index) continue;
        aliases.appendAssumeCapacity(index);
    }

    std.mem.sort(Symbol.Index, aliases.items, elf_file, SortAlias.lessThan);

    self.aliases = aliases.moveToUnmanaged();
}

pub fn getSymbolAliases(self: *SharedObject, index: u32, elf_file: *Elf) []const u32 {
    assert(self.aliases != null);

    const symbol = elf_file.getSymbol(index).getSourceSymbol(elf_file);
    const aliases = self.aliases.?;

    const start = for (aliases.items, 0..) |alias, i| {
        const alias_sym = elf_file.getSymbol(alias).getSourceSymbol(elf_file);
        if (symbol.st_value == alias_sym.st_value) break i;
    } else aliases.items.len;

    const end = for (aliases.items[start..], 0..) |alias, i| {
        const alias_sym = elf_file.getSymbol(alias).getSourceSymbol(elf_file);
        if (symbol.st_value < alias_sym.st_value) break i + start;
    } else aliases.items.len;

    return aliases.items[start..end];
}

pub fn format(
    self: *SharedObject,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format shared objects directly");
}

pub fn fmtSymtab(self: *SharedObject, elf_file: *Elf) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .shared = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    shared: *SharedObject,
    elf_file: *Elf,
};

fn formatSymtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const shared = ctx.shared;
    try writer.writeAll("  globals\n");
    for (shared.symbols.items) |index| {
        const global = ctx.elf_file.getSymbol(index);
        try writer.print("    {}\n", .{global.fmt(ctx.elf_file)});
    }
}

const SharedObject = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const Symbol = @import("Symbol.zig");
