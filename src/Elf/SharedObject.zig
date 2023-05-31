path: []const u8,
data: []const u8,
index: File.Index,

header: ?elf.Elf64_Ehdr = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},
/// Version symtab contains version strings of the symbols if present.
versymtab: []align(1) const elf.Elf64_Versym = &[0]elf.Elf64_Versym{},
verstrings: std.ArrayListUnmanaged(u32) = .{},

dynamic_sect_index: ?u16 = null,

symbols: std.ArrayListUnmanaged(u32) = .{},

needed: bool,
alive: bool,

output_symtab_size: Elf.SymtabSize = .{},

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
    self.verstrings.deinit(allocator);
    self.symbols.deinit(allocator);
}

pub fn parse(self: *SharedObject, elf_file: *Elf) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);
    const shdrs = self.getShdrs();

    var dynsym_index: ?u16 = null;
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_DYNSYM => dynsym_index = @intCast(u16, i),
        elf.SHT_DYNAMIC => self.dynamic_sect_index = @intCast(u16, i),
        else => {},
    };

    if (dynsym_index) |index| {
        const shdr = shdrs[index];
        const symtab = self.getShdrContents(index);
        const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
        self.symtab = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
        self.strtab = self.getShdrContents(@intCast(u16, shdr.sh_link));
    }

    try self.initSymtab(elf_file);
    try self.parseVersions(elf_file);
}

fn parseVersions(self: *SharedObject, elf_file: *Elf) !void {
    if (self.symtab.len == 0) return;

    const shdrs = self.getShdrs();
    var versym_index: ?u16 = null;
    var verdef_index: ?u16 = null;
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        Elf.SHT_GNU_versym => versym_index = @intCast(u16, i),
        Elf.SHT_GNU_verdef => verdef_index = @intCast(u16, i),
        else => {},
    };

    if (versym_index == null or verdef_index == null) return;

    const versymtab = self.getShdrContents(versym_index.?);
    self.versymtab = @ptrCast([*]align(1) const elf.Elf64_Versym, versymtab.ptr)[0..self.symtab.len];

    const verdefs = self.getShdrContents(verdef_index.?);
    const nverdefs = self.getVerdefNum();

    const gpa = elf_file.base.allocator;
    var lookup = std.AutoHashMap(elf.Elf64_Versym, u32).init(gpa);
    defer lookup.deinit();
    try lookup.ensureTotalCapacity(nverdefs);

    {
        var i: u32 = 0;
        var offset: u32 = 0;
        while (i < nverdefs) : (i += 1) {
            const verdef = @ptrCast(*align(1) const elf.Elf64_Verdef, verdefs.ptr + offset).*;

            const vda_name = if (verdef.vd_cnt > 0)
                @ptrCast(*align(1) const elf.Elf64_Verdaux, verdefs.ptr + offset + verdef.vd_aux).vda_name
            else
                0;
            lookup.putAssumeCapacityNoClobber(verdef.vd_ndx, vda_name);

            offset += verdef.vd_next;
        }
    }

    try self.verstrings.resize(gpa, self.symtab.len);
    for (self.versymtab, 0..) |ver, i| {
        const vda_name = lookup.get(ver) orelse 0;
        self.verstrings.items[i] = vda_name;
    }
}

fn initSymtab(self: *SharedObject, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    try self.symbols.ensureTotalCapacityPrecise(gpa, self.symtab.len);

    for (self.symtab) |sym| {
        const name = self.getString(sym.st_name);
        const gop = try elf_file.getOrCreateGlobal(name);
        self.symbols.addOneAssumeCapacity().* = gop.index;
    }
}

pub fn resolveSymbols(self: *SharedObject, elf_file: *Elf) void {
    for (self.symbols.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, i);
        const this_sym = self.symtab[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getSymbol(index);
        if (self.asFile().getSymbolRank(this_sym, false) < global.getSymbolRank(elf_file)) {
            global.* = .{
                .value = this_sym.st_value,
                .name = global.name,
                .atom = 0,
                .sym_idx = sym_idx,
                .file = self.index,
            };
        }
    }
}

pub fn resetGlobals(self: *SharedObject, elf_file: *Elf) void {
    for (self.symbols.items) |index| {
        const global = elf_file.getSymbol(index);
        const name = global.name;
        global.* = .{};
        global.name = name;
    }
}

pub fn markLive(self: *SharedObject, elf_file: *Elf) void {
    for (self.symbols.items, 0..) |index, i| {
        const sym = self.symtab[i];
        if (sym.st_shndx != elf.SHN_UNDEF) continue;

        const global = elf_file.getSymbol(index);
        const file = global.getFile(elf_file) orelse continue;
        if (!file.isAlive()) {
            file.setAlive();
            file.markLive(elf_file);
        }
    }
}

pub fn calcSymtabSize(self: *SharedObject, elf_file: *Elf) !void {
    if (elf_file.options.strip_all) return;

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        if (global.getFile(elf_file)) |file| if (file.getIndex() != self.index) continue;
        if (global.isLocal()) continue;
        global.output_symtab = true;
        self.output_symtab_size.nglobals += 1;
        self.output_symtab_size.strsize += @intCast(u32, global.getName(elf_file).len + 1);
    }
}

pub fn writeSymtab(self: *SharedObject, elf_file: *Elf, ctx: Elf.WriteSymtabCtx) !void {
    if (elf_file.options.strip_all) return;

    const gpa = elf_file.base.allocator;

    var iglobal = ctx.iglobal;
    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        if (global.getFile(elf_file)) |file| if (file.getIndex() != self.index) continue;
        if (!global.output_symtab) continue;
        const st_name = try ctx.strtab.insert(gpa, global.getName(elf_file));
        ctx.symtab[iglobal] = global.asElfSym(st_name, elf_file);
        iglobal += 1;
    }
}

pub inline fn getShdrs(self: *SharedObject) []align(1) const elf.Elf64_Shdr {
    const header = self.header orelse return &[0]elf.Elf64_Shdr{};
    return @ptrCast([*]align(1) const elf.Elf64_Shdr, self.data.ptr + header.e_shoff)[0..header.e_shnum];
}

pub inline fn getShdrContents(self: *SharedObject, index: u16) []const u8 {
    const shdr = self.getShdrs()[index];
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

pub inline fn getString(self: *SharedObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.ptr + off), 0);
}

pub inline fn getVersionString(self: *SharedObject, index: u32) ?[:0]const u8 {
    if (self.versymtab.len == 0) return null;
    const off = self.verstrings.items[index];
    return self.getString(off);
}

pub fn asFile(self: *SharedObject) File {
    return .{ .shared = self };
}

fn getDynamicTable(self: *SharedObject) []align(1) const elf.Elf64_Dyn {
    const shndx = self.dynamic_sect_index orelse return &[0]elf.Elf64_Dyn{};
    const raw = self.getShdrContents(shndx);
    const num = @divExact(raw.len, @sizeOf(elf.Elf64_Dyn));
    return @ptrCast([*]align(1) const elf.Elf64_Dyn, raw.ptr)[0..num];
}

fn getVerdefNum(self: *SharedObject) u32 {
    const entries = self.getDynamicTable();
    for (entries) |entry| switch (entry.d_tag) {
        elf.DT_VERDEFNUM => return @intCast(u32, entry.d_val),
        else => {},
    };
    return 0;
}

pub fn getSoname(self: *SharedObject) []const u8 {
    const entries = self.getDynamicTable();
    for (entries) |entry| switch (entry.d_tag) {
        elf.DT_SONAME => return self.getString(@intCast(u32, entry.d_val)),
        else => {},
    };
    return self.path;
}

pub inline fn getGlobals(self: *SharedObject) []const u32 {
    return self.symbols.items;
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
