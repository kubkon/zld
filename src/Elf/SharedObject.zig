name: []const u8,
data: []const u8,
index: u32,

header: ?elf.Elf64_Ehdr = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},

globals: std.ArrayListUnmanaged(u32) = .{},

needed: bool,
alive: bool,

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
    self.globals.deinit(allocator);
}

pub fn parse(self: *SharedObject, elf_file: *Elf) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);
    const shdrs = self.getShdrs();

    const dynsym_index = for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_DYNSYM => break @intCast(u16, i),
        else => {},
    } else null;

    if (dynsym_index) |index| {
        const shdr = shdrs[index];
        const symtab = self.getShdrContents(index);
        const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
        self.symtab = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
        self.strtab = self.getShdrContents(@intCast(u16, shdr.sh_link));
    }

    try self.initSymtab(elf_file);
}

fn initSymtab(self: *SharedObject, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    try self.globals.ensureTotalCapacityPrecise(gpa, self.symtab.len);

    for (self.symtab, 0..) |sym, i| {
        const sym_idx = @intCast(u32, i);
        const name = self.getString(sym.st_name);
        const gop = try elf_file.getOrCreateGlobal(name);
        if (!gop.found_existing) {
            const global = elf_file.getGlobal(gop.index);
            self.setGlobal(sym_idx, global);
        }
        self.globals.addOneAssumeCapacity().* = gop.index;
    }
}

fn setGlobal(self: SharedObject, sym_idx: u32, global: *Symbol) void {
    const sym = self.symtab[sym_idx];
    const name = global.name;
    global.* = .{
        .value = sym.st_value,
        .name = name,
        .atom = 0,
        .sym_idx = sym_idx,
        .file = self.index,
    };
}

pub inline fn getShdrs(self: SharedObject) []align(1) const elf.Elf64_Shdr {
    const header = self.header orelse return &[0]elf.Elf64_Shdr{};
    return @ptrCast([*]align(1) const elf.Elf64_Shdr, self.data.ptr + header.e_shoff)[0..header.e_shnum];
}

pub inline fn getShdrContents(self: SharedObject, index: u16) []const u8 {
    const shdr = self.getShdrs()[index];
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

pub inline fn getSourceSymbol(self: SharedObject, index: u32) elf.Elf64_Sym {
    assert(index < self.symtab.len);
    return self.symtab[index];
}

pub fn getSourceSymbolIndex(self: SharedObject, name: [:0]const u8) ?u32 {
    const ht = self.hash_table orelse return null;
    return ht.get(name, self);
}

pub inline fn getString(self: SharedObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.ptr + off), 0);
}

pub fn format(
    self: SharedObject,
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

pub fn fmtSymtab(self: *const SharedObject, elf_file: *Elf) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .shared = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    shared: *const SharedObject,
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
    for (shared.globals.items) |index| {
        const global = ctx.elf_file.getGlobal(index);
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
const Symbol = @import("Symbol.zig");
