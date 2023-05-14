name: []const u8,
data: []const u8,
index: u32,

header: ?elf.Elf64_Ehdr = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},

hash_table: ?HashTable = null,

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

    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_DYNSYM => {
            const symtab = self.getShdrContents(@intCast(u16, i));
            const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
            self.symtab = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
            self.strtab = self.getShdrContents(@intCast(u16, shdr.sh_link));
        },
        elf.SHT_HASH => self.initHashTable(@intCast(u16, i)),
        else => {},
    };

    if (self.hash_table == null) return elf_file.base.fatal("{s}: no .hash section in DSO", .{self.name});
}

fn initHashTable(self: *SharedObject, index: u16) void {
    const raw = self.getShdrContents(index);
    const len = @divExact(raw.len, @sizeOf(u32));
    const hash_table = @ptrCast([*]align(1) const u32, raw.ptr)[0..len];
    const nbucket = hash_table[0];
    const nchain = hash_table[1];
    const bucketoff: usize = 2;
    const chainoff: usize = bucketoff + nbucket;
    self.hash_table = .{
        .buckets = hash_table[bucketoff..][0..nbucket],
        .chain = hash_table[chainoff..][0..nchain],
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

const STN_UNDEF = 0;

const HashTable = struct {
    buckets: []align(1) const u32,
    chain: []align(1) const u32,

    fn get(ht: *const HashTable, name: [:0]const u8, ctx: SharedObject) ?u32 {
        const h = hasher(name);
        var index = ht.buckets[h % ht.buckets.len];
        while (index != STN_UNDEF) : (index = ht.chain[index]) {
            const sym = ctx.getSourceSymbol(index);
            const sym_name = ctx.getString(sym.st_name);
            if (mem.eql(u8, name, sym_name)) return index;
        }
        return null;
    }

    fn hasher(name: [:0]const u8) u32 {
        var h: u32 = 0;
        var g: u32 = 0;
        for (name) |c| {
            h = (h << 4) + c;
            g = h & 0xf0000000;
            if (g > 0) h ^= g >> 24;
            h &= ~g;
        }
        return h;
    }

    test "hasher" {
        try std.testing.expectEqual(hasher(""), 0);
        try std.testing.expectEqual(hasher("printf"), 0x77905a6);
        try std.testing.expectEqual(hasher("exit"), 0x6cf04);
        try std.testing.expectEqual(hasher("syscall"), 0xb09985c);
    }
};

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");

test {
    _ = std.testing.refAllDecls(HashTable);
}
