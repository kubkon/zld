name: []const u8,
index: u32,
needed: bool,

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
hash_table: ?HashTable = null,

const HashTable = struct {
    buckets: std.ArrayListUnmanaged(u32) = .{},
    chain: std.ArrayListUnmanaged(u32) = .{},

    fn init(allocator: Allocator, data: []const u8, nbucket: u32, nchain: u32) !HashTable {
        const bucketoff: usize = 8;
        const chainoff: usize = bucketoff + 4 * nbucket;
        var ht = HashTable{
            .data = try allocator.dupe(u8, data),
            .buckets = undefined,
            .chain = undefined,
        };
        ht.buckets = @ptrCast([*]align(1) const u32, ht.data[bucketoff..])[0..nbucket];
        ht.chain = @ptrCast([*]align(1) const u32, ht.data[chainoff..])[0..nchain];
        return ht;
    }

    fn deinit(ht: *HashTable, allocator: Allocator) void {
        ht.buckets.deinit(allocator);
        ht.chain.deinit(allocator);
    }

    const Ctx = struct {
        symtab: []const elf.Elf64_Sym,
        strtab: []const u8,

        inline fn getString(ctx: Ctx, off: u32) [:0]const u8 {
            assert(off < ctx.strtab.len);
            return mem.sliceTo(@ptrCast([*:0]const u8, ctx.strtab.ptr + off), 0);
        }
    };

    fn get(ht: *const HashTable, name: [:0]const u8, ctx: Ctx) ?u32 {
        const h = hasher(name);
        var index = ht.buckets.items[h % ht.buckets.items.len];
        while (index != STN_UNDEF) : (index = ht.chain.items[index]) {
            const sym = ctx.symtab[index];
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

const STN_UNDEF = 0;

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
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    allocator.free(self.name);
    if (self.hash_table) |*ht| {
        ht.deinit(allocator);
    }
}

pub fn parse(self: *SharedObject, data: []const u8, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;
    const header = getEhdr(data);
    const shdrs = getShdrs(data, header);

    // TODO prefer SHT_GNU_HASH to SHT_HASH
    for (shdrs) |shdr| switch (shdr.sh_type) {
        elf.SHT_DYNSYM => {
            const symtab = getShdrContents(data, shdr);
            const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
            const syms = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
            try self.symtab.appendUnalignedSlice(gpa, syms);

            const strtab_shdr = shdrs[shdr.sh_link];
            try self.strtab.appendUnalignedSlice(gpa, getShdrContents(data, strtab_shdr));
        },
        elf.SHT_HASH => try self.initHashTable(gpa, data, shdr),
        else => {},
    };

    const sym_index = self.hash_table.?.get("puts", .{
        .symtab = self.symtab.items,
        .strtab = self.strtab.items,
    });
    log.warn("puts @{?d}", .{sym_index});
}

fn initHashTable(self: *SharedObject, allocator: Allocator, data: []const u8, shdr: elf.Elf64_Shdr) !void {
    const raw = getShdrContents(data, shdr);
    const len = @divExact(raw.len, @sizeOf(u32));
    const hash_table = @ptrCast([*]align(1) const u32, raw.ptr)[0..len];
    const nbucket = hash_table[0];
    const nchain = hash_table[1];
    const bucketoff: usize = 2;
    const chainoff: usize = bucketoff + nbucket;
    const buckets = hash_table[bucketoff..][0..nbucket];
    const chain = hash_table[chainoff..][0..nchain];
    var ht = HashTable{};
    try ht.buckets.appendUnalignedSlice(allocator, buckets);
    try ht.chain.appendUnalignedSlice(allocator, chain);
    self.hash_table = ht;
}

pub fn resolveSymbols(self: SharedObject, elf_file: *Elf) void {
    _ = self;
    _ = elf_file;
}

inline fn getEhdr(data: []const u8) elf.Elf64_Ehdr {
    return @ptrCast(*align(1) const elf.Elf64_Ehdr, data.ptr).*;
}

inline fn getShdrs(data: []const u8, header: elf.Elf64_Ehdr) []align(1) const elf.Elf64_Shdr {
    return @ptrCast([*]align(1) const elf.Elf64_Shdr, data.ptr + header.e_shoff)[0..header.e_shnum];
}

inline fn getShdrContents(data: []const u8, shdr: elf.Elf64_Shdr) []const u8 {
    return data[shdr.sh_offset..][0..shdr.sh_size];
}

pub inline fn getSourceSymbol(self: *const SharedObject, index: u32) elf.Elf64_Sym {
    assert(index < self.symtab.items.len);
    return self.symtab.items[index];
}

pub inline fn getString(self: *const SharedObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.items.ptr + off), 0);
}

test {
    _ = std.testing.refAllDecls(HashTable);
}

const SharedObject = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
