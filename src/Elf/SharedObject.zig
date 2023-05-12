name: []const u8,
index: u32,
needed: bool,

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
hash_table: ?HashTable = null,

const HashTable = struct {
    data: []const u8,
    buckets: []align(1) const u32,
    chain: []align(1) const u32,

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
        allocator.free(ht.data);
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
    const hash_shdr = for (shdrs) |shdr| switch (shdr.sh_type) {
        elf.SHT_HASH => break shdr,
        else => {},
    } else @panic("TODO create hash table manually I guess");
    const symtab_shdr = shdrs[hash_shdr.sh_link];
    const strtab_shdr = shdrs[symtab_shdr.sh_link];

    // Parse dynamic symbol and string tables
    const symtab = getShdrContents(data, symtab_shdr);
    const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
    const syms = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
    try self.symtab.appendUnalignedSlice(gpa, syms);
    try self.strtab.appendUnalignedSlice(gpa, getShdrContents(data, strtab_shdr));

    // Parse hash table
    const raw_hash_table = getShdrContents(data, hash_shdr);
    const nbucket = mem.readIntLittle(u32, raw_hash_table[0..4]);
    const nchain = mem.readIntLittle(u32, raw_hash_table[4..8]);
    self.hash_table = try HashTable.init(gpa, raw_hash_table, nbucket, nchain);
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

test {
    _ = std.testing.refAllDecls(HashTable);
}

const SharedObject = @This();

const std = @import("std");
const elf = std.elf;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
