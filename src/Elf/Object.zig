const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;

file: fs.File,
name: []const u8,

header: ?elf.Elf64_Ehdr = null,

shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
shstrtab: std.ArrayListUnmanaged(u8) = .{},

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symtab_index: ?u16 = null,
strtab_index: ?u16 = null,

pub fn deinit(self: *Object, allocator: *Allocator) void {
    self.shdrs.deinit(allocator);
    self.shstrtab.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    allocator.free(self.name);
}

pub fn parse(self: *Object, allocator: *Allocator, target: std.Target) !void {
    const reader = self.file.reader();
    const header = try reader.readStruct(elf.Elf64_Ehdr);

    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) {
        log.debug("Invalid ELF magic {s}, expected \x7fELF", .{header.e_ident[0..4]});
        return error.NotObject;
    }
    if (header.e_ident[elf.EI_VERSION] != 1) {
        log.debug("Unknown ELF version {d}, expected 1", .{header.e_ident[elf.EI_VERSION]});
        return error.NotObject;
    }
    if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) {
        log.err("TODO big endian support", .{});
        return error.TODOBigEndianSupport;
    }
    if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) {
        log.err("TODO 32bit support", .{});
        return error.TODOElf32bitSupport;
    }
    if (header.e_type != elf.ET.REL) {
        log.debug("Invalid file type {any}, expected ET.REL", .{header.e_type});
        return error.NotObject;
    }
    if (header.e_machine != target.cpu.arch.toElfMachine()) {
        log.debug("Invalid architecture {any}, expected {any}", .{
            header.e_machine,
            target.cpu.arch.toElfMachine(),
        });
        return error.InvalidCpuArch;
    }
    if (header.e_version != 1) {
        log.debug("Invalid ELF version {d}, expected 1", .{header.e_version});
        return error.NotObject;
    }

    assert(header.e_entry == 0);
    assert(header.e_phoff == 0);
    assert(header.e_phnum == 0);

    self.header = header;

    try self.parseShdrs(allocator, reader);
}

fn parseShdrs(self: *Object, allocator: *Allocator, reader: anytype) !void {
    const shnum = self.header.?.e_shnum;
    if (shnum == 0) return;

    try reader.context.seekTo(self.header.?.e_shoff);
    try self.shdrs.ensureTotalCapacity(allocator, shnum);

    var i: u16 = 0;
    while (i < shnum) : (i += 1) {
        const shdr = try reader.readStruct(elf.Elf64_Shdr);
        self.shdrs.appendAssumeCapacity(shdr);
    }

    // Parse shstrtab
    const shstrtab_shdr = self.shdrs.items[self.header.?.e_shstrndx];
    var buffer = try allocator.alloc(u8, shstrtab_shdr.sh_size);
    defer allocator.free(buffer);

    const amt = try self.file.preadAll(buffer, shstrtab_shdr.sh_offset);
    if (amt != buffer.len) {
        return error.InputOutput;
    }

    try self.shstrtab.appendSlice(allocator, buffer);
}
