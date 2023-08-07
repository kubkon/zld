const Object = @This();

const std = @import("std");
const coff = std.coff;
const mem = std.mem;
const fs = std.fs;
const assert = std.debug.assert;
const log = std.log.scoped(.coff);

const Allocator = mem.Allocator;

const Coff = @import("../Coff.zig");

file: fs.File,
name: []const u8,

header: CoffHeader = undefined,

symtab: std.coff.Symtab = undefined,
shdrtab: std.ArrayListUnmanaged(SectionHeader) = .{},
strtab: std.coff.Strtab = undefined,

const CoffHeader = std.coff.CoffHeader;

const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_IA64 = 0x0200;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;

const SectionHeader = std.coff.SectionHeader;

const Symbol = std.coff.Symbol;

pub const IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xff;
pub const IMAGE_SYM_CLASS_NULL = 0;
pub const IMAGE_SYM_CLASS_AUTOMATIC = 1;
pub const IMAGE_SYM_CLASS_EXTERNAL = 2;
pub const IMAGE_SYM_CLASS_STATIC = 3;
pub const IMAGE_SYM_CLASS_REGISTER = 4;
pub const IMAGE_SYM_CLASS_EXTERNAL_DEF = 5;
pub const IMAGE_SYM_CLASS_LABEL = 6;
pub const IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7;
pub const IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8;
pub const IMAGE_SYM_CLASS_ARGUMENT = 9;
pub const IMAGE_SYM_CLASS_STRUCT_TAG = 10;
pub const IMAGE_SYN_CLASS_MEMBER_OF_UNION = 11;
pub const IMAGE_SYM_CLASS_UNION_TAG = 12;
pub const IMAGE_SYM_CLASS_TYPE_DEFINITION = 13;
pub const IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14;
pub const IMAGE_SYM_CLASS_ENUM_TAG = 15;
pub const IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16;
pub const IMAGE_SYM_CLASS_REGISTER_PARAM = 17;
pub const IMAGE_SYM_CLASS_BIT_FIELD = 18;
pub const IMAGE_SYM_CLASS_BLOCK = 100;
pub const IMAGE_SYM_CLASS_FUNCTION = 101;
pub const IMAGE_SYM_CLASS_END_OF_STRUCT = 102;
pub const IMAGE_SYM_CLASS_FILE = 103;
pub const IMAGE_SYM_CLASS_SECTION = 104;
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105;
pub const IMAGE_SYM_CLASS_CLR_TOKEN = 107;

comptime {
    assert(Symbol.sizeOf() == 18);
    assert(@sizeOf(CoffHeader) == 20);
}

pub fn deinit(self: *Object, allocator: Allocator) void {
    self.file.close();
    self.shdrtab.deinit(allocator);
    allocator.free(self.symtab.buffer);
    allocator.free(self.strtab.buffer);
    allocator.free(self.name);
}

pub fn parse(self: *Object, allocator: Allocator, cpu_arch: std.Target.Cpu.Arch, coff_file: *Coff) !void {
    const reader = self.file.reader();
    const header = try reader.readStruct(CoffHeader);

    if (header.size_of_optional_header != 0) {
        log.debug("Optional header not expected in an object file", .{});
        return error.NotObject;
    }

    if (header.machine != cpu_arch.toCoffMachine()) {
        log.debug("Invalid architecture {any}, expected {any}", .{
            header.machine,
            cpu_arch.toCoffMachine(),
        });
        return error.InvalidCpuArch;
    }
    self.header = header;

    try self.parseShdrs(allocator);
    try self.parseSymtab(allocator, coff_file);
    try self.parseStrtab(allocator, coff_file);
}

fn parseShdrs(self: *Object, allocator: Allocator) !void {
    try self.shdrtab.ensureTotalCapacity(allocator, self.header.number_of_sections);

    var i: usize = 0;
    while (i < self.header.number_of_sections) : (i += 1) {
        const section = try self.file.reader().readStruct(SectionHeader);
        self.shdrtab.appendAssumeCapacity(section);
    }
}

fn parseSymtab(self: *Object, allocator: Allocator, coff_file: *Coff) !void {
    const offset = self.header.pointer_to_symbol_table;
    try self.file.seekTo(offset);

    const size = self.header.number_of_symbols * coff.Symbol.sizeOf();
    var symtab_buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(symtab_buffer);

    const read = try self.file.reader().readAll(symtab_buffer);
    if (read < size) {
        return coff_file.base.fatal("{s}: expected symtab size {d}, got {d}", .{ size, read });
    }
    self.symtab = .{ .buffer = symtab_buffer };
}

fn parseStrtab(self: *Object, allocator: Allocator, coff_file: *Coff) !void {
    if (self.header.pointer_to_symbol_table == 0) return error.NoStringTable;

    const offset = self.header.pointer_to_symbol_table + coff.Symbol.sizeOf() * self.header.number_of_symbols;
    try self.file.seekTo(offset);

    const size = try self.file.reader().readIntLittle(u32) - 4;
    var strtab_buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(strtab_buffer);

    const read = try self.file.reader().readAll(strtab_buffer);
    if (read < size) {
        return coff_file.base.fatal("{s}: expected strtab size {d}, got {d}", .{ size, read });
    }
    self.strtab = .{ .buffer = strtab_buffer };
}

pub fn getString(self: *const Object, off: u32) []const u8 {
    return self.strtab.get(off);
}
