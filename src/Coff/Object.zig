const Object = @This();

const std = @import("std");
const coff = std.coff;
const mem = std.mem;
const fs = std.fs;
const assert = std.debug.assert;
const log = std.log.scoped(.coff);

const Allocator = mem.Allocator;

file: fs.File,
name: []const u8,

header: CoffHeader = undefined,

symtab: std.ArrayListUnmanaged(Symbol) = .{},
shdrtab: std.ArrayListUnmanaged(SectionHeader) = .{},
strtab: []u8 = undefined,

// TODO: Make these public in std.coff
const CoffHeader = packed struct {
    machine: u16,
    number_of_sections: u16,
    timedate_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};

const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_IA64 = 0x0200;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;

const SectionHeader = packed struct {
    const Misc = packed union {
        physical_address: u32,
        virtual_size: u32,
    };

    name: [8]u8,
    misc: Misc,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
};

const Symbol = packed struct {
    name: [8]u8,
    value: u32,
    sect_num: i16,
    type: u16,
    storage_class: i8,
    num_aux: u8,

    pub fn getName(self: Symbol, object: *Object) []const u8 {
        if (mem.readIntNative(u32, self.name[0..4]) == 0x0) {
            const offset = mem.readIntNative(u32, self.name[4..]);
            return object.getString(offset);
        } else {
            return mem.span(@ptrCast([*:0]const u8, &self.name));
        }
    }
};

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
    assert(@sizeOf(Symbol) == 18);
    assert(@sizeOf(CoffHeader) == 20);
}

pub fn deinit(self: *Object, allocator: Allocator) void {
    self.symtab.deinit(allocator);
    self.shdrtab.deinit(allocator);
    allocator.free(self.strtab);
    allocator.free(self.name);
}

pub fn parse(self: *Object, allocator: Allocator, cpu_arch: std.Target.Cpu.Arch) !void {
    const reader = self.file.reader();
    const header = try reader.readStruct(CoffHeader);

    if (header.size_of_optional_header != 0) {
        log.debug("Optional header not expected in an object file", .{});
        return error.NotObject;
    }

    if (header.machine != @enumToInt(cpu_arch.toCoffMachine())) {
        log.debug("Invalid architecture {any}, expected {any}", .{
            header.machine,
            cpu_arch.toCoffMachine(),
        });
        return error.InvalidCpuArch;
    }
    self.header = header;

    try self.parseShdrs(allocator);
    try self.parseSymtab(allocator);
    try self.parseStrtab(allocator);
}

fn parseShdrs(self: *Object, allocator: Allocator) !void {
    try self.shdrtab.ensureTotalCapacity(allocator, self.header.number_of_sections);

    var i: usize = 0;
    while (i < self.header.number_of_sections) : (i += 1) {
        const section = try self.file.reader().readStruct(SectionHeader);
        self.shdrtab.appendAssumeCapacity(section);
    }
}

fn parseSymtab(self: *Object, allocator: Allocator) !void {
    const offset = self.header.pointer_to_symbol_table;
    try self.file.seekTo(offset);

    try self.symtab.ensureTotalCapacity(allocator, self.header.number_of_symbols);

    var i: usize = 0;
    var num_aux: usize = 0;
    while (i < self.header.number_of_symbols) : (i += 1) {
        const symbol = try self.file.reader().readStruct(Symbol);

        // Ignore symbol if it has invalid section number
        if (symbol.sect_num < 1 or symbol.sect_num > self.shdrtab.items.len) {
            continue;
        }

        // Ignore auxillary symbols
        if (num_aux > 0) {
            num_aux -= 1;
            continue;
        }

        // Check for upcoming auxillary symbols
        if (symbol.num_aux != 0) {
            num_aux = symbol.num_aux;
        }

        self.symtab.appendAssumeCapacity(symbol);
    }
}

fn parseStrtab(self: *Object, allocator: Allocator) !void {
    const string_table_size = (try self.file.reader().readIntNative(u32)) - @sizeOf(u32);

    self.strtab = try allocator.alloc(u8, string_table_size);
    _ = try self.file.reader().read(self.strtab);
}

pub fn getString(self: *Object, off: u32) []const u8 {
    const local_offset = off - @sizeOf(u32);
    assert(local_offset < self.symtab.items.len);
    return mem.span(@ptrCast([*:0]const u8, self.strtab.ptr + local_offset));
}
