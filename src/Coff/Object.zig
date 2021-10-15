const Object = @This();

const std = @import("std");
const coff = std.coff;
const mem = std.mem;
const fs = std.fs;
const assert = std.debug.assert;

const Allocator = mem.Allocator;

file: fs.File,
name: []const u8,

header: CoffHeader = undefined,

symtab: std.ArrayListUnmanaged(Symbol) = .{},
shdrtab: std.ArrayListUnmanaged(SectionHeader) = .{},
strtab: []u8 = undefined,

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
    name: [8]u8,
    virtual_address: u32,
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
    sect_num: u16,
    type: u16,
    storage_class: u8,
    num_aux: u8,
};

comptime {
    assert(@sizeOf(Symbol) == 18);
    assert(@sizeOf(CoffHeader) == 20);
}

pub fn deinit(self: *Object, allocator: *Allocator) void {
    allocator.free(self.name);
}

pub fn parse(self: *Object, allocator: *Allocator, target: ?std.Target) !void {
    const reader = self.file.reader();
    const header = try reader.readStruct(CoffHeader);

    if (header.machine != IMAGE_FILE_MACHINE_AMD64) {
        return error.TodoSupportOtherMachines;
    }

    assert(header.size_of_optional_header == 0);

    self.header = header;

    try self.parseSectionHeaders(allocator);
    try self.parseSymbolTable(allocator);
    try self.parseStringTable(allocator);

    _ = target;
}

fn parseSectionHeaders(self: *Object, allocator: *Allocator) !void {
    try self.shdrtab.ensureTotalCapacity(allocator, self.header.number_of_sections);

    var i: usize = 0;
    while (i < self.header.number_of_sections) : (i += 1) {
        const section = try self.file.reader().readStruct(SectionHeader);
        self.shdrtab.appendAssumeCapacity(section);
    }
}

fn parseSymbolTable(self: *Object, allocator: *Allocator) !void {
    const offset = self.header.pointer_to_symbol_table;
    try self.file.seekTo(offset);

    try self.symtab.ensureTotalCapacity(allocator, self.header.number_of_symbols);

    var i: usize = 0;
    while (i < self.header.number_of_symbols) : (i += 1) {
        const symbol = try self.file.reader().readStruct(Symbol);
        
        // Ignore symbol if it has invalid section number
        if (symbol.sect_num < 1 or symbol.sect_num > self.shdrtab.items.len) {
            continue;
        }
        
        // Ignore upcoming auxillary symbols
        if (symbol.num_aux != 0) {
            continue;
        }
        
        self.symtab.appendAssumeCapacity(symbol);
    }
}

fn parseStringTable(self: *Object, allocator: *Allocator) !void {
    const string_table_size = (try self.file.reader().readIntNative(u32)) - @sizeOf(u32);

    self.strtab = try allocator.alloc(u8, string_table_size);
    _ = try self.file.reader().read(self.strtab);
}

pub fn getString(self: *Object, off: u32) []const u8 {
    assert(off < self.symtab.items.len);
    return mem.span(@ptrCast([*:0]const u8, self.strtab.ptr + off));
}
