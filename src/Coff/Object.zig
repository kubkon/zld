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

    if (header.machine != cpu_arch.toCoffMachine()) {
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
        const symbol = sym_blk: {
            var sym: Symbol = undefined;
            var reader = self.file.reader();

            if (8 != try reader.readAll(&sym.name)) {
                return error.BadSymbolName;
            }
            sym.value = try reader.readIntLittle(u32);
            sym.section_number = @enumFromInt(try reader.readIntLittle(u16));
            sym.type = try reader.readStruct(std.coff.SymType);
            sym.storage_class = @enumFromInt(try reader.readByte());
            sym.number_of_aux_symbols = try reader.readByte();

            break :sym_blk sym;
        };

        // Ignore symbol if it has invalid section number
        if (@intFromEnum(symbol.section_number) < 1 or @intFromEnum(symbol.section_number) > self.shdrtab.items.len) {
            continue;
        }

        // Ignore auxillary symbols
        if (num_aux > 0) {
            num_aux -= 1;
            continue;
        }

        // Check for upcoming auxillary symbols
        if (symbol.number_of_aux_symbols != 0) {
            num_aux = symbol.number_of_aux_symbols;
        }

        self.symtab.appendAssumeCapacity(symbol);
    }
}

fn parseStrtab(self: *Object, allocator: Allocator) !void {
    if (self.header.pointer_to_symbol_table == 0) return error.NoStringTable;

    const offset = self.header.pointer_to_symbol_table + coff.Symbol.sizeOf() * self.header.number_of_symbols;
    try self.file.seekTo(offset);

    const size = try self.file.reader().readIntLittle(u32);
    self.strtab = try allocator.alloc(u8, size);
    _ = try self.file.reader().readAll(self.strtab);
}

pub fn getString(self: *const Object, off: u32) []const u8 {
    const local_offset = off - @sizeOf(u32);
    assert(local_offset < self.symtab.items.len);
    return mem.span(@as([*:0]const u8, @ptrCast(self.strtab.ptr + local_offset)));
}
