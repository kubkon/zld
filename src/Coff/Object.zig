path: []const u8,
file_handle: File.HandleIndex,
index: File.Index,

header: ?coff.CoffHeader = null,
sections: std.MultiArrayList(InputSection) = .{},
symtab: std.ArrayListUnmanaged(InputSymbol) = .{},
auxtab: std.MultiArrayList(AuxSymbol) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

pub fn deinit(self: *Object, allocator: Allocator) void {
    allocator.free(self.path);
    for (self.sections.items(.relocs)) |*relocs| {
        relocs.deinit(allocator);
    }
    self.sections.deinit(allocator);
    self.symtab.deinit(allocator);
    self.auxtab.deinit(allocator);
    self.strtab.deinit(allocator);
}

pub fn parse(self: *Object, coff_file: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    log.debug("parsing input object file {}", .{self.fmtPath()});

    const gpa = coff_file.base.allocator;
    const offset: usize = 0;
    const file = coff_file.getFileHandle(self.file_handle);

    var header_buffer: [@sizeOf(coff.CoffHeader)]u8 = undefined;
    {
        const amt = try file.preadAll(&header_buffer, offset);
        if (amt != @sizeOf(coff.CoffHeader)) return error.InputOutput;
    }
    self.header = @as(*align(1) const coff.CoffHeader, @ptrCast(&header_buffer)).*;

    // Parse string table
    try self.parseInputStringTable(gpa, file, offset, coff_file);

    // Parse section headers
    if (self.header.?.number_of_sections > 0) try self.parseInputSectionHeaders(gpa, file, offset);

    // Parse symbol table
    if (self.header.?.number_of_symbols > 0) try self.parseInputSymbolTable(gpa, file, offset);

    for (self.sections.items(.header)) |header| {
        std.debug.print("{s}\n", .{self.getString(header.name)});
    }

    for (self.symtab.items) |sym| {
        std.debug.print("{s}\n", .{self.getString(sym.name)});
        for (self.auxtab.items(.tags)[sym.index_of_aux_symbols..][0..sym.number_of_aux_symbols]) |aux| {
            std.debug.print("  {s}\n", .{@tagName(aux)});
        }
    }

    // Init symbols
    // Init atoms
}

fn parseInputSectionHeaders(self: *Object, allocator: Allocator, file: std.fs.File, offset: usize) !void {
    const num_sects = self.header.?.number_of_sections;
    try self.sections.ensureUnusedCapacity(allocator, num_sects);
    const raw_sects_size = num_sects * @sizeOf(coff.SectionHeader);
    const buffer = try allocator.alloc(u8, raw_sects_size);
    defer allocator.free(buffer);
    var amt = try file.preadAll(buffer, offset + @sizeOf(coff.CoffHeader));
    if (amt != raw_sects_size) return error.InputOutput;
    const sections = @as([*]align(1) const coff.SectionHeader, @ptrCast(buffer.ptr))[0..num_sects];
    var relocs_buffer = std.ArrayList(u8).init(allocator);
    defer relocs_buffer.deinit();
    for (sections) |header| {
        const index = try self.sections.addOne(allocator);
        const name = if (header.getNameOffset()) |off|
            off - 4
        else
            try self.insertString(allocator, header.getName().?);
        self.sections.set(index, .{ .header = .{
            .name = name,
            .virtual_size = header.virtual_size,
            .virtual_address = header.virtual_address,
            .size_of_raw_data = header.size_of_raw_data,
            .pointer_to_raw_data = header.pointer_to_raw_data,
            .pointer_to_relocations = header.pointer_to_relocations,
            .pointer_to_linenumbers = header.pointer_to_linenumbers,
            .number_of_relocations = header.number_of_relocations,
            .number_of_linenumbers = header.number_of_linenumbers,
            .flags = header.flags,
        } });
        const relocs = &self.sections.items(.relocs)[index];

        if (header.number_of_relocations > 0) {
            try relocs.ensureTotalCapacityPrecise(allocator, header.number_of_relocations);
            const raw_relocs_size = header.number_of_relocations * relocation_entry_size;
            try relocs_buffer.ensureUnusedCapacity(raw_relocs_size);
            try relocs_buffer.resize(raw_relocs_size);
            defer relocs_buffer.clearRetainingCapacity();
            amt = try file.preadAll(relocs_buffer.items, offset + header.pointer_to_relocations);
            if (amt != raw_relocs_size) return error.InputOutput;
            var i: usize = 0;
            while (i < header.number_of_relocations) : (i += 1) {
                const reloc = @as(*align(1) const Relocation, @ptrCast(relocs_buffer.items.ptr + i * 10)).*;
                relocs.appendAssumeCapacity(reloc);
            }
        }
    }
}

fn parseInputSymbolTable(self: *Object, allocator: Allocator, file: std.fs.File, offset: usize) !void {
    const num_symbols = self.header.?.number_of_symbols;
    const raw_size = num_symbols * symtab_entry_size;
    const buffer = try allocator.alloc(u8, raw_size);
    defer allocator.free(buffer);
    const amt = try file.preadAll(buffer, offset + self.header.?.pointer_to_symbol_table);
    if (amt != raw_size) return error.InputOutput;
    const symtab = coff.Symtab{ .buffer = buffer };
    var slice = symtab.slice(0, null);

    var index: usize = 0;
    var aux_counter: usize = 0;
    var aux_tag: ?coff.Symtab.Tag = null;
    while (slice.next()) |rec| {
        if (aux_counter == 0) {
            const name_off = if (rec.getNameOffset()) |off|
                off - 4
            else
                try self.insertString(allocator, rec.getName().?);
            const name = self.getString(name_off);
            try self.symtab.append(allocator, .{
                .name = name_off,
                .value = rec.value,
                .section_number = rec.section_number,
                .type = rec.type,
                .storage_class = rec.storage_class,
                .index_of_aux_symbols = @intCast(self.auxtab.slice().len),
                .number_of_aux_symbols = 0,
            });

            aux_tag = aux_tag: {
                switch (rec.section_number) {
                    .UNDEFINED => {
                        if (rec.storage_class == .WEAK_EXTERNAL and rec.value == 0) {
                            break :aux_tag .weak_ext;
                        }
                    },
                    .ABSOLUTE => {},
                    .DEBUG => {
                        if (rec.storage_class == .FILE) {
                            break :aux_tag .file_def;
                        }
                    },
                    else => {
                        if (rec.storage_class == .FUNCTION) {
                            break :aux_tag .debug_info;
                        }
                        if (rec.storage_class == .EXTERNAL and rec.type.complex_type == .FUNCTION) {
                            break :aux_tag .func_def;
                        }
                        if (rec.storage_class == .STATIC) {
                            for (self.sections.items(.header)) |header| {
                                const sect_name = self.getString(header.name);
                                if (mem.eql(u8, sect_name, name)) {
                                    break :aux_tag .sect_def;
                                }
                            }
                        }
                    },
                }
                break :aux_tag null;
            };
            aux_counter = rec.number_of_aux_symbols;
        } else {
            const sym = &self.symtab.items[self.symtab.items.len - 1];
            if (aux_tag) |tag| switch (symtab.at(index, tag)) {
                .weak_ext => |weak_ext| {
                    try self.auxtab.append(allocator, .{ .weak = weak_ext });
                    sym.number_of_aux_symbols += 1;
                },
                .file_def => |*file_def| {
                    const auxtab_index = try self.auxtab.addOne(allocator);
                    self.auxtab.set(auxtab_index, .{ .file = undefined });
                    const el = &self.auxtab.items(.data)[auxtab_index].file;
                    @memcpy(&el.file_name, &file_def.file_name);
                    sym.number_of_aux_symbols += 1;
                },
                .sect_def => |sect_def| {
                    const sect = self.sections.items(.header)[@intFromEnum(sym.section_number) - 1];
                    if (!sect.isComdat()) {
                        // TODO convert into an error
                        // Expected non COMDAT section would not set the selection field in aux record.
                        assert(sect_def.selection == .NONE);
                    }
                    try self.auxtab.append(allocator, .{ .sect = sect_def });
                    sym.number_of_aux_symbols += 1;
                },
                .debug_info => |debug_info| {
                    try self.auxtab.append(allocator, .{ .debug_info = debug_info });
                    sym.number_of_aux_symbols += 1;
                },
                else => |other| {
                    log.warn("{s}: unhandled auxiliary symbol: {}", .{ self.fmtPath(), other });
                },
            };
            aux_counter -= 1;
        }

        index += 1;
    }
}

fn parseInputStringTable(
    self: *Object,
    allocator: Allocator,
    file: std.fs.File,
    offset: usize,
    coff_file: *Coff,
) !void {
    const strtab_offset = offset + self.header.?.pointer_to_symbol_table + self.header.?.number_of_symbols * symtab_entry_size;
    var size_buffer: [@sizeOf(u32)]u8 = undefined;
    var amt = try file.preadAll(&size_buffer, strtab_offset);
    if (amt != @sizeOf(u32)) return error.InputOutput;
    var strtab_size = mem.readInt(u32, &size_buffer, .little);
    if (strtab_size < @sizeOf(u32)) {
        coff_file.base.fatal("{}: malformed object: invalid strtab size", .{self.fmtPath()});
        return error.ParseFailed;
    }
    strtab_size -= @sizeOf(u32);
    try self.strtab.ensureTotalCapacityPrecise(allocator, strtab_size);
    try self.strtab.resize(allocator, strtab_size);
    amt = try file.preadAll(self.strtab.items, strtab_offset + @sizeOf(u32));
    if (amt != strtab_size) return error.InputOutput;
}

pub fn getString(self: Object, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

fn insertString(self: *Object, allocator: Allocator, str: []const u8) !u32 {
    const off: u32 = @intCast(self.strtab.items.len);
    try self.strtab.ensureUnusedCapacity(allocator, str.len + 1);
    self.strtab.appendSliceAssumeCapacity(str);
    self.strtab.appendAssumeCapacity(0);
    return off;
}

pub fn fmtPath(self: Object) std.fmt.Formatter(formatPath) {
    return .{ .data = self };
}

fn formatPath(
    object: Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll(object.path);
}

const InputSection = struct {
    header: SectionHeader,
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
};

const SectionHeader = struct {
    name: u32,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    flags: coff.SectionHeaderFlags,

    pub fn isComdat(hdr: SectionHeader) bool {
        return hdr.flags.LNK_COMDAT == 0b1;
    }

    pub fn isCode(hdr: SectionHeader) bool {
        return hdr.flags.CNT_CODE == 0b1;
    }

    pub fn getAlignment(hdr: SectionHeader) ?u16 {
        if (hdr.flags.ALIGN == 0) return null;
        return std.math.powi(u16, 2, hdr.flags.ALIGN - 1) catch return null;
    }
};

const Relocation = extern struct {
    virtual_address: u32,
    symbol_table_index: u32,
    type: u16,
};

const ImageRelAmd64 = enum(u16) {
    /// The relocation is ignored.
    absolute = 0,

    /// The 64-bit VA of the relocation target.
    addr64 = 1,

    /// The 32-bit VA of the relocation target.
    addr32 = 2,

    /// The 32-bit address without an image base.
    addr32nb = 3,

    /// The 32-bit relative address from the byte following the relocation.
    rel32 = 4,

    /// The 32-bit address relative to byte distance 1 from the relocation.
    rel32_1 = 5,

    /// The 32-bit address relative to byte distance 2 from the relocation.
    rel32_2 = 6,

    /// The 32-bit address relative to byte distance 3 from the relocation.
    rel32_3 = 7,

    /// The 32-bit address relative to byte distance 4 from the relocation.
    rel32_4 = 8,

    /// The 32-bit address relative to byte distance 5 from the relocation.
    rel32_5 = 9,

    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    section = 10,

    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    secrel = 11,

    /// A 7-bit unsigned offset from the base of the section that contains the target.
    secrel7 = 12,

    /// CLR tokens.
    token = 13,

    /// A 32-bit signed span-dependent value emitted into the object.
    srel32 = 14,

    /// A pair that must immediately follow every span-dependent value.
    pair = 15,

    /// A 32-bit signed span-dependent value that is applied at link time.
    sspan32 = 16,
};

const ImageRelArm64 = enum(u16) {
    /// The relocation is ignored.
    absolute = 0,

    /// The 32-bit VA of the target.
    addr32 = 1,

    /// The 32-bit RVA of the target.
    addr32nb = 2,

    /// The 26-bit relative displacement to the target, for B and BL instructions.
    branch26 = 3,

    /// The page base of the target, for ADRP instruction.
    pagebase_rel21 = 4,

    /// The 21-bit relative displacement to the target, for instruction ADR.
    rel21 = 5,

    /// The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    pageoffset_12a = 6,

    /// The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
    pageoffset_12l = 7,

    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    secrel = 8,

    /// Bit 0:11 of section offset of the target for instructions ADD/ADDS (immediate) with zero shift.
    low12a = 9,

    /// Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    high12a = 10,

    /// Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
    low12l = 11,

    /// CLR token.
    token = 12,

    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    section = 13,

    /// The 64-bit VA of the relocation target.
    addr64 = 14,

    /// The 19-bit offset to the relocation target, for conditional B instruction.
    branch19 = 15,

    /// The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
    branch14 = 16,

    /// The 32-bit relative address from the byte following the relocation.
    rel32 = 17,
};

const InputSymbol = struct {
    name: u32,
    value: u32,
    section_number: coff.SectionNumber,
    type: coff.SymType,
    storage_class: coff.StorageClass,
    index_of_aux_symbols: u32,
    number_of_aux_symbols: u8,
};

const AuxSymbolTag = enum {
    file,
    func,
    debug_info,
    sect,
    weak,
};

const AuxSymbol = union(AuxSymbolTag) {
    file: coff.FileDefinition,
    func: coff.FunctionDefinition,
    debug_info: coff.DebugInfoDefinition,
    sect: coff.SectionDefinition,
    weak: coff.WeakExternalDefinition,
};

const relocation_entry_size = 10;
const symtab_entry_size = 18;

const assert = std.debug.assert;
const coff = std.coff;
const mem = std.mem;
const fs = std.fs;
const log = std.log.scoped(.coff);
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const Object = @This();
