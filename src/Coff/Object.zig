path: []const u8,
file_handle: File.HandleIndex,
index: File.Index,

header: ?coff.CoffHeader = null,
sections: std.MultiArrayList(InputSection) = .{},
symtab: std.ArrayListUnmanaged(InputSymbol) = .{},
auxtab: std.MultiArrayList(AuxSymbol) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

directives: std.ArrayListUnmanaged(u32) = .{},

atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

alive: bool = true,

pub fn deinit(self: *Object, allocator: Allocator) void {
    allocator.free(self.path);
    for (self.sections.items(.relocs)) |*relocs| {
        relocs.deinit(allocator);
    }
    self.sections.deinit(allocator);
    self.symtab.deinit(allocator);
    self.auxtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.directives.deinit(allocator);
    self.atoms.deinit(allocator);
}

pub fn parse(self: *Object, coff_file: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    log.debug("parsing input object file {}", .{self.fmtPath()});

    const gpa = coff_file.base.allocator;
    const offset: u64 = 0;
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
    if (self.header.?.number_of_symbols > 0) try self.parseInputSymbolTable(gpa, file, offset, coff_file);

    // Parse linker directives if any
    try self.parseDirectives(gpa, file, offset, coff_file);

    // Init atoms
    try self.initAtoms(gpa, coff_file);

    // Init symbols
}

fn parseInputSectionHeaders(self: *Object, allocator: Allocator, file: std.fs.File, offset: u64) !void {
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

fn parseInputSymbolTable(
    self: *Object,
    allocator: Allocator,
    file: std.fs.File,
    offset: u64,
    coff_file: *Coff,
) !void {
    const num_symbols = self.header.?.number_of_symbols;
    const raw_size = num_symbols * symtab_entry_size;
    const buffer = try allocator.alloc(u8, raw_size);
    defer allocator.free(buffer);
    const amt = try file.preadAll(buffer, offset + self.header.?.pointer_to_symbol_table);
    if (amt != raw_size) return error.InputOutput;

    const symtab = coff.Symtab{ .buffer = buffer };

    var index_map = std.AutoHashMap(u32, u32).init(allocator);
    defer index_map.deinit();
    {
        var index: u32 = 0;
        var symbol_count: u32 = 0;
        while (index < num_symbols) : ({
            index += 1;
            symbol_count += 1;
        }) {
            const sym = symtab.at(index, .symbol).symbol;
            try index_map.put(index, symbol_count);
            index += sym.number_of_aux_symbols;
        }
    }

    var index: usize = 0;
    var aux_data: struct {
        tag: ?coff.Symtab.Tag = null,
        count: u8 = 0,
    } = .{};
    while (index < num_symbols) : (index += 1) {
        if (aux_data.count > 0) {
            defer index += aux_data.count;
            defer aux_data = .{};

            if (aux_data.tag == null) continue;
            if (aux_data.count > 1 and aux_data.tag != null) switch (aux_data.tag.?) {
                .file_def => {},
                .func_def, .weak_ext, .sect_def, .debug_info => |tag| {
                    coff_file.base.fatal("{}: invalid symbol table: too many aux symbols for record type '{s}'", .{ self.fmtPath(), @tagName(tag) });
                    return error.ParseFailed;
                },
                .symbol => unreachable,
            };
            self.symtab.items[self.symtab.items.len - 1].aux_index = @intCast(self.auxtab.slice().len);

            switch (aux_data.tag.?) {
                .func_def => {
                    const func_def = symtab.at(index, .func_def).func_def;
                    try self.auxtab.append(allocator, .{
                        .func = .{
                            .sym_index = index_map.get(func_def.tag_index).?,
                            .total_size = func_def.total_size,
                            .pointer_to_linenumber = func_def.pointer_to_linenumber,
                            .pointer_to_next_function = index_map.get(func_def.pointer_to_next_function).?,
                        },
                    });
                },
                .file_def => {
                    var file_buffer = std.ArrayList(u8).init(allocator);
                    defer file_buffer.deinit();
                    var next: usize = 0;
                    while (next < aux_data.count) : (next += 1) {
                        const file_def = symtab.at(next + index, .file_def).file_def;
                        try file_buffer.writer().writeAll(file_def.getFileName());
                    }
                    try self.auxtab.append(allocator, .{
                        .file = try self.insertString(allocator, file_buffer.items),
                    });
                },
                .debug_info => {
                    const debug_info = symtab.at(index, .debug_info).debug_info;
                    try self.auxtab.append(allocator, .{
                        .debug_info = .{
                            .line_number = debug_info.linenumber,
                            .pointer_to_next_function = index_map.get(debug_info.pointer_to_next_function).?,
                        },
                    });
                },
                .sect_def => {
                    const sect_def = symtab.at(index, .sect_def).sect_def;
                    try self.auxtab.append(allocator, .{ .sect = .{
                        .length = sect_def.length,
                        .number_of_relocations = sect_def.number_of_relocations,
                        .number_of_linenumbers = sect_def.number_of_linenumbers,
                        .checksum = sect_def.checksum,
                        .number = sect_def.number,
                        .selection = sect_def.selection,
                    } });
                },
                .weak_ext => {
                    const weak_ext = symtab.at(index, .weak_ext).weak_ext;
                    try self.auxtab.append(allocator, .{
                        .weak = .{
                            .sym_index = index_map.get(weak_ext.tag_index).?,
                            .flag = weak_ext.flag,
                        },
                    });
                },
                .symbol => unreachable,
            }
        } else {
            const rec = symtab.at(index, .symbol).symbol;
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
                .aux_index = null,
            });

            aux_data.tag = switch (rec.section_number) {
                .UNDEFINED => if (rec.storage_class == .WEAK_EXTERNAL and rec.value == 0)
                    .weak_ext
                else
                    null,
                .ABSOLUTE => null,
                .DEBUG => if (rec.storage_class == .FILE)
                    .file_def
                else
                    null,
                else => tag: {
                    if (rec.storage_class == .FUNCTION) {
                        break :tag .debug_info;
                    }
                    if (rec.storage_class == .EXTERNAL and rec.type.complex_type == .FUNCTION) {
                        break :tag .func_def;
                    }
                    if (rec.storage_class == .STATIC) {
                        for (self.sections.items(.header)) |header| {
                            const sect_name = self.getString(header.name);
                            if (mem.eql(u8, sect_name, name)) {
                                break :tag .sect_def;
                            }
                        }
                    }
                    break :tag null;
                },
            };
            aux_data.count = rec.number_of_aux_symbols;
        }
    }
}

fn parseInputStringTable(
    self: *Object,
    allocator: Allocator,
    file: std.fs.File,
    offset: u64,
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

fn parseDirectives(self: *Object, allocator: Allocator, file: std.fs.File, offset: u64, coff_file: *Coff) !void {
    for (self.sections.items(.header), self.sections.items(.relocs)) |header, relocs| {
        if (header.flags.LNK_INFO == 0b1 and mem.eql(u8, self.getString(header.name), ".drectve")) {
            if (relocs.items.len > 0) {
                coff_file.base.fatal("{}: unexpected relocations for .drectve section", .{self.fmtPath()});
                return error.ParseFailed;
            }

            const buffer = try allocator.alloc(u8, header.size_of_raw_data);
            defer allocator.free(buffer);
            const amt = try file.preadAll(buffer, offset + header.pointer_to_raw_data);
            if (amt != header.size_of_raw_data) return error.InputOutput;

            var it = mem.splitScalar(u8, buffer, ' ');
            while (it.next()) |dir| {
                if (dir.len == 0) continue;
                const off = try self.insertString(allocator, dir);
                try self.directives.append(allocator, off);
            }
        }
    }
}

fn initAtoms(self: *Object, allocator: Allocator, coff_file: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const headers = self.sections.items(.header);
    try self.atoms.resize(allocator, headers.len);
    @memset(self.atoms.items, 0);

    for (headers, 0..) |header, i| {
        if (header.flags.LNK_REMOVE == 0b1) continue;

        // TODO handle LNK_COMDAT
        if (self.skipSection(@intCast(i))) continue;
        try self.addAtom(header, @intCast(i), coff_file);
    }
}

fn skipSection(self: *Object, index: u16) bool {
    const header = self.sections.items(.header)[index];
    const name = self.getString(header.name);
    const ignore = blk: {
        if (header.flags.LNK_INFO == 0b1) break :blk true; // TODO info sections
        if (mem.startsWith(u8, name, ".debug")) break :blk true; // TODO debug info
        break :blk false;
    };
    return ignore;
}

fn addAtom(self: *Object, header: Coff.SectionHeader, section_number: u16, coff_file: *Coff) !void {
    const atom_index = try coff_file.addAtom();
    const atom = coff_file.getAtom(atom_index).?;
    atom.atom_index = atom_index;
    atom.file = self.index;
    atom.name = header.name; // TODO do we handle $ here?
    atom.section_number = section_number;
    atom.size = header.size_of_raw_data;
    atom.alignment = header.getAlignment() orelse {
        coff_file.base.fatal("{}: malformed section header #{X}, '{s}': missing alignment flag", .{
            self.fmtPath(),
            section_number,
            self.getString(header.name),
        });
        return error.ParseFailed;
    };
    self.atoms.items[section_number] = atom_index;
}

pub fn getString(self: Object, off: u32) [:0]const u8 {
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

pub fn format(
    self: *Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format objects directly");
}

const FormatContext = struct {
    object: *Object,
    coff_file: *Coff,
};

pub fn fmtAtoms(self: *Object, coff_file: *Coff) std.fmt.Formatter(formatAtoms) {
    return .{ .data = .{
        .object = self,
        .coff_file = coff_file,
    } };
}

fn formatAtoms(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.writeAll("  atoms\n");
    for (object.atoms.items) |atom_index| {
        const atom = ctx.coff_file.getAtom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(ctx.coff_file)});
    }
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

pub const InputSection = struct {
    header: Coff.SectionHeader,
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
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
    aux_index: ?u32,
};

const AuxSymbolTag = enum {
    file,
    func,
    debug_info,
    sect,
    weak,
};

const AuxSymbol = union(AuxSymbolTag) {
    file: u32,
    func: struct {
        sym_index: u32,
        total_size: u32,
        pointer_to_linenumber: u32,
        pointer_to_next_function: u32,
    },
    debug_info: struct {
        line_number: u16,
        pointer_to_next_function: u32,
    },
    sect: struct {
        length: u32,
        number_of_relocations: u16,
        number_of_linenumbers: u16,
        checksum: u32,
        number: u16,
        selection: coff.ComdatSelection,
    },
    weak: struct {
        sym_index: u32,
        flag: coff.WeakExternalFlag,
    },
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
const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const Object = @This();
