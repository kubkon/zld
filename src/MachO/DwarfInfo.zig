debug_info: []const u8,
debug_abbrev: []const u8,
debug_str: []const u8,

abbrev_tables: std.AutoArrayHashMapUnmanaged(u64, AbbrevTable) = .{},
compile_units: std.ArrayListUnmanaged(CompileUnit) = .{},

pub fn init(dw: *DwarfInfo, allocator: Allocator) !void {
    try dw.parseAbbrevTables(allocator);
    try dw.parseCompileUnits(allocator);
}

pub fn deinit(dw: *DwarfInfo, allocator: Allocator) void {
    dw.abbrev_tables.deinit(allocator);
    for (dw.compile_units.items) |*cu| {
        cu.deinit(allocator);
    }
    dw.compile_units.deinit(allocator);
}

fn getString(dw: DwarfInfo, off: u64) [:0]const u8 {
    assert(off < dw.debug_str.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(dw.debug_str.ptr + off)), 0);
}

fn parseAbbrevTables(dw: *DwarfInfo, allocator: Allocator) !void {
    const debug_abbrev = dw.debug_abbrev;
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    while (true) {
        if (creader.bytes_read >= debug_abbrev.len) break;

        try dw.abbrev_tables.ensureUnusedCapacity(allocator, 1);
        const table_gop = dw.abbrev_tables.getOrPutAssumeCapacity(@intCast(creader.bytes_read));
        assert(!table_gop.found_existing);
        const table = table_gop.value_ptr;
        table.* = .{ .loc = .{ .pos = creader.bytes_read, .len = 0 } };

        while (true) {
            const code = try leb.readULEB128(u64, reader);
            if (code == 0) break;

            try table.decls.ensureUnusedCapacity(allocator, 1);
            const decl_gop = table.decls.getOrPutAssumeCapacity(code);
            assert(!decl_gop.found_existing);
            const decl = decl_gop.value_ptr;
            decl.* = .{
                .code = code,
                .tag = undefined,
                .children = false,
                .loc = .{ .pos = creader.bytes_read, .len = 1 },
            };
            decl.tag = try leb.readULEB128(u64, reader);
            decl.children = (try reader.readByte()) > 0;

            while (true) {
                const at = try leb.readULEB128(u64, reader);
                const form = try leb.readULEB128(u64, reader);
                if (at == 0 and form == 0) break;

                try decl.attrs.ensureUnusedCapacity(allocator, 1);
                const attr_gop = decl.attrs.getOrPutAssumeCapacity(at);
                assert(!attr_gop.found_existing);
                const attr = attr_gop.value_ptr;
                attr.* = .{
                    .at = at,
                    .form = form,
                    .loc = .{ .pos = creader.bytes_read, .len = 0 },
                };
                attr.loc.len = creader.bytes_read - attr.loc.pos;
            }

            decl.loc.len = creader.bytes_read - decl.loc.pos;
        }

        table.loc.len = creader.bytes_read - table.loc.pos;
    }
}

fn parseCompileUnits(dw: *DwarfInfo, allocator: Allocator) !void {
    const debug_info = dw.debug_info;
    var stream = std.io.fixedBufferStream(debug_info);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    while (true) {
        if (creader.bytes_read == debug_info.len) break;

        const cu = try dw.compile_units.addOne(allocator);
        cu.* = .{
            .header = undefined,
            .loc = .{ .pos = creader.bytes_read, .len = 0 },
        };

        var length: u64 = try reader.readInt(u32, .little);
        const is_64bit = length == 0xffffffff;
        if (is_64bit) {
            length = try reader.readInt(u64, .little);
        }
        cu.header.dw_format = if (is_64bit) .dwarf64 else .dwarf32;
        cu.header.length = length;
        cu.header.version = try reader.readInt(u16, .little);
        cu.header.debug_abbrev_offset = try readOffset(cu.header.dw_format, reader);
        cu.header.address_size = try reader.readInt(u8, .little);

        const table = dw.abbrev_tables.get(cu.header.debug_abbrev_offset).?;
        try dw.parseDebugInfoEntry(allocator, cu, table, null, &creader);

        cu.loc.len = creader.bytes_read - cu.loc.pos;
    }
}

fn parseDebugInfoEntry(
    dw: *DwarfInfo,
    allocator: Allocator,
    cu: *CompileUnit,
    table: AbbrevTable,
    parent: ?usize,
    creader: anytype,
) anyerror!void {
    while (creader.bytes_read < cu.nextCompileUnitOffset()) {
        const die = try cu.addDie(allocator);
        cu.diePtr(die).* = .{
            .code = undefined,
            .loc = .{ .pos = creader.bytes_read, .len = 0 },
        };
        if (parent) |p| {
            try cu.diePtr(p).children.append(allocator, die);
        } else {
            try cu.children.append(allocator, die);
        }

        const code = try leb.readULEB128(u64, creader.reader());
        cu.diePtr(die).code = code;

        if (code == 0) {
            if (parent == null) continue;
            return; // Close scope
        }

        const decl = table.decls.get(code) orelse return error.MalformedDwarf; // TODO better errors
        const data = dw.debug_info;
        try cu.diePtr(die).values.ensureTotalCapacityPrecise(allocator, decl.attrs.values().len);

        for (decl.attrs.values()) |attr| {
            const start = creader.bytes_read;
            try advanceByFormSize(cu, attr.form, creader);
            const end = creader.bytes_read;
            cu.diePtr(die).values.appendAssumeCapacity(data[start..end]);
        }

        if (decl.children) {
            // Open scope
            try dw.parseDebugInfoEntry(allocator, cu, table, die, creader);
        }

        cu.diePtr(die).loc.len = creader.bytes_read - cu.diePtr(die).loc.pos;
    }
}

fn advanceByFormSize(cu: *CompileUnit, form: u64, creader: anytype) !void {
    const reader = creader.reader();
    switch (form) {
        dwarf.FORM.strp,
        dwarf.FORM.sec_offset,
        dwarf.FORM.ref_addr,
        => {
            _ = try readOffset(cu.header.dw_format, reader);
        },

        dwarf.FORM.addr => try reader.skipBytes(cu.header.address_size, .{}),

        dwarf.FORM.block1,
        dwarf.FORM.block2,
        dwarf.FORM.block4,
        dwarf.FORM.block,
        => {
            const len: u64 = switch (form) {
                dwarf.FORM.block1 => try reader.readInt(u8, .little),
                dwarf.FORM.block2 => try reader.readInt(u16, .little),
                dwarf.FORM.block4 => try reader.readInt(u32, .little),
                dwarf.FORM.block => try leb.readULEB128(u64, reader),
                else => unreachable,
            };
            for (0..len) |_| {
                _ = try reader.readByte();
            }
        },

        dwarf.FORM.exprloc => {
            const len = try leb.readULEB128(u64, reader);
            for (0..len) |_| {
                _ = try reader.readByte();
            }
        },
        dwarf.FORM.flag_present => {},

        dwarf.FORM.data1,
        dwarf.FORM.ref1,
        dwarf.FORM.flag,
        => try reader.skipBytes(1, .{}),

        dwarf.FORM.data2,
        dwarf.FORM.ref2,
        => try reader.skipBytes(2, .{}),

        dwarf.FORM.data4,
        dwarf.FORM.ref4,
        => try reader.skipBytes(4, .{}),

        dwarf.FORM.data8,
        dwarf.FORM.ref8,
        dwarf.FORM.ref_sig8,
        => try reader.skipBytes(8, .{}),

        dwarf.FORM.udata,
        dwarf.FORM.ref_udata,
        => {
            _ = try leb.readULEB128(u64, reader);
        },

        dwarf.FORM.sdata => {
            _ = try leb.readILEB128(i64, reader);
        },

        dwarf.FORM.string => {
            while (true) {
                const byte = try reader.readByte();
                if (byte == 0x0) break;
            }
        },

        else => {
            // TODO better errors
            log.err("unhandled DW_FORM_* value with identifier {x}", .{form});
            return error.UnhandledDwFormValue;
        },
    }
}

fn readOffset(format: Format, reader: anytype) !u64 {
    return switch (format) {
        .dwarf32 => try reader.readInt(u32, .little),
        .dwarf64 => try reader.readInt(u64, .little),
    };
}

pub const AbbrevTable = struct {
    decls: std.AutoArrayHashMapUnmanaged(u64, Decl) = .{},
    loc: Loc,

    pub fn deinit(table: *AbbrevTable, gpa: Allocator) void {
        for (table.decls.values()) |*decl| {
            decl.deinit(gpa);
        }
        table.decls.deinit(gpa);
    }

    pub const Decl = struct {
        code: u64,
        tag: u64,
        children: bool,
        attrs: std.AutoArrayHashMapUnmanaged(u64, Attr) = .{},
        loc: Loc,

        pub fn deinit(decl: *Decl, gpa: Allocator) void {
            decl.attrs.deinit(gpa);
        }
    };

    pub const Attr = struct {
        at: u64,
        form: u64,
        loc: Loc,

        pub fn getFlag(attr: Attr, value: []const u8) ?bool {
            return switch (attr.form) {
                dwarf.FORM.flag => value[0] == 1,
                dwarf.FORM.flag_present => true,
                else => null,
            };
        }

        pub fn getString(attr: Attr, value: []const u8, dwf: Format, ctx: *const DwarfInfo) ?[]const u8 {
            switch (attr.form) {
                dwarf.FORM.string => {
                    return mem.sliceTo(@as([*:0]const u8, @ptrCast(value.ptr)), 0);
                },
                dwarf.FORM.strp => {
                    const off = switch (dwf) {
                        .dwarf64 => mem.readInt(u64, value[0..8], .little),
                        .dwarf32 => mem.readInt(u32, value[0..4], .little),
                    };
                    return ctx.getString(off);
                },
                else => return null,
            }
        }

        pub fn getSecOffset(attr: Attr, value: []const u8, dwf: Format) ?u64 {
            return switch (attr.form) {
                dwarf.FORM.sec_offset => switch (dwf) {
                    .dwarf32 => mem.readInt(u32, value[0..4], .little),
                    .dwarf64 => mem.readInt(u64, value[0..8], .little),
                },
                else => null,
            };
        }

        pub fn getConstant(attr: Attr, value: []const u8) !?i128 {
            var stream = std.io.fixedBufferStream(value);
            const reader = stream.reader();
            return switch (attr.form) {
                dwarf.FORM.data1 => value[0],
                dwarf.FORM.data2 => mem.readInt(u16, value[0..2], .little),
                dwarf.FORM.data4 => mem.readInt(u32, value[0..4], .little),
                dwarf.FORM.data8 => mem.readInt(u64, value[0..8], .little),
                dwarf.FORM.udata => try leb.readULEB128(u64, reader),
                dwarf.FORM.sdata => try leb.readILEB128(i64, reader),
                else => null,
            };
        }

        pub fn getReference(attr: Attr, value: []const u8, dwf: Format) !?u64 {
            var stream = std.io.fixedBufferStream(value);
            const reader = stream.reader();
            return switch (attr.form) {
                dwarf.FORM.ref1 => value[0],
                dwarf.FORM.ref2 => mem.readInt(u16, value[0..2], .little),
                dwarf.FORM.ref4 => mem.readInt(u32, value[0..4], .little),
                dwarf.FORM.ref8 => mem.readInt(u64, value[0..8], .little),
                dwarf.FORM.ref_udata => try leb.readULEB128(u64, reader),
                dwarf.FORM.ref_addr => switch (dwf) {
                    .dwarf32 => mem.readInt(u32, value[0..4], .little),
                    .dwarf64 => mem.readInt(u64, value[0..8], .little),
                },
                else => null,
            };
        }

        pub fn getAddr(attr: Attr, value: []const u8, cuh: CompileUnit.Header) ?u64 {
            return switch (attr.form) {
                dwarf.FORM.addr => switch (cuh.address_size) {
                    1 => value[0],
                    2 => mem.readInt(u16, value[0..2], .little),
                    4 => mem.readInt(u32, value[0..4], .little),
                    8 => mem.readInt(u64, value[0..8], .little),
                    else => null,
                },
                else => null,
            };
        }

        pub fn getExprloc(attr: Attr, value: []const u8) !?[]const u8 {
            if (attr.form != dwarf.FORM.exprloc) return null;
            var stream = std.io.fixedBufferStream(value);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();
            const expr_len = try leb.readULEB128(u64, reader);
            return value[creader.bytes_read..][0..expr_len];
        }
    };
};

pub const CompileUnit = struct {
    header: Header,
    loc: Loc,
    dies: std.ArrayListUnmanaged(DebugInfoEntry) = .{},
    children: std.ArrayListUnmanaged(usize) = .{},

    pub fn deinit(cu: *CompileUnit, gpa: Allocator) void {
        for (cu.dies.items) |*die| {
            die.deinit(gpa);
        }
        cu.dies.deinit(gpa);
        cu.children.deinit(gpa);
    }

    pub fn addDie(cu: *CompileUnit, gpa: Allocator) !usize {
        const index = cu.dies.items.len;
        _ = try cu.dies.addOne(gpa);
        return index;
    }

    pub fn diePtr(cu: *CompileUnit, index: usize) *DebugInfoEntry {
        return &cu.dies.items[index];
    }

    pub fn find(cu: CompileUnit, at: u64, dw: DwarfInfo) ?struct { AbbrevTable.Attr, []const u8 } {
        const table = dw.abbrev_tables.get(cu.header.debug_abbrev_offset) orelse return null;
        for (cu.dies.items) |die| {
            const decl = table.decls.get(die.code).?;
            const index = decl.attrs.getIndex(at) orelse return null;
            const attr = decl.attrs.values()[index];
            const value = die.values.items[index];
            return .{ attr, value };
        }
        return null;
    }

    pub fn nextCompileUnitOffset(cu: CompileUnit) u64 {
        return cu.loc.pos + switch (cu.header.dw_format) {
            .dwarf32 => @as(u64, 4),
            .dwarf64 => 12,
        } + cu.header.length;
    }

    pub const Header = struct {
        dw_format: Format,
        length: u64,
        version: u16,
        debug_abbrev_offset: u64,
        address_size: u8,
    };

    pub const DebugInfoEntry = struct {
        code: u64,
        loc: Loc,
        values: std.ArrayListUnmanaged([]const u8) = .{},
        children: std.ArrayListUnmanaged(usize) = .{},

        pub fn deinit(die: *DebugInfoEntry, gpa: Allocator) void {
            die.values.deinit(gpa);
            die.children.deinit(gpa);
        }
    };
};

pub const Loc = struct {
    pos: usize,
    len: usize,
};

pub const Format = enum {
    dwarf32,
    dwarf64,
};

const assert = std.debug.assert;
const dwarf = std.dwarf;
const leb = std.leb;
const log = std.log.scoped(.link);
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const DwarfInfo = @This();
const MachO = @import("../MachO.zig");
