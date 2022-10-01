const DwarfInfo = @This();

const std = @import("std");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const leb = std.leb;
const mem = std.mem;

const Allocator = mem.Allocator;
pub const AbbrevLookupTable = std.AutoHashMap(u64, struct { pos: usize, len: usize });

debug_info: []const u8,
debug_abbrev: []const u8,
debug_str: []const u8,

pub const CompileUnitIterator = struct {
    pos: usize = 0,

    pub fn next(self: *CompileUnitIterator, ctx: DwarfInfo) !?CompileUnit {
        if (self.pos >= ctx.debug_info.len) return null;

        var stream = std.io.fixedBufferStream(ctx.debug_info);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const cuh = try CompileUnit.Header.read(reader);
        const total_length = cuh.length + @as(u64, if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32));

        const cu = CompileUnit{
            .cuh = cuh,
            .debug_info_off = creader.bytes_read,
        };

        self.pos += total_length;

        return cu;
    }
};

pub fn genAbbrevLookupByKind(self: DwarfInfo, off: usize, lookup: *AbbrevLookupTable) !void {
    const data = self.debug_abbrev[off..];
    var stream = std.io.fixedBufferStream(data);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    var open_scope = false;
    while (true) {
        const kind = try leb.readULEB128(u64, reader);
        if (kind == 0) {
            if (open_scope) return error.MalformedDwarf;
            break;
        }
        open_scope = true;

        const pos = creader.bytes_read;

        while (true) {
            const byte = try reader.readByte();
            if (byte == 0) {
                if ((try reader.readByte()) == 0x0) {
                    open_scope = false;
                    break;
                }
            }
        }

        try lookup.putNoClobber(kind, .{
            .pos = pos,
            .len = creader.bytes_read - pos - 2,
        });
    }
}

const CompileUnit = struct {
    cuh: Header,
    debug_info_off: usize,

    const Header = struct {
        is_64bit: bool,
        length: u64,
        version: u16,
        debug_abbrev_offset: u64,
        address_size: u8,

        fn read(reader: anytype) !Header {
            var length: u64 = try reader.readIntLittle(u32);

            const is_64bit = length == 0xffffffff;
            if (is_64bit) {
                length = try reader.readIntLittle(u64);
            }

            const version = try reader.readIntLittle(u16);
            const debug_abbrev_offset = if (is_64bit)
                try reader.readIntLittle(u64)
            else
                try reader.readIntLittle(u32);
            const address_size = try reader.readIntLittle(u8);

            return Header{
                .is_64bit = is_64bit,
                .length = length,
                .version = version,
                .debug_abbrev_offset = debug_abbrev_offset,
                .address_size = address_size,
            };
        }
    };

    inline fn getDebugInfo(self: CompileUnit, ctx: DwarfInfo) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.cuh.length];
    }
};

pub const AbbrevEntryIterator = struct {
    pos: usize = 0,

    pub fn next(self: *AbbrevEntryIterator, ctx: DwarfInfo, cu: CompileUnit, lookup: AbbrevLookupTable) !?AbbrevEntry {
        if (self.pos + cu.debug_info_off >= ctx.debug_info.len) return null;

        const kind = ctx.debug_info[self.pos + cu.debug_info_off];
        self.pos += 1;

        if (kind == 0) {
            return AbbrevEntry.@"null"();
        }

        const abbrev_pos = lookup.get(kind) orelse return error.MalformedDwarf;
        const len = try findAbbrevEntrySize(ctx, abbrev_pos.pos, abbrev_pos.len, self.pos + cu.debug_info_off, cu.cuh);
        const entry = try getAbbrevEntry(ctx, abbrev_pos.pos, abbrev_pos.len, self.pos + cu.debug_info_off, len);

        self.pos += len;

        return entry;
    }
};

pub const AbbrevEntry = struct {
    tag: u64,
    children: u8,
    debug_abbrev_off: usize,
    debug_abbrev_len: usize,
    debug_info_off: usize,
    debug_info_len: usize,

    fn @"null"() AbbrevEntry {
        return .{
            .tag = 0,
            .children = dwarf.CHILDREN.no,
            .debug_abbrev_off = 0,
            .debug_abbrev_len = 0,
            .debug_info_off = 0,
            .debug_info_len = 0,
        };
    }

    pub fn hasChildren(self: AbbrevEntry) bool {
        return self.children == dwarf.CHILDREN.yes;
    }

    inline fn getDebugInfo(self: AbbrevEntry, ctx: DwarfInfo) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.debug_info_len];
    }

    inline fn getDebugAbbrev(self: AbbrevEntry, ctx: DwarfInfo) []const u8 {
        return ctx.debug_abbrev[self.debug_abbrev_off..][0..self.debug_abbrev_len];
    }
};

const Attribute = struct {
    name: u64,
    form: u64,
    debug_info_off: usize,
    debug_info_len: usize,

    inline fn getDebugInfo(self: Attribute, ctx: DwarfInfo) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.debug_info_len];
    }

    pub fn getString(self: Attribute, ctx: DwarfInfo, cuh: CompileUnit.Header) ?[]const u8 {
        if (self.form != dwarf.FORM.strp) return null;
        const debug_info = self.getDebugInfo(ctx);
        const off = if (cuh.is_64bit)
            mem.readIntLittle(u64, debug_info[0..8])
        else
            mem.readIntLittle(u32, debug_info[0..4]);
        return ctx.getString(off);
    }

    fn getConstant(self: Attribute, ctx: DwarfInfo) !?i128 {
        const debug_info = self.getDebugInfo(ctx);
        var stream = std.io.fixedBufferStream(debug_info);
        const reader = stream.reader();

        return switch (self.form) {
            dwarf.FORM.data1 => debug_info[0],
            dwarf.FORM.data2 => mem.readIntLittle(u16, debug_info[0..2]),
            dwarf.FORM.data4 => mem.readIntLittle(u32, debug_info[0..4]),
            dwarf.FORM.data8 => mem.readIntLittle(u64, debug_info[0..8]),
            dwarf.FORM.udata => try leb.readULEB128(u64, reader),
            dwarf.FORM.sdata => try leb.readILEB128(i64, reader),
            else => null,
        };
    }

    fn getReference(self: Attribute, ctx: DwarfInfo) !?u64 {
        const debug_info = self.getDebugInfo(ctx);
        var stream = std.io.fixedBufferStream(debug_info);
        const reader = stream.reader();

        return switch (self.form) {
            dwarf.FORM.ref1 => debug_info[0],
            dwarf.FORM.ref2 => mem.readIntLittle(u16, debug_info[0..2]),
            dwarf.FORM.ref4 => mem.readIntLittle(u32, debug_info[0..4]),
            dwarf.FORM.ref8 => mem.readIntLittle(u64, debug_info[0..8]),
            dwarf.FORM.ref_udata => try leb.readULEB128(u64, reader),
            else => null,
        };
    }

    fn getAddr(self: Attribute, ctx: DwarfInfo, cuh: CompileUnit.Header) ?u64 {
        if (self.form != dwarf.FORM.addr) return null;
        const debug_info = self.getDebugInfo(ctx);
        return switch (cuh.address_size) {
            1 => debug_info[0],
            2 => mem.readIntLittle(u16, debug_info[0..2]),
            4 => mem.readIntLittle(u32, debug_info[0..4]),
            8 => mem.readIntLittle(u64, debug_info[0..8]),
            else => unreachable,
        };
    }
};

pub const AttributeIterator = struct {
    debug_abbrev_pos: usize = 0,
    debug_info_pos: usize = 0,

    pub fn next(self: *AttributeIterator, ctx: DwarfInfo, entry: AbbrevEntry, cuh: CompileUnit.Header) !?Attribute {
        const debug_abbrev = entry.getDebugAbbrev(ctx);
        if (self.debug_abbrev_pos >= debug_abbrev.len) return null;

        var stream = std.io.fixedBufferStream(debug_abbrev[self.debug_abbrev_pos..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const name = try leb.readULEB128(u64, reader);
        const form = try leb.readULEB128(u64, reader);

        self.debug_abbrev_pos += creader.bytes_read;

        const len = try findFormSize(
            ctx,
            form,
            self.debug_info_pos + entry.debug_info_off,
            entry.debug_info_len - self.debug_info_pos,
            cuh,
        );
        const attr = Attribute{
            .name = name,
            .form = form,
            .debug_info_off = self.debug_info_pos + entry.debug_info_off,
            .debug_info_len = entry.debug_info_len - self.debug_info_pos,
        };

        self.debug_info_pos += len;

        return attr;
    }
};

fn getAbbrevEntry(self: DwarfInfo, da_off: usize, da_len: usize, di_off: usize, di_len: usize) !AbbrevEntry {
    const debug_abbrev = self.debug_abbrev[da_off..][0..da_len];
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    const tag = try leb.readULEB128(u64, reader);
    const children = try reader.readByte();

    return AbbrevEntry{
        .tag = tag,
        .children = children,
        .debug_abbrev_off = creader.bytes_read + da_off,
        .debug_abbrev_len = da_len - creader.bytes_read,
        .debug_info_off = di_off,
        .debug_info_len = di_len,
    };
}

fn findFormSize(self: DwarfInfo, form: u64, di_off: usize, di_len: ?usize, cuh: CompileUnit.Header) !usize {
    const debug_info = if (di_len) |len|
        self.debug_info[di_off..][0..len]
    else
        self.debug_info[di_off..];
    var stream = std.io.fixedBufferStream(debug_info);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    return switch (form) {
        dwarf.FORM.strp => if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32),
        dwarf.FORM.sec_offset => if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32),
        dwarf.FORM.addr => cuh.address_size,
        dwarf.FORM.exprloc => blk: {
            const expr_len = try leb.readULEB128(u64, reader);
            var i: u64 = 0;
            while (i < expr_len) : (i += 1) {
                _ = try reader.readByte();
            }
            break :blk creader.bytes_read;
        },
        dwarf.FORM.flag_present => 0,

        dwarf.FORM.data1 => @sizeOf(u8),
        dwarf.FORM.data2 => @sizeOf(u16),
        dwarf.FORM.data4 => @sizeOf(u32),
        dwarf.FORM.data8 => @sizeOf(u64),
        dwarf.FORM.udata => blk: {
            _ = try leb.readULEB128(u64, reader);
            break :blk creader.bytes_read;
        },
        dwarf.FORM.sdata => blk: {
            _ = try leb.readILEB128(i64, reader);
            break :blk creader.bytes_read;
        },

        dwarf.FORM.ref1 => @sizeOf(u8),
        dwarf.FORM.ref2 => @sizeOf(u16),
        dwarf.FORM.ref4 => @sizeOf(u32),
        dwarf.FORM.ref8 => @sizeOf(u64),
        dwarf.FORM.ref_udata => blk: {
            _ = try leb.readULEB128(u64, reader);
            break :blk creader.bytes_read;
        },

        else => return error.ToDo,
    };
}

fn findAbbrevEntrySize(self: DwarfInfo, da_off: usize, da_len: usize, di_off: usize, cuh: CompileUnit.Header) !usize {
    const debug_abbrev = self.debug_abbrev[da_off..][0..da_len];
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    _ = try leb.readULEB128(u64, reader);
    _ = try reader.readByte();

    var len: usize = 0;
    while (creader.bytes_read < debug_abbrev.len) {
        _ = try leb.readULEB128(u64, reader);
        const form = try leb.readULEB128(u64, reader);
        const form_len = try self.findFormSize(form, di_off + len, null, cuh);
        len += form_len;
    }

    return len;
}

fn getString(self: DwarfInfo, off: u64) []const u8 {
    assert(off < self.debug_str.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.debug_str.ptr + off), 0);
}
