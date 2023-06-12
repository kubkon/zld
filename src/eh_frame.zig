pub const Fde = struct {
    offset: u64,
    size: u64,
    data: []const u8,
    cie_index: u32,

    pub fn deinit(fde: *Fde, gpa: Allocator) void {
        gpa.free(fde.data);
    }

    // TODO handle 64bit records
    pub inline fn getSize(fde: Fde) u32 {
        return 4 + fde.size;
    }

    pub fn getTargetSymbolAddress(fde: Fde, ctx: struct {
        base_addr: u64,
        base_offset: u64,
    }) u64 {
        const addend = mem.readIntLittle(i64, fde.data[4..][0..8]);
        return @intCast(u64, @intCast(i64, ctx.base_addr + ctx.base_offset + 8) + addend);
    }

    pub fn setTargetSymbolAddress(fde: *Fde, value: u64, ctx: struct {
        base_addr: u64,
        base_offset: u64,
    }) !void {
        const addend = @intCast(i64, value) - @intCast(i64, ctx.base_addr + ctx.base_offset + 8);
        mem.writeIntLittle(i64, fde.data[4..][0..8], addend);
    }

    pub fn getCiePointer(fde: Fde) u32 {
        return mem.readIntLittle(u32, fde.data[0..4]);
    }

    pub fn setCiePointer(fde: *Fde, ptr: u32) void {
        mem.writeIntLittle(u32, fde.data[0..4], ptr);
    }

    pub fn getLsdaPointer(fde: Fde, cie: Cie, ctx: struct {
        base_addr: u64,
        base_offset: u64,
    }) !?u64 {
        const enc = (try cie.getLsdaEncoding()) orelse return null;
        var stream = std.io.fixedBufferStream(fde.data[20..]);
        const reader = stream.reader();
        _ = try reader.readByte();
        const offset = ctx.base_offset + 25;
        const ptr = try getEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), reader);
        return ptr;
    }

    pub fn setLsdaPointer(fde: *Fde, cie: Cie, value: u64, ctx: struct {
        base_addr: u64,
        base_offset: u64,
    }) !void {
        const enc = (try cie.getLsdaEncoding()) orelse unreachable;
        var stream = std.io.fixedBufferStream(fde.data[21..]);
        const writer = stream.writer();
        const offset = ctx.base_offset + 25;
        try setEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), value, writer);
    }
};

pub const Cie = struct {
    offset: u64,
    size: u64,
    data: []const u8,

    // TODO handle 64bit records
    pub inline fn getSize(cie: Cie) u32 {
        return 4 + cie.size;
    }

    pub fn getAugmentationString(cie: Cie) []const u8 {
        return mem.sliceTo(@ptrCast([*:0]const u8, cie.data.ptr + 5), 0);
    }

    pub fn getPersonalityPointer(cie: Cie, ctx: struct {
        base_addr: u64,
        base_offset: u64,
    }) !?u64 {
        const aug_str = cie.getAugmentationString();
        var stream = std.io.fixedBufferStream(cie.data[9 + aug_str.len ..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        for (aug_str, 0..) |ch, i| switch (ch) {
            'z' => if (i > 0) {
                return error.MalformedAugmentationString;
            } else {
                _ = try leb.readULEB128(u64, reader);
            },
            'R' => {
                _ = try reader.readByte();
            },
            'P' => {
                const enc = try reader.readByte();
                const offset = ctx.base_offset + 13 + aug_str.len + creader.bytes_read;
                const ptr = try getEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), reader);
                return ptr;
            },
            'L' => {
                _ = try reader.readByte();
            },
            'S', 'B', 'G' => {},
            else => return error.UnknownAugmentationStringValue,
        };

        return null;
    }

    fn getLsdaEncoding(cie: Cie) !?u8 {
        const aug_str = cie.getAugmentationString();
        const base_offset = 9 + aug_str.len;
        var stream = std.io.fixedBufferStream(cie.data[base_offset..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        for (aug_str, 0..) |ch, i| switch (ch) {
            'z' => if (i > 0) {
                return error.MalformedAugmentationString;
            } else {
                _ = try leb.readULEB128(u64, reader);
            },
            'R' => {
                _ = try reader.readByte();
            },
            'P' => {
                const enc = try reader.readByte();
                _ = try getEncodedPointer(enc, 0, reader);
            },
            'L' => {
                const enc = try reader.readByte();
                return enc;
            },
            'S', 'B', 'G' => {},
            else => return error.UnknownAugmentationStringValue,
        };

        return null;
    }
};

fn getEncodedPointer(enc: u8, pcrel_offset: i64, reader: anytype) !?u64 {
    if (enc == EH_PE.omit) return null;

    var ptr: i64 = switch (enc & 0x0F) {
        EH_PE.absptr => @bitCast(i64, try reader.readIntLittle(u64)),
        EH_PE.udata2 => @bitCast(i16, try reader.readIntLittle(u16)),
        EH_PE.udata4 => @bitCast(i32, try reader.readIntLittle(u32)),
        EH_PE.udata8 => @bitCast(i64, try reader.readIntLittle(u64)),
        EH_PE.uleb128 => @bitCast(i64, try leb.readULEB128(u64, reader)),
        EH_PE.sdata2 => try reader.readIntLittle(i16),
        EH_PE.sdata4 => try reader.readIntLittle(i32),
        EH_PE.sdata8 => try reader.readIntLittle(i64),
        EH_PE.sleb128 => try leb.readILEB128(i64, reader),
        else => return null,
    };

    switch (enc & 0x70) {
        EH_PE.absptr => {},
        EH_PE.pcrel => ptr += pcrel_offset,
        EH_PE.datarel,
        EH_PE.textrel,
        EH_PE.funcrel,
        EH_PE.aligned,
        => return null,
        else => return null,
    }

    return @bitCast(u64, ptr);
}

fn setEncodedPointer(enc: u8, pcrel_offset: i64, value: u64, writer: anytype) !void {
    if (enc == EH_PE.omit) return;

    var actual = @intCast(i64, value);

    switch (enc & 0x70) {
        EH_PE.absptr => {},
        EH_PE.pcrel => actual -= pcrel_offset,
        EH_PE.datarel,
        EH_PE.textrel,
        EH_PE.funcrel,
        EH_PE.aligned,
        => unreachable,
        else => unreachable,
    }

    switch (enc & 0x0F) {
        EH_PE.absptr => try writer.writeIntLittle(u64, @bitCast(u64, actual)),
        EH_PE.udata2 => try writer.writeIntLittle(u16, @bitCast(u16, @intCast(i16, actual))),
        EH_PE.udata4 => try writer.writeIntLittle(u32, @bitCast(u32, @intCast(i32, actual))),
        EH_PE.udata8 => try writer.writeIntLittle(u64, @bitCast(u64, actual)),
        EH_PE.uleb128 => try leb.writeULEB128(writer, @bitCast(u64, actual)),
        EH_PE.sdata2 => try writer.writeIntLittle(i16, @intCast(i16, actual)),
        EH_PE.sdata4 => try writer.writeIntLittle(i32, @intCast(i32, actual)),
        EH_PE.sdata8 => try writer.writeIntLittle(i64, actual),
        EH_PE.sleb128 => try leb.writeILEB128(writer, actual),
        else => unreachable,
    }
}

pub const EhFrameRecordTag = enum { cie, fde };

pub fn EhFrameRecord(comptime is_mutable: bool) type {
    return struct {
        tag: EhFrameRecordTag,
        size: u32,
        data: if (is_mutable) []u8 else []const u8,

        const Record = @This();

        pub fn deinit(rec: *Record, gpa: Allocator) void {
            comptime assert(is_mutable);
            gpa.free(rec.data);
        }

        pub fn toOwned(rec: Record, gpa: Allocator) Allocator.Error!EhFrameRecord(true) {
            const data = try gpa.dupe(u8, rec.data);
            return EhFrameRecord(true){
                .tag = rec.tag,
                .size = rec.size,
                .data = data,
            };
        }

        pub inline fn getSize(rec: Record) u32 {
            return 4 + rec.size;
        }

        pub fn getTargetSymbolAddress(rec: Record, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) u64 {
            assert(rec.tag == .fde);
            const addend = mem.readIntLittle(i64, rec.data[4..][0..8]);
            return @intCast(u64, @intCast(i64, ctx.base_addr + ctx.base_offset + 8) + addend);
        }

        pub fn setTargetSymbolAddress(rec: *Record, value: u64, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) !void {
            assert(rec.tag == .fde);
            const addend = @intCast(i64, value) - @intCast(i64, ctx.base_addr + ctx.base_offset + 8);
            mem.writeIntLittle(i64, rec.data[4..][0..8], addend);
        }

        pub fn getCiePointer(rec: Record) u32 {
            assert(rec.tag == .fde);
            return mem.readIntLittle(u32, rec.data[0..4]);
        }

        pub fn setCiePointer(rec: *Record, ptr: u32) void {
            assert(rec.tag == .fde);
            mem.writeIntLittle(u32, rec.data[0..4], ptr);
        }

        pub fn getAugmentationString(rec: Record) []const u8 {
            assert(rec.tag == .cie);
            return mem.sliceTo(@ptrCast([*:0]const u8, rec.data.ptr + 5), 0);
        }

        pub fn getPersonalityPointer(rec: Record, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) !?u64 {
            assert(rec.tag == .cie);
            const aug_str = rec.getAugmentationString();

            var stream = std.io.fixedBufferStream(rec.data[9 + aug_str.len ..]);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();

            for (aug_str, 0..) |ch, i| switch (ch) {
                'z' => if (i > 0) {
                    return error.MalformedAugmentationString;
                } else {
                    _ = try leb.readULEB128(u64, reader);
                },
                'R' => {
                    _ = try reader.readByte();
                },
                'P' => {
                    const enc = try reader.readByte();
                    const offset = ctx.base_offset + 13 + aug_str.len + creader.bytes_read;
                    const ptr = try getEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), reader);
                    return ptr;
                },
                'L' => {
                    _ = try reader.readByte();
                },
                'S', 'B', 'G' => {},
                else => return error.UnknownAugmentationStringValue,
            };

            return null;
        }

        pub fn getLsdaPointer(rec: Record, cie: Record, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) !?u64 {
            assert(rec.tag == .fde);
            const enc = (try cie.getLsdaEncoding()) orelse return null;
            var stream = std.io.fixedBufferStream(rec.data[20..]);
            const reader = stream.reader();
            _ = try reader.readByte();
            const offset = ctx.base_offset + 25;
            const ptr = try getEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), reader);
            return ptr;
        }

        pub fn setLsdaPointer(rec: *Record, cie: Record, value: u64, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) !void {
            assert(rec.tag == .fde);
            const enc = (try cie.getLsdaEncoding()) orelse unreachable;
            var stream = std.io.fixedBufferStream(rec.data[21..]);
            const writer = stream.writer();
            const offset = ctx.base_offset + 25;
            try setEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), value, writer);
        }

        fn getLsdaEncoding(rec: Record) !?u8 {
            assert(rec.tag == .cie);
            const aug_str = rec.getAugmentationString();

            const base_offset = 9 + aug_str.len;
            var stream = std.io.fixedBufferStream(rec.data[base_offset..]);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();

            for (aug_str, 0..) |ch, i| switch (ch) {
                'z' => if (i > 0) {
                    return error.MalformedAugmentationString;
                } else {
                    _ = try leb.readULEB128(u64, reader);
                },
                'R' => {
                    _ = try reader.readByte();
                },
                'P' => {
                    const enc = try reader.readByte();
                    _ = try getEncodedPointer(enc, 0, reader);
                },
                'L' => {
                    const enc = try reader.readByte();
                    return enc;
                },
                'S', 'B', 'G' => {},
                else => return error.UnknownAugmentationStringValue,
            };

            return null;
        }
    };
}

pub const NewIterator = struct {
    data: []const u8,
    pos: u64 = 0,

    pub const Record = struct {
        tag: enum { fde, cie },
        offset: u64,
        size: u64,
        data: []const u8,

        pub fn fde(rec: Record) Fde {
            assert(rec.tag == .fde);
            return .{
                .offset = rec.offset,
                .size = rec.size,
                .data = rec.data,
                .cie_index = undefined,
            };
        }

        pub fn cie(rec: Record) Cie {
            assert(rec.tag == .cie);
            return .{
                .offset = rec.offset,
                .size = rec.size,
                .data = rec.data,
            };
        }
    };

    pub fn next(it: *NewIterator) !?Record {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        var size = try reader.readIntLittle(u32);
        it.pos += 4;
        if (size == 0xFFFFFFFF) @panic("TODO");

        const id = try reader.readIntLittle(u32);
        const record = Record{
            .tag = if (id == 0) .cie else .fde,
            .offset = it.pos,
            .size = size,
            .data = it.data[it.pos..][0..size],
        };
        it.pos += size;

        return record;
    }
};

pub const Iterator = struct {
    data: []const u8,
    pos: u32 = 0,

    pub fn next(it: *Iterator) !?EhFrameRecord(false) {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        var size = try reader.readIntLittle(u32);
        if (size == 0xFFFFFFFF) {
            log.err("MachO doesn't support 64bit DWARF CFI __eh_frame records", .{});
            return error.UnsupportedDwarfCfiFormat;
        }

        const id = try reader.readIntLittle(u32);
        const tag: EhFrameRecordTag = if (id == 0) .cie else .fde;
        const offset: u32 = 4;
        const record = EhFrameRecord(false){
            .tag = tag,
            .size = size,
            .data = it.data[it.pos + offset ..][0..size],
        };

        it.pos += size + offset;

        return record;
    }

    pub fn reset(it: *Iterator) void {
        it.pos = 0;
    }

    pub fn seekTo(it: *Iterator, pos: u32) void {
        assert(pos >= 0 and pos < it.data.len);
        it.pos = pos;
    }
};

pub const EH_PE = struct {
    pub const absptr = 0x00;
    pub const uleb128 = 0x01;
    pub const udata2 = 0x02;
    pub const udata4 = 0x03;
    pub const udata8 = 0x04;
    pub const sleb128 = 0x09;
    pub const sdata2 = 0x0A;
    pub const sdata4 = 0x0B;
    pub const sdata8 = 0x0C;
    pub const pcrel = 0x10;
    pub const textrel = 0x20;
    pub const datarel = 0x30;
    pub const funcrel = 0x40;
    pub const aligned = 0x50;
    pub const indirect = 0x80;
    pub const omit = 0xFF;
};

const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log;
const mem = std.mem;

const Allocator = mem.Allocator;
