const EhFrameRecord = @This();

const std = @import("std");
const assert = std.debug.assert;
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const leb = std.leb;
const log = std.log.scoped(.eh_frame);
const parseRelocTarget = @import("unwind_info.zig").parseRelocTarget;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");

tag: Tag,
size: u32,
data: []const u8,

pub const Tag = enum { cie, fde };

pub inline fn getSize(rec: EhFrameRecord) u32 {
    return 4 + rec.size;
}

pub fn getRelocs(
    macho_file: *MachO,
    object_id: u31,
    source_offset: u32,
) []align(1) const macho.relocation_info {
    const object = &macho_file.objects.items[object_id];
    const rel_pos = object.eh_frame_relocs_lookup.get(source_offset) orelse
        return &[0]macho.relocation_info{};
    const all_relocs = object.getRelocs(object.eh_frame_sect.?);
    return all_relocs[rel_pos.start..][0..rel_pos.len];
}

pub fn scanRelocs(rec: EhFrameRecord, macho_file: *MachO, object_id: u31, source_offset: u32) !void {
    const relocs = getRelocs(macho_file, object_id, source_offset);

    for (relocs) |rel| {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);

        switch (rel_type) {
            .ARM64_RELOC_SUBTRACTOR,
            .ARM64_RELOC_UNSIGNED,
            => {},
            .ARM64_RELOC_POINTER_TO_GOT => {
                const target = parseRelocTarget(
                    macho_file,
                    object_id,
                    rel,
                    rec.data,
                    @intCast(i32, source_offset) + 4,
                );
                try Atom.addGotEntry(macho_file, target);
            },
            else => unreachable,
        }
    }
}

pub fn write(rec: EhFrameRecord, macho_file: *MachO, object_id: u31, writer: anytype, ctx: struct {
    source_offset: u32,
    out_offset: u32,
    sect_addr: u64,
}) !void {
    var data = try std.BoundedArray(u8, 128).init(rec.data.len);
    try data.appendSlice(rec.data);

    const relocs = getRelocs(macho_file, object_id, ctx.source_offset);

    for (relocs) |rel| {
        const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
        const target = parseRelocTarget(
            macho_file,
            object_id,
            rel,
            rec.data,
            @intCast(i32, ctx.source_offset) + 4,
        );
        const rel_offset = @intCast(u32, rel.r_address - @intCast(i32, ctx.source_offset) - 4);
        const source_addr = ctx.sect_addr + rel_offset + ctx.out_offset + 4;

        switch (rel_type) {
            .ARM64_RELOC_SUBTRACTOR => {
                // Address of the __eh_frame in the source object file
            },
            .ARM64_RELOC_POINTER_TO_GOT => {
                const target_addr = try Atom.getRelocTargetAddress(macho_file, target, true, false);
                const result = math.cast(i32, @intCast(i64, target_addr) - @intCast(i64, source_addr)) orelse
                    return error.Overflow;
                mem.writeIntLittle(i32, data.slice()[rel_offset..][0..4], result);
            },
            .ARM64_RELOC_UNSIGNED => {
                assert(rel.r_extern == 1);
                const target_addr = try Atom.getRelocTargetAddress(macho_file, target, false, false);
                const result = @intCast(i64, target_addr) - @intCast(i64, source_addr);
                mem.writeIntLittle(i64, data.slice()[rel_offset..][0..8], @intCast(i64, result));
            },
            else => unreachable,
        }
    }

    try writer.writeAll(data.constSlice());
}

pub fn getCiePointer(rec: EhFrameRecord) u32 {
    assert(rec.tag == .fde);
    return mem.readIntLittle(u32, rec.data[0..4]);
}

pub fn getAugmentationString(rec: EhFrameRecord) []const u8 {
    assert(rec.tag == .cie);
    return mem.sliceTo(@ptrCast([*:0]const u8, rec.data.ptr + 5), 0);
}

pub fn getPersonalityPointer(rec: EhFrameRecord, ctx: struct {
    base_addr: u64,
    base_offset: u64,
}) !?u64 {
    assert(rec.tag == .cie);
    const aug_str = rec.getAugmentationString();

    var stream = std.io.fixedBufferStream(rec.data[9 + aug_str.len ..]);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    for (aug_str) |ch, i| switch (ch) {
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

pub fn getLsdaPointer(rec: EhFrameRecord, cie: EhFrameRecord, ctx: struct {
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

fn getLsdaEncoding(rec: EhFrameRecord) !?u8 {
    assert(rec.tag == .cie);
    const aug_str = rec.getAugmentationString();

    const base_offset = 9 + aug_str.len;
    var stream = std.io.fixedBufferStream(rec.data[base_offset..]);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    for (aug_str) |ch, i| switch (ch) {
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

pub const Iterator = struct {
    data: []const u8,
    pos: u32 = 0,

    pub fn next(it: *Iterator) !?EhFrameRecord {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        var size = try reader.readIntLittle(u32);
        if (size == 0xFFFFFFFF) {
            log.err("MachO doesn't support 64bit DWARF CFI __eh_frame records", .{});
            return error.UnsupportedDwarfCfiFormat;
        }

        const id = try reader.readIntLittle(u32);
        const tag: Tag = if (id == 0) .cie else .fde;
        const offset: u32 = 4;
        const record = EhFrameRecord{
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
