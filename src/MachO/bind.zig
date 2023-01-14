const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log.scoped(.bind);
const macho = std.macho;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub const Rebase = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},
    buffer: std.ArrayListUnmanaged(u8) = .{},

    const Entry = struct {
        offset: u64,
        segment_id: u8,

        pub fn lessThan(ctx: void, entry: Entry, other: Entry) bool {
            _ = ctx;
            if (entry.segment_id == other.segment_id) {
                return entry.offset < other.offset;
            }
            return entry.segment_id < other.segment_id;
        }
    };

    pub fn deinit(rebase: *Rebase, gpa: Allocator) void {
        rebase.entries.deinit(gpa);
        rebase.buffer.deinit(gpa);
    }

    pub fn size(rebase: Rebase) u64 {
        return @intCast(u64, rebase.buffer.items.len);
    }

    pub fn finalize(rebase: *Rebase, gpa: Allocator) !void {
        if (rebase.entries.items.len == 0) return;

        const writer = rebase.buffer.writer(gpa);

        std.sort.sort(Entry, rebase.entries.items, {}, Entry.lessThan);

        try setTypePointer(writer);

        var start: usize = 0;
        var seg_id: ?u8 = null;
        for (rebase.entries.items) |entry, i| {
            if (seg_id != null and seg_id.? == entry.segment_id) continue;
            try finalizeSegment(gpa, rebase.entries.items[start..i], writer);
            seg_id = entry.segment_id;
            start = i;
        }

        try finalizeSegment(gpa, rebase.entries.items[start..], writer);
        try writer.writeByte(macho.REBASE_OPCODE_DONE);
    }

    fn finalizeSegment(gpa: Allocator, entries: []const Entry, writer: anytype) !void {
        if (entries.len == 0) return;

        const first_entry = entries[0];
        try setSegmentOffset(first_entry.segment_id, first_entry.offset, writer);

        const Compressed = struct {
            count: usize,
            delta: u64,
        };

        var compressed = try std.ArrayList(Compressed).initCapacity(gpa, entries.len);
        defer compressed.deinit();

        var i: usize = 1;
        while (i < entries.len) : (i += 1) {
            const delta = entries[i].offset - entries[i - 1].offset - @sizeOf(u64);
            log.warn("delta = {x}", .{delta});
            if (compressed.items.len == 0) {
                compressed.appendAssumeCapacity(.{
                    .count = 1,
                    .delta = delta,
                });
                continue;
            }
            const last = &compressed.items[compressed.items.len - 1];
            if (last.delta == delta) {
                last.count += 1;
            } else {
                compressed.appendAssumeCapacity(.{
                    .count = 1,
                    .delta = delta,
                });
            }
        }

        for (compressed.items) |cmp, cmp_i| {
            log.warn("cmp = {}", .{cmp});
            const next: ?Compressed = if (cmp_i + 1 < compressed.items.len)
                compressed.items[cmp_i + 1]
            else
                null;

            if (next) |n| {
                if (cmp.count == 1 and cmp.delta == 0) {
                    try emitTimes(2, writer);
                    try addAddr(n.delta, writer);
                } else if (cmp.count == 1) {
                    try emitAddAddr(cmp.delta, writer);
                } else if (cmp.delta == 0) {
                    try emitTimes(cmp.count + 1, writer);
                    try addAddr(n.delta, writer);
                } else if (n.delta < cmp.delta) {
                    try emitTimesSkip(cmp.count, cmp.delta, writer);
                    try emitAddAddr(cmp.delta, writer);
                } else {
                    try emitTimesSkip(cmp.count + 1, cmp.delta, writer);
                    try addAddr(n.delta, writer);
                }
            } else {
                if (cmp.count == 1) {
                    try emitTimes(1, writer);
                } else if (cmp.delta == 0) {
                    try emitTimes(cmp.count + 1, writer);
                } else {
                    try emitTimesSkip(cmp.count + 1, cmp.delta, writer);
                }
            }
        }
    }

    fn setTypePointer(writer: anytype) !void {
        log.warn(">>> set type: {d}", .{macho.REBASE_TYPE_POINTER});
        try writer.writeByte(macho.REBASE_OPCODE_SET_TYPE_IMM | @truncate(u4, macho.REBASE_TYPE_POINTER));
    }

    fn setSegmentOffset(segment_id: u8, offset: u64, writer: anytype) !void {
        log.warn(">>> set segment: {d} and offset: {x}", .{ segment_id, offset });
        try writer.writeByte(macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, segment_id));
        try std.leb.writeULEB128(writer, offset);
    }

    fn emitAddAddr(addr: u64, writer: anytype) !void {
        log.warn(">>> emit with add: {x}", .{addr});
        try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB);
        try std.leb.writeULEB128(writer, addr);
    }

    fn emitTimes(count: usize, writer: anytype) !void {
        log.warn(">>> emit with count: {d}", .{count});
        if (count <= 0xf) {
            try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | @truncate(u4, count));
        } else {
            try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
            try std.leb.writeULEB128(writer, count);
        }
    }

    fn emitTimesSkip(count: usize, skip: u64, writer: anytype) !void {
        log.warn(">>> emit with count: {d} and skip: {x}", .{ count, skip });
        try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB);
        try std.leb.writeULEB128(writer, count);
        try std.leb.writeULEB128(writer, skip);
    }

    fn addAddr(addr: u64, writer: anytype) !void {
        log.warn(">>> add: {x}", .{addr});
        try writer.writeByte(macho.REBASE_OPCODE_ADD_ADDR_ULEB);
        try std.leb.writeULEB128(writer, addr);
    }

    pub fn write(rebase: Rebase, writer: anytype) !void {
        if (rebase.size() == 0) return;
        try writer.writeAll(rebase.buffer.items);
    }
};

pub const Pointer = struct {
    offset: u64,
    segment_id: u16,
    dylib_ordinal: ?i64 = null,
    name: ?[]const u8 = null,
    bind_flags: u4 = 0,
    addend: ?i64 = null,
};

pub fn bindInfoSize(pointers: []const Pointer) !u64 {
    var stream = std.io.countingWriter(std.io.null_writer);
    var writer = stream.writer();
    var size: u64 = 0;

    for (pointers) |pointer| {
        size += 1;
        if (pointer.dylib_ordinal.? > 15) {
            try leb.writeULEB128(writer, @bitCast(u64, pointer.dylib_ordinal.?));
        }
        size += 1;

        size += 1;
        size += pointer.name.?.len;
        size += 1;

        size += 1;
        try leb.writeILEB128(writer, pointer.offset);

        if (pointer.addend) |addend| {
            size += 1;
            try leb.writeILEB128(writer, addend);
        }

        size += 1;
    }

    size += stream.bytes_written + 1;
    return size;
}

pub fn writeBindInfo(pointers: []const Pointer, writer: anytype) !void {
    for (pointers) |pointer| {
        if (pointer.dylib_ordinal.? > 15) {
            try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
            try leb.writeULEB128(writer, @bitCast(u64, pointer.dylib_ordinal.?));
        } else if (pointer.dylib_ordinal.? > 0) {
            try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | @truncate(u4, @bitCast(u64, pointer.dylib_ordinal.?)));
        } else {
            try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | @truncate(u4, @bitCast(u64, pointer.dylib_ordinal.?)));
        }
        try writer.writeByte(macho.BIND_OPCODE_SET_TYPE_IMM | @truncate(u4, macho.BIND_TYPE_POINTER));

        try writer.writeByte(macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | pointer.bind_flags);
        try writer.writeAll(pointer.name.?);
        try writer.writeByte(0);

        try writer.writeByte(macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, pointer.segment_id));

        try leb.writeILEB128(writer, pointer.offset);

        if (pointer.addend) |addend| {
            try writer.writeByte(macho.BIND_OPCODE_SET_ADDEND_SLEB);
            try leb.writeILEB128(writer, addend);
        }

        try writer.writeByte(macho.BIND_OPCODE_DO_BIND);
    }

    try writer.writeByte(macho.BIND_OPCODE_DONE);
}

pub fn lazyBindInfoSize(pointers: []const Pointer) !u64 {
    var stream = std.io.countingWriter(std.io.null_writer);
    var writer = stream.writer();
    var size: u64 = 0;

    for (pointers) |pointer| {
        size += 1;

        try leb.writeILEB128(writer, pointer.offset);

        size += 1;
        if (pointer.dylib_ordinal.? > 15) {
            try leb.writeULEB128(writer, @bitCast(u64, pointer.dylib_ordinal.?));
        }

        size += 1;
        size += pointer.name.?.len;
        size += 1;

        size += 2;
    }

    size += stream.bytes_written;
    return size;
}

pub fn writeLazyBindInfo(pointers: []const Pointer, writer: anytype) !void {
    for (pointers) |pointer| {
        assert(pointer.addend == null);

        try writer.writeByte(macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, pointer.segment_id));

        try leb.writeILEB128(writer, pointer.offset);

        if (pointer.dylib_ordinal.? > 15) {
            try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
            try leb.writeULEB128(writer, @bitCast(u64, pointer.dylib_ordinal.?));
        } else if (pointer.dylib_ordinal.? > 0) {
            try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | @truncate(u4, @bitCast(u64, pointer.dylib_ordinal.?)));
        } else {
            try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | @truncate(u4, @bitCast(u64, pointer.dylib_ordinal.?)));
        }

        try writer.writeByte(macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | pointer.bind_flags);
        try writer.writeAll(pointer.name.?);
        try writer.writeByte(0);

        try writer.writeByte(macho.BIND_OPCODE_DO_BIND);
        try writer.writeByte(macho.BIND_OPCODE_DONE);
    }
}

test "rebase - no entries" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    try rebase.finalize(gpa);
    try testing.expectEqual(@as(u64, 0), rebase.size());
}

test "rebase - single entry" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x10,
    });
    try rebase.finalize(gpa);
    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x10,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

test "rebase - emitTimes - IMM" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        try rebase.entries.append(gpa, .{
            .segment_id = 1,
            .offset = i * @sizeOf(u64),
        });
    }

    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 10,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

test "rebase - emitTimes - ULEB" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        try rebase.entries.append(gpa, .{
            .segment_id = 1,
            .offset = i * @sizeOf(u64),
        });
    }

    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
        0x64,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

test "rebase - emitTimes followed by addAddr followed by emitTimes" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    var offset: u64 = 0;
    var i: u64 = 0;
    while (i < 15) : (i += 1) {
        try rebase.entries.append(gpa, .{
            .segment_id = 1,
            .offset = offset,
        });
        offset += @sizeOf(u64);
    }

    offset += @sizeOf(u64);

    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = offset,
    });

    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 15,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x8,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

test "rebase - emitTimesSkip" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    var offset: u64 = 0;
    var i: u64 = 0;
    while (i < 15) : (i += 1) {
        try rebase.entries.append(gpa, .{
            .segment_id = 1,
            .offset = offset,
        });
        offset += 2 * @sizeOf(u64);
    }

    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
        0xf,
        0x8,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

test "rebase - complex" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x10,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x40,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x48,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x50,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x58,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x70,
    });
    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x8,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x28,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 4,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x10,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

test "rebase - complex 2" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x10,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x28,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x48,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x78,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xb8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 2,
        .offset = 0x0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 2,
        .offset = 0x8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 2,
        .offset = 0x10,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 2,
        .offset = 0x18,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 3,
        .offset = 0x0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 3,
        .offset = 0x20,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 3,
        .offset = 0x40,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 3,
        .offset = 0x60,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 3,
        .offset = 0x68,
    });
    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x8,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x10,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x18,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x28,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 4,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 3,
        0x0,
        macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
        0x3,
        0x18,
        macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        0x18,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}
