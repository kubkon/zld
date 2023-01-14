const Rebase = @This();

const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log.scoped(.dyld_info);
const macho = std.macho;
const testing = std.testing;

const Allocator = std.mem.Allocator;

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

pub fn finalize(rebase: *Rebase, gpa: Allocator, macho_file: anytype) !void {
    if (rebase.entries.items.len == 0) return;

    const writer = rebase.buffer.writer(gpa);

    std.sort.sort(Entry, rebase.entries.items, {}, Entry.lessThan);

    try setTypePointer(writer);

    var start: usize = 0;
    var seg_id: ?u8 = null;
    for (rebase.entries.items) |entry, i| {
        if (seg_id != null and seg_id.? == entry.segment_id) continue;
        try finalizeSegment(gpa, rebase.entries.items[start..i], writer, macho_file);
        seg_id = entry.segment_id;
        start = i;
    }

    try finalizeSegment(gpa, rebase.entries.items[start..], writer, macho_file);
    try writer.writeByte(macho.REBASE_OPCODE_DONE);
}

fn finalizeSegment(gpa: Allocator, entries: []const Entry, writer: anytype, macho_file: anytype) !void {
    _ = gpa;
    if (entries.len == 0) return;

    const segment_id = entries[0].segment_id;
    const vmaddr = macho_file.segments.items[segment_id].vmaddr;
    var offset = entries[0].offset;
    try setSegmentOffset(segment_id, offset, writer);

    var count: usize = 0;
    var skip: u64 = 0;
    var state: enum {
        start,
        times,
        times_skip,
    } = .times;

    var i: usize = 0;
    while (i < entries.len) : (i += 1) {
        log.warn("offset = {x}, count = {d}, skip = {x}, state = {s}", .{
            vmaddr + offset,
            count,
            skip,
            @tagName(state),
        });
        const current_offset = entries[i].offset;
        log.warn("  current = {x}", .{vmaddr + current_offset});

        switch (state) {
            .start => {
                if (offset < current_offset) {
                    const delta = current_offset - offset;
                    try addAddr(delta, writer);
                    offset += delta;
                }
                state = .times;
                offset += @sizeOf(u64);
                count = 1;
            },
            .times => {
                const delta = current_offset - offset;
                log.warn("  delta = {x}", .{delta});
                if (delta == 0) {
                    count += 1;
                    offset += @sizeOf(u64);
                    continue;
                }

                // if (count == 1) {
                //     try rebaseAddAddr(delta, writer);
                // } else {
                //     try rebaseTimes(count, writer);
                // }
                // state = .start;
                // offset = offset_after_rebase;
                // i -= 1;

                if (count == 1) {
                    state = .times_skip;
                    skip = delta;
                    offset += skip;
                    i -= 1;
                    // offset += @sizeOf(u64) + 2 * skip;
                    // count += 1;
                    log.warn("  skip = {x}", .{skip});
                } else {
                    try rebaseTimes(count, writer);
                    state = .start;
                    i -= 1;
                }
            },
            .times_skip => {
                if (current_offset < offset) {
                    count -= 1;
                    if (count == 1) {
                        try rebaseAddAddr(skip, writer);
                    } else {
                        try rebaseTimesSkip(count, skip, writer);
                    }
                    state = .start;
                    offset = offset - (@sizeOf(u64) + skip);
                    i -= 1;
                    continue;
                }

                const delta = current_offset - offset;
                log.warn("  delta = {x}", .{delta});
                if (delta == 0) {
                    count += 1;
                    offset += @sizeOf(u64) + skip;
                    continue;
                }

                if (count == 1) {
                    try rebaseAddAddr(delta, writer);
                    offset += @sizeOf(u64);
                } else {
                    try rebaseTimesSkip(count, skip, writer);
                }
                state = .start;
                i -= 1;
            },
        }
    }

    switch (state) {
        .start => unreachable,
        .times => {
            try rebaseTimes(count, writer);
        },
        .times_skip => {
            try rebaseTimesSkip(count, skip, writer);
        },
    }

    // const Compressed = struct {
    //     count: usize,
    //     delta: u64,
    //     offset: u64,
    // };

    // var compressed = try std.ArrayList(Compressed).initCapacity(gpa, entries.len);
    // defer compressed.deinit();

    // var i: usize = 1;
    // while (i < entries.len) : (i += 1) {
    //     const delta = entries[i].offset - entries[i - 1].offset - @sizeOf(u64);
    //     log.warn("{x} - {x} = {x}", .{ vmaddr + entries[i].offset, vmaddr + entries[i - 1].offset, delta });
    //     if (compressed.items.len == 0) {
    //         compressed.appendAssumeCapacity(.{
    //             .count = 1,
    //             .delta = delta,
    //             .offset = entries[i - 1].offset,
    //         });
    //         continue;
    //     }
    //     const last = &compressed.items[compressed.items.len - 1];
    //     if (last.delta == delta) {
    //         last.count += 1;
    //     } else {
    //         compressed.appendAssumeCapacity(.{
    //             .count = 1,
    //             .delta = delta,
    //             .offset = entries[i - 1].offset,
    //         });
    //     }
    // }

    // for (compressed.items) |cmp| {
    //     log.warn("{x} => count={x}, delta={x}", .{ vmaddr + cmp.offset, cmp.count, cmp.delta });
    // }

    // i = 0;
    // while (i < compressed.items.len) : (i += 1) {
    //     const cmp = compressed.items[i];
    //     log.warn("{x} => count={x}, delta={x}", .{ vmaddr + cmp.offset, cmp.count, cmp.delta });
    //     const next: ?Compressed = if (i + 1 < compressed.items.len)
    //         compressed.items[i + 1]
    //     else
    //         null;

    //     if (next) |n| {
    //         if (cmp.count == 1) {
    //             if (cmp.delta == 0) {
    //                 try rebaseTimes(2, writer);
    //                 try addAddr(n.delta, writer);
    //                 i += 1;
    //             } else {
    //                 try rebaseAddAddr(cmp.delta, writer);
    //             }
    //         } else {
    //             if (cmp.delta == 0) {
    //                 try rebaseTimes(cmp.count + 1, writer);
    //                 try addAddr(n.delta, writer);
    //                 i += 1;
    //             } else if (n.delta < cmp.delta) {
    //                 try rebaseTimesSkip(cmp.count, cmp.delta, writer);
    //                 try rebaseAddAddr(cmp.delta, writer);
    //             } else {
    //                 try rebaseTimesSkip(cmp.count + 1, cmp.delta, writer);
    //                 try addAddr(n.delta, writer);
    //                 i += 1;
    //             }
    //         }
    //     } else {
    //         if (cmp.count == 1) {
    //             try rebaseTimes(1, writer);
    //         } else if (cmp.delta == 0) {
    //             try rebaseTimes(cmp.count + 1, writer);
    //         } else {
    //             try rebaseTimesSkip(cmp.count + 1, cmp.delta, writer);
    //         }
    //     }
    // }
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

fn rebaseAddAddr(addr: u64, writer: anytype) !void {
    log.warn(">>> rebase with add: {x}", .{addr});
    try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB);
    try std.leb.writeULEB128(writer, addr);
}

fn rebaseTimes(count: usize, writer: anytype) !void {
    log.warn(">>> rebase with count: {d}", .{count});
    if (count <= 0xf) {
        try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | @truncate(u4, count));
    } else {
        try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
        try std.leb.writeULEB128(writer, count);
    }
}

fn rebaseTimesSkip(count: usize, skip: u64, writer: anytype) !void {
    log.warn(">>> rebase with count: {d} and skip: {x}", .{ count, skip });
    try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB);
    try std.leb.writeULEB128(writer, count);
    try std.leb.writeULEB128(writer, skip);
}

fn addAddr(addr: u64, writer: anytype) !void {
    if (addr == 0) return;
    log.warn(">>> add: {x}", .{addr});
    try writer.writeByte(macho.REBASE_OPCODE_ADD_ADDR_ULEB);
    try std.leb.writeULEB128(writer, addr);
}

pub fn write(rebase: Rebase, writer: anytype) !void {
    if (rebase.size() == 0) return;
    try writer.writeAll(rebase.buffer.items);
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
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
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
        macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
        0x2,
        0x8,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x20,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 4,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x10,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}

// test "rebase - complex 2" {
//     const gpa = testing.allocator;

//     var rebase = Rebase{};
//     defer rebase.deinit(gpa);

//     try rebase.entries.append(gpa, .{
//         .segment_id = 1,
//         .offset = 0,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 1,
//         .offset = 0x10,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 1,
//         .offset = 0x28,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 1,
//         .offset = 0x48,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 1,
//         .offset = 0x78,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 1,
//         .offset = 0xb8,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 2,
//         .offset = 0x0,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 2,
//         .offset = 0x8,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 2,
//         .offset = 0x10,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 2,
//         .offset = 0x18,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 3,
//         .offset = 0x0,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 3,
//         .offset = 0x20,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 3,
//         .offset = 0x40,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 3,
//         .offset = 0x60,
//     });
//     try rebase.entries.append(gpa, .{
//         .segment_id = 3,
//         .offset = 0x68,
//     });
//     try rebase.finalize(gpa);

//     try testing.expectEqualSlices(u8, &[_]u8{
//         macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
//         macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
//         0x0,
//         macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
//         0x8,
//         macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
//         0x10,
//         macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
//         0x18,
//         macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
//         0x28,
//         macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
//         macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2,
//         0x0,
//         macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 4,
//         macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 3,
//         0x0,
//         macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
//         0x3,
//         0x18,
//         macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
//         0x18,
//         macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
//         macho.REBASE_OPCODE_DONE,
//     }, rebase.buffer.items);
// }

test "composite" {
    const gpa = testing.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);

    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x38,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xa0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xa8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xb0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xc0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xc8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xd0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xd8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xe0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xe8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xf0,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0xf8,
    });
    try rebase.entries.append(gpa, .{
        .segment_id = 1,
        .offset = 0x108,
    });
    try rebase.finalize(gpa);

    try testing.expectEqualSlices(u8, &[_]u8{
        macho.REBASE_OPCODE_SET_TYPE_IMM | macho.REBASE_TYPE_POINTER,
        macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x8,
        macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
        0x2,
        0x28,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x38,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 3,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x8,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 8,
        macho.REBASE_OPCODE_ADD_ADDR_ULEB,
        0x8,
        macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        macho.REBASE_OPCODE_DONE,
    }, rebase.buffer.items);
}
