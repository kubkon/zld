const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log.scoped(.bind);
const macho = std.macho;

const Allocator = std.mem.Allocator;

pub const Rebase = struct {
    entries: std.ArrayListUnmanaged(Entry) = .{},
    buffer: std.ArrayListUnmanaged(u8) = .{},

    const Entry = struct {
        offset: u64,
        segment_id: u8,

        pub fn greaterThan(ctx: void, entry: Entry, other: Entry) bool {
            _ = ctx;
            if (entry.segment_id == other.segment_id) {
                return entry.offset > other.offset;
            }
            return entry.segment_id > other.segment_id;
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

        std.sort.sort(Entry, rebase.entries.items, {}, Entry.greaterThan);

        var count: usize = 1;
        var prev = rebase.entries.pop();

        try writer.writeByte(macho.REBASE_OPCODE_SET_TYPE_IMM | @truncate(u4, macho.REBASE_TYPE_POINTER));
        try writer.writeByte(macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, prev.segment_id));
        try std.leb.writeULEB128(writer, prev.offset);
        log.debug("rebase: starting segment: {d}", .{prev.segment_id});
        log.debug("        start offset: {x}", .{prev.offset});

        while (rebase.entries.popOrNull()) |next| {
            if (prev.segment_id != next.segment_id) {
                try writer.writeByte(macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, next.segment_id));
                try std.leb.writeULEB128(writer, next.offset);
                log.debug("rebase: changing segments: {d} -> {d}", .{ prev.segment_id, next.segment_id });
                log.debug("        new start offset: {x}", .{next.offset});
            } else {
                log.debug("rebase: prev offset: {x}, next offset: {x}", .{ prev.offset, next.offset });
                const delta = next.offset - prev.offset - @sizeOf(u64);
                if (delta == 0) {
                    count += 1;
                } else {
                    if (count > 0) {
                        log.debug("rebase: do with count: {d}", .{count});
                        if (count < 0xf) {
                            try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | @truncate(u4, count));
                        } else {
                            try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
                            try std.leb.writeULEB128(writer, count);
                        }
                        try writer.writeByte(macho.REBASE_OPCODE_ADD_ADDR_ULEB);
                        try std.leb.writeULEB128(writer, delta);
                        count = 1;
                    } else {
                        log.debug("rebase: do add: {x}", .{delta});
                        try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB);
                        try std.leb.writeULEB128(writer, delta);
                    }
                }
            }

            prev = next;
        }

        try writer.writeByte(macho.REBASE_OPCODE_DONE);
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
