const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const macho = std.macho;

// TODO split it up into rebase, bind/weak-bind and lazy-bind specific
// containers and perform compact encoding on them.
pub const Pointer = struct {
    offset: u64,
    segment_id: u16,
    dylib_ordinal: ?i64 = null,
    name: ?[]const u8 = null,
    bind_flags: u4 = 0,
    addend: ?i64 = null,
};

pub fn rebaseInfoSize(pointers: []const Pointer) !u64 {
    var stream = std.io.countingWriter(std.io.null_writer);
    var writer = stream.writer();
    var size: u64 = 0;

    for (pointers) |pointer| {
        size += 2;
        try leb.writeILEB128(writer, pointer.offset);
        size += 1;
    }

    size += 1 + stream.bytes_written;
    return size;
}

pub fn writeRebaseInfo(pointers: []const Pointer, writer: anytype) !void {
    for (pointers) |pointer| {
        try writer.writeByte(macho.REBASE_OPCODE_SET_TYPE_IMM | @truncate(u4, macho.REBASE_TYPE_POINTER));
        try writer.writeByte(macho.REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, pointer.segment_id));

        try leb.writeILEB128(writer, pointer.offset);
        try writer.writeByte(macho.REBASE_OPCODE_DO_REBASE_IMM_TIMES | @truncate(u4, 1));
    }
    try writer.writeByte(macho.REBASE_OPCODE_DONE);
}

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
