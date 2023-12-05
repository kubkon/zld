path: []const u8,
data: []const u8,

objects: std.ArrayListUnmanaged(Object) = .{},
strtab: []const u8 = &[0]u8{},

pub fn isValidMagic(magic: []const u8) bool {
    if (!mem.eql(u8, magic, elf.ARMAG)) {
        log.debug("invalid archive magic: expected '{s}', found '{s}'", .{ elf.ARMAG, magic });
        return false;
    }
    return true;
}

pub fn deinit(self: *Archive, allocator: Allocator) void {
    self.objects.deinit(allocator);
}

pub fn parse(self: *Archive, arena: Allocator, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();
    _ = try reader.readBytesNoEof(elf.ARMAG.len);

    while (true) {
        if (stream.pos % 2 != 0) {
            stream.pos += 1;
        }

        const hdr = reader.readStruct(elf.ar_hdr) catch break;

        if (!mem.eql(u8, &hdr.ar_fmag, elf.ARFMAG)) {
            return elf_file.base.fatal(
                "{s}: invalid header delimiter: expected '{s}', found '{s}'",
                .{ self.path, std.fmt.fmtSliceEscapeLower(elf.ARFMAG), std.fmt.fmtSliceEscapeLower(&hdr.ar_fmag) },
            );
        }

        const size = try hdr.size();
        defer {
            _ = stream.seekBy(size) catch {};
        }

        if (hdr.isSymtab()) continue;
        if (hdr.isStrtab()) {
            self.strtab = self.data[stream.pos..][0..size];
            continue;
        }
        if (hdr.isSymdef() or hdr.isSymdefSorted()) continue;

        const name = if (hdr.name()) |name|
            try arena.dupe(u8, name)
        else if (try hdr.nameOffset()) |off|
            try arena.dupe(u8, self.getString(off))
        else
            unreachable;

        const object = Object{
            .archive = self.path,
            .path = name,
            .data = self.data[stream.pos..][0..size],
            .index = undefined,
            .alive = false,
        };

        log.debug("extracting object '{s}' from archive '{s}'", .{ object.path, self.path });

        try self.objects.append(gpa, object);
    }
}

fn getString(self: Archive, off: u32) []const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@as([*:'\n']const u8, @ptrCast(self.strtab.ptr + off)), 0);
}

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @This();
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");
