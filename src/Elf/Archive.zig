objects: std.ArrayListUnmanaged(Object) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

pub fn isValidMagic(magic: []const u8) bool {
    if (!mem.eql(u8, magic, elf.ARMAG)) {
        log.debug("invalid archive magic: expected '{s}', found '{s}'", .{ elf.ARMAG, magic });
        return false;
    }
    return true;
}

pub fn deinit(self: *Archive, allocator: Allocator) void {
    self.objects.deinit(allocator);
    self.strtab.deinit(allocator);
}

pub fn parse(self: *Archive, elf_file: *Elf, path: []const u8, file_handle: File.HandleIndex) !void {
    const gpa = elf_file.base.allocator;
    const file = elf_file.getFileHandle(file_handle);

    const size = (try file.stat()).size;
    const reader = file.reader();
    _ = try reader.readBytesNoEof(elf.ARMAG.len);

    var pos: usize = elf.ARMAG.len;
    while (true) {
        if (pos >= size) break;
        if (!mem.isAligned(pos, 2)) {
            try file.seekBy(1);
            pos += 1;
        }

        const hdr = try reader.readStruct(elf.ar_hdr);
        pos += @sizeOf(elf.ar_hdr);

        if (!mem.eql(u8, &hdr.ar_fmag, elf.ARFMAG)) {
            elf_file.base.fatal("{s}: invalid header delimiter: expected '{s}', found '{s}'", .{
                path,
                std.fmt.fmtSliceEscapeLower(elf.ARFMAG),
                std.fmt.fmtSliceEscapeLower(&hdr.ar_fmag),
            });
            return error.ParseFailed;
        }

        const obj_size = try hdr.size();
        defer {
            _ = file.seekBy(obj_size) catch {};
            pos += obj_size;
        }

        if (hdr.isSymtab()) continue;
        if (hdr.isStrtab()) {
            try self.strtab.resize(gpa, obj_size);
            const amt = try file.readAll(self.strtab.items);
            if (amt != obj_size) return error.InputOutput;
            continue;
        }
        if (hdr.isSymdef() or hdr.isSymdefSorted()) continue;

        const name = if (hdr.name()) |name|
            name
        else if (try hdr.nameOffset()) |off|
            self.getString(off)
        else
            unreachable;

        const object = Object{
            .archive = .{
                .path = try gpa.dupe(u8, path),
                .offset = pos,
            },
            .path = try gpa.dupe(u8, name),
            .file_handle = file_handle,
            .index = undefined,
            .alive = false,
        };

        log.debug("extracting object '{s}' from archive '{s}'", .{ object.path, path });

        try self.objects.append(gpa, object);
    }
}

fn getString(self: Archive, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:'\n']const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
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
const File = @import("file.zig").File;
const Object = @import("Object.zig");
