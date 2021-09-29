const Archive = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const mem = std.mem;

const Allocator = mem.Allocator;
const Object = @import("Object.zig");

file: fs.File,
name: []const u8,

header: ?ar_hdr = null,

/// Parsed table of contents.
/// Each symbol name points to a list of all definition
/// sites within the current static archive.
toc: std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(u32)) = .{},

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";
/// Size of that string.
const SARMAG: u4 = 8;

/// String in ar_fmag at the end of each header.
const ARFMAG: *const [2:0]u8 = "`\n";

const ar_hdr = extern struct {
    /// Member file name, sometimes / terminated.
    ar_name: [16]u8,

    /// File date, decimal seconds since Epoch.
    ar_date: [12]u8,

    /// User ID, in ASCII format.
    ar_uid: [6]u8,

    /// Group ID, in ASCII format.
    ar_gid: [6]u8,

    /// File mode, in ASCII octal.
    ar_mode: [8]u8,

    /// File size, in ASCII decimal.
    ar_size: [10]u8,

    /// Always contains ARFMAG.
    ar_fmag: [2]u8,
};

pub fn deinit(self: *Archive, allocator: *Allocator) void {
    for (self.toc.keys()) |*key| {
        allocator.free(key.*);
    }
    for (self.toc.values()) |*value| {
        value.deinit(allocator);
    }
    self.toc.deinit(allocator);
    allocator.free(self.name);
}

pub fn parse(self: *Archive, allocator: *Allocator, target: std.Target) !void {
    _ = allocator;
    _ = target;
    const reader = self.file.reader();
    const magic = try reader.readBytesNoEof(SARMAG);

    if (!mem.eql(u8, &magic, ARMAG)) {
        log.debug("invalid magic: expected '{s}', found '{s}'", .{ ARMAG, magic });
        return error.NotArchive;
    }

    self.header = try reader.readStruct(ar_hdr);
    if (!mem.eql(u8, &self.header.?.ar_fmag, ARFMAG)) {
        log.debug("invalid header delimiter: expected '{s}', found '{s}'", .{ ARFMAG, self.header.?.ar_fmag });
        return error.NotArchive;
    }

    log.debug("{}", .{self.header.?});
}
