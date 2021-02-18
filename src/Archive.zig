const Archive = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.Archive);
const macho = std.macho;
const mem = std.mem;

const Allocator = mem.Allocator;
const Object = @import("Object.zig");
const parseName = @import("Zld.zig").parseName;

usingnamespace @import("commands.zig");

allocator: *Allocator,

objects: std.ArrayListUnmanaged(Object) = .{},

// Archive files start with the ARMAG identifying string.  Then follows a
// `struct ar_hdr', and as many bytes of member file data as its `ar_size'
// member indicates, for each member file.
/// String that begins an archive file.
pub const ARMAG: *const [SARMAG:0]u8 = "!<arch>\n";

/// Size of that string.
pub const SARMAG: u4 = 8;

/// String in ar_fmag at the end of each header.
pub const ARFMAG: *const [2:0]u8 = "`\n";

pub const ar_hdr = extern struct {
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

pub fn deinit(self: *Archive) void {}

/// Caller owns the returned Archive instance and is responsible for calling
/// `deinit` to free allocated memory.
pub fn initFromFile(allocator: *Allocator, name: []const u8, file: fs.File) !Archive {
    return error.NotArchive;
}
