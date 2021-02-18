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

pub fn deinit(self: *Archive) void {}

/// Caller owns the returned Archive instance and is responsible for calling
/// `deinit` to free allocated memory.
pub fn initFromFile(allocator: *Allocator, name: []const u8, file: fs.File) !Archive {
    log.debug("{s}", .{std.os.ARMAG});
    return error.NotArchive;
}
