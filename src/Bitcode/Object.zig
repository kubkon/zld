const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Bitcode = @import("../Bitcode.zig");
pub const magic = "BC\xC0\xDE";

file: fs.File,
name: []const u8,
file_offset: ?u32 = null,

// Reference for llvm bitcode format:
// https://llvm.org/docs/BitCodeFormat.html

pub fn deinit(self: *Object, allocator: Allocator) void {
    _ = self;
    _ = allocator;
    // ZAR MODIFICATION:
    // We manage memory of assigned names ourselves in zar - so
    // freeing this here for that does not make much sense.
    // allocator.free(self.name);
}

pub fn parse(self: *Object, allocator: Allocator, target: std.Target) !void {
    _ = self;
    _ = allocator;
    _ = target;
}
