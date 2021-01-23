const Zld = @This();

const std = @import("std");

const Allocator = std.mem.Allocator;
const CrossTarget = std.zig.CrossTarget;

allocator: *Allocator,

pub fn init(allocator: *Allocator) Zld {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Zld) void {}

pub fn link(self: *Zld, files: []const []const u8, target: CrossTarget) !void {}
