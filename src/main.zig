const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Zld = @import("Zld.zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = gpa_allocator.allocator();

pub fn main() anyerror!void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try process.argsAlloc(gpa);
    defer process.argsFree(gpa, all_args);

    // TODO allow for non-native targets
    const opts = try Zld.parseOpts(arena, builtin.target, all_args[1..]);
    const zld = try Zld.openPath(gpa, opts);
    defer zld.deinit();
    try zld.flush();
}
