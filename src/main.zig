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

pub fn main() !void {
    const all_args = try process.argsAlloc(gpa);
    defer process.argsFree(gpa, all_args);

    if (mem.eql(u8, all_args[0], "zld.ld")) {
        return Zld.parseAndFlush(gpa, .elf, all_args[1..]);
    } else if (mem.eql(u8, all_args[0], "zld.ld64")) {
        return Zld.parseAndFlush(gpa, .macho, all_args[1..]);
    } else if (mem.eql(u8, all_args[0], "zld.link")) {
        return Zld.parseAndFlush(gpa, .coff, all_args[1..]);
    } else {
        unreachable;
    }
}
