const Zld = @import("Zld.zig");

const std = @import("std");
const io = std.io;
const mem = std.mem;
const process = std.process;

const CrossTarget = std.zig.CrossTarget;
const Target = std.Target;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

const usage =
    \\Usage: zld [files...]
    \\
    \\Commands:
    \\  <empty> [files...] (default)  Generate final executable artifact 'a.out' from input '.o' files
    \\
    \\General Options:
    \\-h, --help                    Print this help and exit
;

fn printHelpAndExit() noreturn {
    io.getStdOut().writeAll(usage) catch {};
    process.exit(0);
}

pub fn main() anyerror!void {
    const all_args = try process.argsAlloc(&gpa.allocator);
    defer process.argsFree(&gpa.allocator, all_args);

    const args = all_args[1..];
    if (args.len == 0) {
        printHelpAndExit();
    }
    const first_arg = args[0];
    if (mem.eql(u8, first_arg, "--help") or mem.eql(u8, first_arg, "-h")) {
        printHelpAndExit();
    }

    var zld = Zld.init(&gpa.allocator);
    defer zld.deinit();

    const cross_target = CrossTarget.fromTarget(Target.current);
    try zld.link(args, cross_target);
}
