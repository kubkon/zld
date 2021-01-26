const Zld = @import("Zld.zig");

const std = @import("std");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = &gpa.allocator;

const usage =
    \\Usage: zld [files...]
    \\
    \\Commands:
    \\  <empty> [files...] (default)  Generate final executable artifact 'a.out' from input '.o' files
    \\
    \\General Options:
    \\-h, --help                    Print this help and exit
    \\-target [triple]              Specifies the target triple (e.g., aarch64-macos-gnu)
;

fn printHelpAndExit() noreturn {
    io.getStdOut().writeAll(usage) catch {};
    process.exit(0);
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    ret: {
        const msg = std.fmt.allocPrint(allocator, format, args) catch break :ret;
        io.getStdErr().writeAll(msg) catch {};
    }
    process.exit(1);
}

fn parseTarget(triple: []const u8) !Target {
    const ct = try CrossTarget.parse(.{ .arch_os_abi = triple });
    return ct.toTarget();
}

pub fn main() anyerror!void {
    const all_args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, all_args);

    const args = all_args[1..];
    if (args.len == 0) {
        printHelpAndExit();
    }

    var input_files = std.ArrayList([]const u8).init(allocator);
    defer input_files.deinit();
    var target = Target.current;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            printHelpAndExit();
        }
        if (mem.eql(u8, arg, "-target")) {
            if (i + 1 >= args.len) fatal("Expected target triple after {s}", .{arg});
            i += 1;
            const triple = args[i];
            target = try parseTarget(triple);
            continue;
        }
        try input_files.append(arg);
    }

    var zld = Zld.init(allocator, target);
    defer zld.deinit();
    try zld.link(input_files.items);
}
