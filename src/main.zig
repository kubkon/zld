const Zld = @import("Zld.zig");

const std = @import("std");
const build_options = @import("build_options");
const io = std.io;
const mem = std.mem;
const process = std.process;

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
    \\-o [path]                     Specify output path for the final artifact
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

pub const log_level: std.log.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast => .err,
    .ReleaseSmall => .crit,
};

var log_scopes: std.ArrayListUnmanaged([]const u8) = .{};

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    // Hide debug messages unless:
    // * logging enabled with `-Dlog`.
    // * the --debug-log arg for the scope has been provided
    if (@enumToInt(level) > @enumToInt(std.log.level) or
        @enumToInt(level) > @enumToInt(std.log.Level.info))
    {
        if (!build_options.enable_logging) return;

        const scope_name = @tagName(scope);
        for (log_scopes.items) |log_scope| {
            if (mem.eql(u8, log_scope, scope_name))
                break;
        } else return;
    }

    // We only recognize 4 log levels in this application.
    const level_txt = switch (level) {
        .emerg, .alert, .crit, .err => "error",
        .warn => "warning",
        .notice, .info => "info",
        .debug => "debug",
    };
    const prefix1 = level_txt;
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    // Print the message to stderr, silently ignoring any errors
    std.debug.print(prefix1 ++ prefix2 ++ format ++ "\n", args);
}

pub fn main() anyerror!void {
    const all_args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, all_args);
    defer log_scopes.deinit(allocator);

    const args = all_args[1..];
    if (args.len == 0) {
        printHelpAndExit();
    }

    var input_files = std.ArrayList([]const u8).init(allocator);
    defer input_files.deinit();
    var out_path: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            printHelpAndExit();
        }
        if (mem.eql(u8, arg, "--debug-log")) {
            if (i + 1 >= args.len) fatal("Expected parameter after {s}", .{arg});
            i += 1;
            try log_scopes.append(allocator, args[i]);
            continue;
        }
        if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) fatal("Expected output path after {s}", .{arg});
            i += 1;
            out_path = args[i];
            continue;
        }
        try input_files.append(arg);
    }

    if (input_files.items.len == 0) {
        fatal("Expected at least one input .o file", .{});
    }

    var zld = Zld.init(allocator);
    defer zld.deinit();

    const final_out_path = blk: {
        if (out_path) |p| break :blk try allocator.dupe(u8, p);
        const prefix = std.fs.path.dirname(input_files.items[0]) orelse ".";
        break :blk try std.fs.path.join(allocator, &[_][]const u8{ prefix, "a.out" });
    };
    defer allocator.free(final_out_path);

    try zld.link(input_files.items, final_out_path);
}
