const std = @import("std");
const build_options = @import("build_options");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Zld = @import("Zld.zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = &gpa_allocator.allocator;

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
        const msg = std.fmt.allocPrint(gpa, format, args) catch break :ret;
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
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = &arena_allocator.allocator;

    const all_args = try process.argsAlloc(gpa);
    defer process.argsFree(gpa, all_args);

    const args = all_args[1..];
    if (args.len == 0) {
        printHelpAndExit();
    }

    var positionals = std.ArrayList([]const u8).init(arena);
    var libs = std.ArrayList([]const u8).init(arena);
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    var sysroot: ?[]const u8 = null;
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
            try log_scopes.append(arena, args[i]);
            continue;
        }
        if (mem.eql(u8, arg, "-syslibroot")) {
            if (i + 1 >= args.len) fatal("Expected path after {s}", .{arg});
            i += 1;
            sysroot = args[i];
            continue;
        }
        if (mem.startsWith(u8, arg, "-l")) {
            try libs.append(args[i][2..]);
            continue;
        }
        if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(args[i][2..]);
            continue;
        }
        if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) fatal("Expected output path after {s}", .{arg});
            i += 1;
            out_path = args[i];
            continue;
        }
        try positionals.append(arg);
    }

    if (positionals.items.len == 0) {
        fatal("Expected at least one input .o file", .{});
    }

    // TODO infer target if not specified
    const target = CrossTarget{
        .cpu_arch = .x86_64,
        .os_tag = .macos,
    };

    var zld = try Zld.openPath(gpa, .{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = "a.out",
        },
        .target = target.toTarget(),
        .output_mode = .exe,
        .sysroot = sysroot,
        .positionals = positionals.items,
        .libs = libs.items,
        .frameworks = &[0][]const u8{},
        .lib_dirs = lib_dirs.items,
        .framework_dirs = &[0][]const u8{},
        .rpath_list = &[0][]const u8{},
    });
    defer {
        zld.closeFiles();
        zld.deinit();
    }
    try zld.flush();
}
