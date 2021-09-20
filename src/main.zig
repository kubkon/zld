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
    \\--verbose                     Print the full invocation
    \\-dynamic                      Perform dynamic linking
    \\-dylib                        Create dynamic library
    \\-shared                       Create dynamic library
    \\-syslibroot [path]            Specify the syslibroot
    \\-l[name]                      Specify library to link against
    \\-L[path]                      Specify library search dir
    \\-framework [name]             Specify framework to link against
    \\-F[path]                      Specify framework search dir
    \\-rpath [path]                 Specify runtime path
    \\-stack                        Override default stack size
    \\-o [path]                     Specify output path for the final artifact
    \\--debug-log [name]            Turn on debugging for [name] backend (requires zld to be compiled with -Dlog)
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
    var frameworks = std.ArrayList([]const u8).init(arena);
    var framework_dirs = std.ArrayList([]const u8).init(arena);
    var rpath_list = std.ArrayList([]const u8).init(arena);
    var out_path: ?[]const u8 = null;
    var syslibroot: ?[]const u8 = null;
    var stack: ?u64 = null;
    var dynamic: bool = false;
    var verbose: bool = false;
    var dylib: bool = false;
    var shared: bool = false;

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
            syslibroot = args[i];
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
        if (mem.eql(u8, arg, "-framework")) {
            if (i + 1 >= args.len) fatal("Expected framework name after {s}", .{arg});
            i += 1;
            try frameworks.append(args[i]);
            continue;
        }
        if (mem.startsWith(u8, arg, "-F")) {
            try framework_dirs.append(args[i][2..]);
            continue;
        }
        if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) fatal("Expected output path after {s}", .{arg});
            i += 1;
            out_path = args[i];
            continue;
        }
        if (mem.eql(u8, arg, "-stack")) {
            if (i + 1 >= args.len) fatal("Expected stack size value after {s}", .{arg});
            i += 1;
            stack = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (mem.eql(u8, arg, "-dylib")) {
            dylib = true;
            continue;
        }
        if (mem.eql(u8, arg, "-shared")) {
            shared = true;
            continue;
        }
        if (mem.eql(u8, arg, "-dynamic")) {
            dynamic = true;
            continue;
        }
        if (mem.eql(u8, arg, "-rpath")) {
            if (i + 1 >= args.len) fatal("Expected path after {s}", .{arg});
            i += 1;
            try rpath_list.append(args[i]);
            continue;
        }
        if (mem.eql(u8, arg, "--verbose")) {
            verbose = true;
            continue;
        }
        try positionals.append(arg);
    }

    if (positionals.items.len == 0) {
        fatal("Expected at least one input .o file", .{});
    }

    if (verbose) {
        var argv = std.ArrayList([]const u8).init(arena);
        try argv.append("zld");

        if (dynamic) {
            try argv.append("-dynamic");
        }
        if (syslibroot) |path| {
            try argv.append("-syslibroot");
            try argv.append(path);
        }
        if (shared) {
            try argv.append("-shared");
        }
        if (dylib) {
            try argv.append("-dylib");
        }
        if (stack) |st| {
            try argv.append("-stack");
            try argv.append(try std.fmt.allocPrint(arena, "{d}", .{st}));
        }
        if (out_path) |path| {
            try argv.append("-o");
            try argv.append(path);
        }
        for (libs.items) |lib| {
            try argv.append(try std.fmt.allocPrint(arena, "-l{s}", .{lib}));
        }
        for (lib_dirs.items) |dir| {
            try argv.append(try std.fmt.allocPrint(arena, "-L{s}", .{dir}));
        }
        for (frameworks.items) |fw| {
            try argv.append("-framework");
            try argv.append(fw);
        }
        for (framework_dirs.items) |dir| {
            try argv.append(try std.fmt.allocPrint(arena, "-F{s}", .{dir}));
        }
        for (rpath_list.items) |rpath| {
            try argv.append("-rpath");
            try argv.append(rpath);
        }
        for (positionals.items) |pos| {
            try argv.append(pos);
        }
        try argv.append("\n");

        try io.getStdOut().writeAll(try mem.join(arena, " ", argv.items));
    }

    // TODO allow for non-native targets
    const target = std.Target.current;
    if (std.Target.current.os.tag == .macos) {
        if (syslibroot == null) {
            syslibroot = try std.zig.system.darwin.getSDKPath(arena, target);
        }
        try libs.append("System");
        try libs.append("c");
        try lib_dirs.append("/usr/lib");
        if (frameworks.items.len > 0) {
            try framework_dirs.append("/System/Library/Frameworks");
        }
    }

    var zld = try Zld.openPath(gpa, .{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = out_path orelse "a.out",
        },
        .dynamic = dynamic,
        .target = target,
        .output_mode = if (dylib or shared) .lib else .exe,
        .syslibroot = syslibroot,
        .positionals = positionals.items,
        .libs = libs.items,
        .frameworks = frameworks.items,
        .lib_dirs = lib_dirs.items,
        .framework_dirs = framework_dirs.items,
        .rpath_list = rpath_list.items,
        .stack_size_override = stack,
    });
    defer {
        zld.closeFiles();
        zld.deinit();
    }
    try zld.flush();
}
