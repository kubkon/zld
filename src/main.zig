const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Zld = @import("Zld.zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};

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
    \\-weak_framework [name]        Specify weak framework to link against
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
        const msg = std.fmt.allocPrint(gpa_allocator.allocator(), format, args) catch break :ret;
        io.getStdErr().writeAll(msg) catch {};
    }
    process.exit(1);
}

pub const log_level: std.log.Level = switch (builtin.mode) {
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
        .err => "error",
        .warn => "warning",
        .info => "info",
        .debug => "debug",
    };
    const prefix1 = level_txt;
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";

    // Print the message to stderr, silently ignoring any errors
    std.debug.print(prefix1 ++ prefix2 ++ format ++ "\n", args);
}

pub fn main() anyerror!void {
    var gpa = gpa_allocator.allocator();
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try process.argsAlloc(gpa);
    defer process.argsFree(gpa, all_args);

    const args = all_args[1..];
    if (args.len == 0) {
        printHelpAndExit();
    }

    var positionals = std.ArrayList(Zld.LinkObject).init(arena);
    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    var frameworks = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var framework_dirs = std.ArrayList([]const u8).init(arena);
    var rpath_list = std.ArrayList([]const u8).init(arena);
    var out_path: ?[]const u8 = null;
    var syslibroot: ?[]const u8 = null;
    var stack: ?u64 = null;
    var dynamic: bool = false;
    var verbose: bool = false;
    var dylib: bool = false;
    var shared: bool = false;
    var version: ?std.builtin.Version = null;
    var compatibility_version: ?std.builtin.Version = null;
    var gc_sections: bool = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            printHelpAndExit();
        } else if (mem.eql(u8, arg, "--debug-log")) {
            if (i + 1 >= args.len) fatal("Expected parameter after {s}", .{arg});
            i += 1;
            try log_scopes.append(arena, args[i]);
        } else if (mem.eql(u8, arg, "-syslibroot")) {
            if (i + 1 >= args.len) fatal("Expected path after {s}", .{arg});
            i += 1;
            syslibroot = args[i];
        } else if (mem.startsWith(u8, arg, "-l")) {
            try libs.put(args[i][2..], .{});
        } else if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(args[i][2..]);
        } else if (mem.eql(u8, arg, "-framework") or mem.eql(u8, arg, "-weak_framework")) {
            if (i + 1 >= args.len) fatal("Expected framework name after {s}", .{arg});
            i += 1;
            try frameworks.put(args[i], .{});
        } else if (mem.startsWith(u8, arg, "-F")) {
            try framework_dirs.append(args[i][2..]);
        } else if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) fatal("Expected output path after {s}", .{arg});
            i += 1;
            out_path = args[i];
        } else if (mem.eql(u8, arg, "-stack")) {
            if (i + 1 >= args.len) fatal("Expected stack size value after {s}", .{arg});
            i += 1;
            stack = try std.fmt.parseInt(u64, args[i], 10);
        } else if (mem.eql(u8, arg, "-z")) {
            if (i + 1 >= args.len) fatal("Expected another argument after {s}", .{arg});
            i += 1;
            if (mem.startsWith(u8, args[i], "stack-size=")) {
                stack = try std.fmt.parseInt(u64, args[i]["stack-size=".len..], 10);
            } else {
                std.log.warn("TODO unhandled argument '-z {s}'", .{args[i]});
            }
        } else if (mem.startsWith(u8, arg, "-z")) {
            std.log.warn("TODO unhandled argument '-z {s}'", .{args[i]["-z".len..]});
        } else if (mem.eql(u8, arg, "--gc-sections")) {
            gc_sections = true;
        } else if (mem.eql(u8, arg, "--as-needed")) {
            std.log.warn("TODO unhandled argument '--as-needed'", .{});
        } else if (mem.eql(u8, arg, "--allow-shlib-undefined")) {
            std.log.warn("TODO unhandled argument '--allow-shlib-undefined'", .{});
        } else if (mem.startsWith(u8, arg, "-O")) {
            std.log.warn("TODO unhandled argument '-O{s}'", .{args[i]["-O".len..]});
        } else if (mem.eql(u8, arg, "-dylib")) {
            dylib = true;
        } else if (mem.eql(u8, arg, "-shared")) {
            shared = true;
        } else if (mem.eql(u8, arg, "-dynamic")) {
            dynamic = true;
        } else if (mem.eql(u8, arg, "-static")) {
            dynamic = false;
        } else if (mem.eql(u8, arg, "-rpath")) {
            if (i + 1 >= args.len) fatal("Expected path after {s}", .{arg});
            i += 1;
            try rpath_list.append(args[i]);
        } else if (mem.eql(u8, arg, "-compatibility_version")) {
            if (i + 1 >= args.len) fatal("Expected version after {s}", .{arg});
            i += 1;
            compatibility_version = std.builtin.Version.parse(args[i]) catch |err| {
                fatal("Unable to parse {s} {s}: {s}", .{ arg, args[i], @errorName(err) });
            };
        } else if (mem.eql(u8, arg, "-current_version")) {
            if (i + 1 >= args.len) fatal("Expected version after {s}", .{arg});
            i += 1;
            version = std.builtin.Version.parse(args[i]) catch |err| {
                fatal("Unable to parse {s} {s}: {s}", .{ arg, args[i], @errorName(err) });
            };
        } else if (mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else {
            try positionals.append(.{
                .path = arg,
                .must_link = true,
            });
        }
    }

    if (positionals.items.len == 0) {
        fatal("Expected at least one input .o file", .{});
    }

    // TODO allow for non-native targets
    const target = builtin.target;

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
        .libs = libs,
        .frameworks = frameworks,
        .lib_dirs = lib_dirs.items,
        .framework_dirs = framework_dirs.items,
        .rpath_list = rpath_list.items,
        .stack_size_override = stack,
        .version = version,
        .compatibility_version = compatibility_version,
        .gc_sections = gc_sections,
        .verbose = verbose,
    });
    defer zld.deinit();

    try zld.flush();
}
