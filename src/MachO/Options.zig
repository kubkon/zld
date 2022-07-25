const Options = @This();

const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const MachO = @import("../MachO.zig");
const Zld = @import("../Zld.zig");

const usage =
    \\Usage: zld [files...]
    \\
    \\Commands:
    \\  <empty> [files...] (default)  Generate final executable artifact 'a.out' from input '.o' files
    \\
    \\General Options:
    \\-dylib                        Create dynamic library
    \\-dynamic                      Perform dynamic linking
    \\-framework [name]             specify framework to link against
    \\-F[path]                      specify framework search dir
    \\-install_name                 add dylib's install name
    \\-stack                        Override default stack size
    \\-syslibroot [path]            Specify the syslibroot
    \\-weak_framework [name]        specify weak framework to link against
    \\--entitlements                (Linker extension) add path to entitlements file for embedding in code signature
    \\-l[name]                      Specify library to link against
    \\-L[path]                      Specify library search dir
    \\-rpath [path]                 Specify runtime path
    \\-o [path]                     Specify output path for the final artifact
    \\-h, --help                    Print this help and exit
;

fn printHelpAndExit() noreturn {
    io.getStdOut().writeAll(usage) catch {};
    process.exit(0);
}

fn fatal(arena: Allocator, comptime format: []const u8, args: anytype) noreturn {
    ret: {
        const msg = std.fmt.allocPrint(arena, format, args) catch break :ret;
        io.getStdErr().writeAll(msg) catch {};
    }
    process.exit(1);
}

emit: Zld.Emit,
output_mode: Zld.OutputMode,
target: CrossTarget,
platform_version: std.builtin.Version,
sdk_version: std.builtin.Version,
positionals: []const Zld.LinkObject,
libs: std.StringArrayHashMap(Zld.SystemLib),
frameworks: std.StringArrayHashMap(Zld.SystemLib),
lib_dirs: []const []const u8,
framework_dirs: []const []const u8,
rpath_list: []const []const u8,
dynamic: bool = false,
syslibroot: ?[]const u8 = null,
stack_size_override: ?u64 = null,
strip: bool = false,
entry: ?[]const u8 = null,
version: ?std.builtin.Version = null,
compatibility_version: ?std.builtin.Version = null,
install_name: ?[]const u8 = null,
entitlements: ?[]const u8 = null,
pagezero_size: ?u64 = null,
search_strategy: ?MachO.SearchStrategy = null,
headerpad_size: ?u32 = null,
headerpad_max_install_names: bool = false,
dead_strip: bool = false,
dead_strip_dylibs: bool = false,

pub fn parseArgs(arena: Allocator, args: []const []const u8) !Options {
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
    var dylib: bool = false;
    var install_name: ?[]const u8 = null;
    var version: ?std.builtin.Version = null;
    var compatibility_version: ?std.builtin.Version = null;

    var platform_version: std.builtin.Version = builtin.target.os.version_range.semver.min;
    var sdk_version: std.builtin.Version = platform_version;

    const Iterator = struct {
        args: []const []const u8,
        i: usize = 0,
        fn next(it: *@This()) ?[]const u8 {
            if (it.i >= it.args.len) {
                return null;
            }
            defer it.i += 1;
            return it.args[it.i];
        }
    };
    var args_iter = Iterator{ .args = args };

    while (args_iter.next()) |arg| {
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            printHelpAndExit();
        } else if (mem.eql(u8, arg, "-syslibroot")) {
            syslibroot = args_iter.next() orelse fatal(arena, "Expected path after {s}", .{arg});
        } else if (mem.startsWith(u8, arg, "-l")) {
            try libs.put(arg[2..], .{});
        } else if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(arg[2..]);
        } else if (mem.eql(u8, arg, "-framework") or mem.eql(u8, arg, "-weak_framework")) {
            const name = args_iter.next() orelse fatal(arena, "Expected framework name after {s}", .{arg});
            try frameworks.put(name, .{});
        } else if (mem.startsWith(u8, arg, "-F")) {
            try framework_dirs.append(arg[2..]);
        } else if (mem.eql(u8, arg, "-o")) {
            out_path = args_iter.next() orelse fatal(arena, "Expected output path after {s}", .{arg});
        } else if (mem.eql(u8, arg, "-stack")) {
            const stack_s = args_iter.next() orelse
                fatal(arena, "Expected stack size value after {s}", .{arg});
            stack = try std.fmt.parseInt(u64, stack_s, 10);
        } else if (mem.eql(u8, arg, "-dylib")) {
            dylib = true;
        } else if (mem.eql(u8, arg, "-dynamic")) {
            dynamic = true;
        } else if (mem.eql(u8, arg, "-static")) {
            dynamic = false;
        } else if (mem.eql(u8, arg, "-rpath")) {
            const rpath = args_iter.next() orelse fatal(arena, "Expected path after {s}", .{arg});
            try rpath_list.append(rpath);
        } else if (mem.eql(u8, arg, "-compatibility_version")) {
            const raw = args_iter.next() orelse fatal(arena, "Expected version after {s}", .{arg});
            compatibility_version = std.builtin.Version.parse(raw) catch |err| {
                fatal(arena, "Unable to parse {s} {s}: {s}", .{ arg, raw, @errorName(err) });
            };
        } else if (mem.eql(u8, arg, "-current_version")) {
            const raw = args_iter.next() orelse fatal(arena, "Expected version after {s}", .{arg});
            version = std.builtin.Version.parse(raw) catch |err| {
                fatal(arena, "Unable to parse {s} {s}: {s}", .{ arg, raw, @errorName(err) });
            };
        } else if (mem.eql(u8, arg, "-install_name")) {
            install_name = args_iter.next() orelse fatal(arena, "Expected argument after {s}", .{arg});
        } else {
            try positionals.append(.{
                .path = arg,
                .must_link = true,
            });
        }
    }

    if (positionals.items.len == 0) {
        fatal(arena, "Expected at least one input .o file", .{});
    }

    return Options{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = out_path orelse "a.out",
        },
        .dynamic = dynamic,
        .target = CrossTarget.fromTarget(builtin.target),
        .platform_version = platform_version,
        .sdk_version = sdk_version,
        .output_mode = if (dylib) .lib else .exe,
        .syslibroot = syslibroot,
        .positionals = positionals.items,
        .libs = libs,
        .frameworks = frameworks,
        .lib_dirs = lib_dirs.items,
        .framework_dirs = framework_dirs.items,
        .rpath_list = rpath_list.items,
        .stack_size_override = stack,
        .install_name = install_name,
        .version = version,
        .compatibility_version = compatibility_version,
    };
}
