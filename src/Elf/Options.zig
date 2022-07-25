const Options = @This();

const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Elf = @import("../Elf.zig");
const Zld = @import("../Zld.zig");

const usage =
    \\Usage: ld.zld [files...]
    \\
    \\Commands:
    \\  <empty> [files...] (default)  Generate final executable artifact 'a.out' from input '.o' files
    \\
    \\General Options:
    \\-l[name]                      Specify library to link against
    \\-L[path]                      Specify library search dir
    \\-shared                       Create dynamic library
    \\--gc-sections                 Force removal of functions and data that are unreachable by the entry point or exported symbols
    \\--no-gc-section               Don't force removal of unreachable functions and data
    \\-rpath [path]                 Specify runtime path
    \\-o [path]                     Specify output path for the final artifact
    \\-z [arg]                      Set linker extension flags
    \\  stack-size                  Override default stack size
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
positionals: []const Zld.LinkObject,
libs: std.StringArrayHashMap(Zld.SystemLib),
lib_dirs: []const []const u8,
rpath_list: []const []const u8,
stack_size_override: ?u64 = null,
strip: bool = false,
entry: ?[]const u8 = null,
gc_sections: ?bool = null,

pub fn parseArgs(arena: Allocator, args: []const []const u8) !Options {
    if (args.len == 0) {
        printHelpAndExit();
    }

    var positionals = std.ArrayList(Zld.LinkObject).init(arena);
    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    var rpath_list = std.ArrayList([]const u8).init(arena);
    var out_path: ?[]const u8 = null;
    var stack: ?u64 = null;
    var shared: bool = false;
    var gc_sections: ?bool = null;

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
        } else if (mem.startsWith(u8, arg, "-l")) {
            try libs.put(arg[2..], .{});
        } else if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(arg[2..]);
        } else if (mem.eql(u8, arg, "-o")) {
            out_path = args_iter.next() orelse
                fatal(arena, "Expected output path after {s}", .{arg});
        } else if (mem.eql(u8, arg, "-z")) {
            const z_arg = args_iter.next() orelse
                fatal(arena, "Expected another argument after {s}", .{arg});
            if (mem.startsWith(u8, z_arg, "stack-size=")) {
                stack = try std.fmt.parseInt(u64, z_arg["stack-size=".len..], 10);
            } else {
                std.log.warn("TODO unhandled argument '-z {s}'", .{z_arg});
            }
        } else if (mem.startsWith(u8, arg, "-z")) {
            std.log.warn("TODO unhandled argument '-z {s}'", .{arg["-z".len..]});
        } else if (mem.eql(u8, arg, "--gc-sections")) {
            gc_sections = true;
        } else if (mem.eql(u8, arg, "--as-needed")) {
            std.log.warn("TODO unhandled argument '--as-needed'", .{});
        } else if (mem.eql(u8, arg, "--allow-shlib-undefined")) {
            std.log.warn("TODO unhandled argument '--allow-shlib-undefined'", .{});
        } else if (mem.startsWith(u8, arg, "-O")) {
            std.log.warn("TODO unhandled argument '-O{s}'", .{arg["-O".len..]});
        } else if (mem.eql(u8, arg, "-shared")) {
            shared = true;
        } else if (mem.eql(u8, arg, "-rpath")) {
            const rpath = args_iter.next() orelse
                fatal(arena, "Expected path after {s}", .{arg});
            try rpath_list.append(rpath);
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
        .target = CrossTarget.fromTarget(builtin.target),
        .output_mode = if (shared) .lib else .exe,
        .positionals = positionals.items,
        .libs = libs,
        .lib_dirs = lib_dirs.items,
        .rpath_list = rpath_list.items,
        .stack_size_override = stack,
        .gc_sections = gc_sections,
    };
}
