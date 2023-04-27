const Options = @This();

const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const Zld = @import("../Zld.zig");

const usage =
    \\Usage: {s} [files...]
    \\
    \\General Options:
    \\--allow-multiple-definition   Allow multiple definitions
    \\--entry=[name], -e [name]     Set name of the entry point symbol
    \\--gc-sections                 Force removal of functions and data that are unreachable by the entry point or exported symbols
    \\-l[name]                      Specify library to link against
    \\-L[path]                      Specify library search dir
    \\--rpath=[path], -R [path]     Specify runtime path
    \\--shared                      Create dynamic library
    \\-o [path]                     Specify output path for the final artifact
    \\-z [arg]                      Set linker extension flags
    \\  stack-size=[value]          Override default stack size
    \\-h, --help                    Print this help and exit
    \\--debug-log [scope]           Turn on debugging logs for [scope] (requires zld compiled with -Dlog)
    \\
    \\ld.zld: supported targets: elf64-x86-64
;

emit: Zld.Emit,
output_mode: Zld.OutputMode,
positionals: []const Zld.LinkObject,
libs: std.StringArrayHashMap(Zld.SystemLib),
lib_dirs: []const []const u8,
rpath_list: []const []const u8,
stack_size: ?u64 = null,
strip: bool = false,
entry: ?[]const u8 = null,
gc_sections: bool = false,
allow_multiple_definition: bool = false,

pub fn parseArgs(arena: Allocator, ctx: Zld.MainCtx) !Options {
    if (ctx.args.len == 0) {
        ctx.printSuccess(usage, .{ctx.cmd});
    }

    var positionals = std.ArrayList(Zld.LinkObject).init(arena);
    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    var rpath_list = std.ArrayList([]const u8).init(arena);
    var out_path: ?[]const u8 = null;
    var stack_size: ?u64 = null;
    var shared: bool = false;
    var gc_sections: bool = false;
    var entry: ?[]const u8 = null;
    var allow_multiple_definition: bool = false;

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
    var args_iter = Iterator{ .args = ctx.args };

    while (args_iter.next()) |arg| {
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            ctx.printSuccess(usage, .{ctx.cmd});
        } else if (mem.eql(u8, arg, "--debug-log")) {
            const scope = args_iter.next() orelse ctx.printFailure("Expected log scope after {s}", .{arg});
            try ctx.log_scopes.append(scope);
        } else if (mem.startsWith(u8, arg, "-l")) {
            try libs.put(arg[2..], .{});
        } else if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(arg[2..]);
        } else if (mem.eql(u8, arg, "-o")) {
            out_path = args_iter.next() orelse
                ctx.printFailure("Expected output path after {s}", .{arg});
        } else if (mem.eql(u8, arg, "-z")) {
            const z_arg = args_iter.next() orelse
                ctx.printFailure("Expected another argument after {s}", .{arg});
            if (mem.startsWith(u8, z_arg, "stack-size=")) {
                stack_size = try std.fmt.parseInt(u64, z_arg["stack-size=".len..], 10);
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
        } else if (mem.eql(u8, arg, "--shared")) {
            shared = true;
        } else if (mem.startsWith(u8, arg, "--rpath=")) {
            try rpath_list.append(arg["--rpath=".len..]);
        } else if (mem.eql(u8, arg, "-R")) {
            const rpath = args_iter.next() orelse
                ctx.printFailure("Expected path after {s}", .{arg});
            try rpath_list.append(rpath);
        } else if (mem.startsWith(u8, arg, "--entry=")) {
            entry = arg["--entry=".len..];
        } else if (mem.eql(u8, arg, "-e")) {
            entry = args_iter.next() orelse ctx.printFailure("Expected name after {s}", .{arg});
        } else if (mem.eql(u8, arg, "--allow-multiple-definition")) {
            allow_multiple_definition = true;
        } else {
            try positionals.append(.{
                .path = arg,
                .must_link = true,
            });
        }
    }

    if (positionals.items.len == 0) {
        ctx.printFailure("Expected at least one input .o file", .{});
    }

    return Options{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = out_path orelse "a.out",
        },
        .output_mode = if (shared) .lib else .exe,
        .positionals = positionals.items,
        .libs = libs,
        .lib_dirs = lib_dirs.items,
        .rpath_list = rpath_list.items,
        .stack_size = stack_size,
        .gc_sections = gc_sections,
        .entry = entry,
        .allow_multiple_definition = allow_multiple_definition,
    };
}
