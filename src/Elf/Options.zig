const usage =
    \\Usage: {s} [files...]
    \\
    \\General Options:
    \\--allow-multiple-definition   Allow multiple definitions
    \\--Bstatic                     Do not link against shared libraries
    \\--end-group                   Ignored for compatibility with GNU
    \\--entry=[value], -e [value]   Set name of the entry point symbol
    \\--gc-sections                 Remove unused sections
    \\--no-gc-sections              Don't remove unused sections (default)
    \\--print-gc-sections           List removed unused sections to stderr
    \\-l[value]                     Specify library to link against
    \\-L[value]                     Specify library search dir
    \\-m [value]                    Set target emulation
    \\--rpath=[value], -R [value]   Specify runtime path
    \\--shared                      Create dynamic library
    \\--static                      Alias for --Bstatic
    \\--start-group                 Ignored for compatibility with GNU
    \\-o [value]                    Specify output path for the final artifact
    \\-z                            Set linker extension flags
    \\  stack-size=[value]          Override default stack size
    \\  execstack                   Require executable stack
    \\  noexecstack                 Force stack non-executable
    \\  execstack-if-needed         Make the stack executable if the input file explicitly requests it
    \\-h, --help                    Print this help and exit
    \\--verbose                     Print full linker invocation to stderr
    \\--debug-log [value]           Turn on debugging logs for [value] (requires zld compiled with -Dlog)
    \\
    \\ld.zld: supported targets: elf64-x86-64
    \\ld.zld: supported emulations: elf_x86_64
;

const cmd = "ld.zld";

emit: Zld.Emit,
output_mode: Zld.OutputMode,
positionals: []const Zld.LinkObject,
libs: std.StringArrayHashMap(Zld.SystemLib),
lib_dirs: []const []const u8,
rpath_list: []const []const u8,
strip: bool = false,
entry: ?[]const u8 = null,
gc_sections: bool = false,
print_gc_sections: bool = false,
allow_multiple_definition: bool = false,
/// -z flags
/// Overrides default stack size.
stack_size: ?u64 = null,
/// Marks the writeable segments as executable.
execstack: bool = false,
/// Marks the writeable segments as executable only if requested by an input object file
/// via sh_flags of the input .note.GNU-stack section.
execstack_if_needed: bool = false,
cpu_arch: ?std.Target.Cpu.Arch = null,
static: bool = false,

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage, .{cmd});

    var positionals = std.ArrayList(Zld.LinkObject).init(arena);
    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    var rpath_list = std.ArrayList([]const u8).init(arena);
    var out_path: ?[]const u8 = null;
    var shared: bool = false;
    var gc_sections: bool = false;
    var print_gc_sections: bool = false;
    var entry: ?[]const u8 = null;
    var allow_multiple_definition: bool = false;
    var stack_size: ?u64 = null;
    var execstack: bool = false;
    var execstack_if_needed: bool = false;
    var cpu_arch: ?std.Target.Cpu.Arch = null;
    var static: bool = false;
    var verbose: bool = false;

    var it = Zld.Options.ArgsIterator{ .args = args };
    while (it.next()) |arg| {
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            ctx.fatal(usage, .{cmd});
        } else if (mem.eql(u8, arg, "--debug-log")) {
            try ctx.log_scopes.append(it.nextOrFatal(ctx));
        } else if (mem.startsWith(u8, arg, "-l")) {
            try libs.put(arg[2..], .{});
        } else if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(arg[2..]);
        } else if (mem.eql(u8, arg, "-o")) {
            out_path = it.nextOrFatal(ctx);
        } else if (mem.eql(u8, arg, "-z")) {
            const z_arg = it.nextOrFatal(ctx);
            if (mem.startsWith(u8, z_arg, "stack-size=")) {
                const value = z_arg["stack-size=".len..];
                stack_size = std.fmt.parseInt(u64, value, 0) catch
                    ctx.fatal("Could not parse value '{s}' into integer", .{value});
            } else if (mem.eql(u8, z_arg, "execstack")) {
                execstack = true;
            } else if (mem.eql(u8, z_arg, "noexecstack")) {
                execstack = false;
            } else if (mem.eql(u8, z_arg, "execstack-if-needed")) {
                execstack_if_needed = true;
            } else {
                ctx.fatal("TODO unhandled argument '-z {s}'", .{z_arg});
            }
        } else if (mem.startsWith(u8, arg, "-z")) {
            ctx.fatal("TODO unhandled argument '-z {s}'", .{arg["-z".len..]});
        } else if (mem.eql(u8, arg, "--gc-sections")) {
            gc_sections = true;
        } else if (mem.eql(u8, arg, "--no-gc-sections")) {
            gc_sections = false;
        } else if (mem.eql(u8, arg, "--print-gc-sections")) {
            print_gc_sections = true;
        } else if (mem.eql(u8, arg, "--as-needed")) {
            ctx.fatal("TODO unhandled argument '--as-needed'", .{});
        } else if (mem.eql(u8, arg, "--allow-shlib-undefined")) {
            ctx.fatal("TODO unhandled argument '--allow-shlib-undefined'", .{});
        } else if (mem.startsWith(u8, arg, "-O")) {
            ctx.fatal("TODO unhandled argument '-O{s}'", .{arg["-O".len..]});
        } else if (mem.eql(u8, arg, "--shared")) {
            shared = true;
        } else if (mem.startsWith(u8, arg, "--rpath=")) {
            try rpath_list.append(arg["--rpath=".len..]);
        } else if (mem.eql(u8, arg, "-rpath")) {
            try rpath_list.append(it.nextOrFatal(ctx));
        } else if (mem.eql(u8, arg, "-R")) {
            try rpath_list.append(it.nextOrFatal(ctx));
        } else if (mem.startsWith(u8, arg, "--entry=")) {
            entry = arg["--entry=".len..];
        } else if (mem.eql(u8, arg, "-e")) {
            entry = it.nextOrFatal(ctx);
        } else if (mem.eql(u8, arg, "-m")) {
            const target = it.nextOrFatal(ctx);
            if (mem.eql(u8, target, "elf_x86_64")) {
                cpu_arch = .x86_64;
            } else {
                ctx.fatal("unknown target emulation '{s}'", .{target});
            }
        } else if (mem.eql(u8, arg, "--allow-multiple-definition")) {
            allow_multiple_definition = true;
        } else if (mem.eql(u8, arg, "--static") or mem.eql(u8, arg, "-static")) {
            static = true;
        } else if (mem.startsWith(u8, arg, "--B") or mem.startsWith(u8, arg, "-B")) {
            const b_arg = it.nextOrFatal(ctx);
            if (mem.eql(u8, b_arg, "static")) {
                static = true;
            } else {
                ctx.fatal("unknown argument '--B{s}'", .{b_arg});
            }
        } else if (mem.eql(u8, arg, "--start-group") or mem.eql(u8, arg, "--end-group")) {
            // Currently ignored
        } else if (mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else {
            try positionals.append(.{
                .path = arg,
                .must_link = true,
            });
        }
    }

    if (verbose) {
        std.debug.print("{s} ", .{cmd});
        for (args[0 .. args.len - 1]) |arg| {
            std.debug.print("{s} ", .{arg});
        }
        std.debug.print("{s}\n", .{args[args.len - 1]});
    }

    if (positionals.items.len == 0) ctx.fatal("Expected at least one input .o file", .{});

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
        .print_gc_sections = print_gc_sections,
        .entry = entry,
        .allow_multiple_definition = allow_multiple_definition,
        .gc_sections = gc_sections,
        .execstack = execstack,
        .execstack_if_needed = execstack_if_needed,
        .cpu_arch = cpu_arch,
        .static = static,
    };
}

const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");
const Options = @This();
const Zld = @import("../Zld.zig");
