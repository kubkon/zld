emit: Zld.Emit,
cpu_arch: ?std.Target.Cpu.Arch = null,
positionals: []const Coff.LinkObject,
lib_paths: []const []const u8,
@"align": ?u32 = null,
file_align: ?u32 = null,

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage, .{cmd});

    var positionals = std.ArrayList(Coff.LinkObject).init(arena);
    var lib_paths = std.StringArrayHashMap(void).init(arena);
    var opts: Options = .{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = "a.exe",
        },
        .positionals = undefined,
        .lib_paths = undefined,
    };
    var verbose = false;

    var it = Zld.Options.ArgsIterator{ .args = args };
    var p = ArgsParser(@TypeOf(it)){ .it = &it };
    while (p.hasMore()) {
        if (p.flag("help")) {
            ctx.fatal(usage ++ "\n", .{cmd});
        } else if (p.arg("debug-log")) |scope| {
            try ctx.log_scopes.append(scope);
        } else if (p.arg("defaultlib")) |name| {
            try positionals.append(.{ .name = name, .tag = .default_lib });
        } else if (p.arg("out")) |path| {
            opts.emit.sub_path = path;
        } else if (p.flag("v")) {
            verbose = true;
        } else if (p.flag("nologo")) {
            // Ignore...
        } else if (p.arg("machine")) |target| {
            if (mem.eql(u8, target, "x64")) {
                opts.cpu_arch = .x86_64;
            } else if (mem.eql(u8, target, "arm64")) {
                opts.cpu_arch = .aarch64;
            } else {
                ctx.fatal("unsupported machine value: {s}\n", .{target});
            }
        } else if (p.arg("libpath")) |path| {
            try lib_paths.put(path, {});
        } else if (p.arg("align")) |value| {
            opts.@"align" = std.fmt.parseInt(u32, value, 0) catch
                ctx.fatal("Could not parse /align:{s} into integer\n", .{value});
        } else if (p.arg("filealign")) |value| {
            opts.file_align = std.fmt.parseInt(u32, value, 0) catch
                ctx.fatal("Could not parse /filealign:{s} into integer\n", .{value});
        } else {
            try positionals.append(.{ .name = p.next_arg, .tag = .explicit });
        }
    }

    if (verbose) {
        ctx.print("{s} ", .{cmd});
        for (args[0 .. args.len - 1]) |arg| {
            ctx.print("{s} ", .{arg});
        }
        ctx.print("{s}\n", .{args[args.len - 1]});
    }
    if (positionals.items.len == 0) ctx.fatal("Expected at least one positional argument\n", .{});
    if (opts.@"align") |alignment| {
        if (alignment % 2 != 0) ctx.fatal("/align:{x} is not a power of two\n", .{alignment});
    }
    if (opts.file_align) |alignment| {
        if (alignment % 2 != 0) ctx.fatal("/filealign:{x} is not a power of two\n", .{alignment});
    }

    opts.positionals = positionals.items;
    opts.lib_paths = lib_paths.keys();

    return opts;
}

pub fn ArgsParser(comptime Iterator: type) type {
    return struct {
        next_arg: []const u8 = undefined,
        it: *Iterator,

        pub fn hasMore(p: *Self) bool {
            var next_arg = p.it.next() orelse return false;
            while (true) {
                if (next_arg.len == 0 or (next_arg.len == 1 and next_arg[0] == 0)) {
                    next_arg = p.it.next() orelse return false;
                }
                break;
            }
            p.next_arg = next_arg;
            return true;
        }

        pub fn flag(p: *Self, comptime pat: []const u8) bool {
            return p.flagPrefix(pat, "-") or p.flagPrefix(pat, "/");
        }

        fn flagPrefix(p: *Self, comptime pat: []const u8, comptime prefix: []const u8) bool {
            if (mem.startsWith(u8, p.next_arg, prefix)) {
                const actual_arg = p.next_arg[prefix.len..];
                if (mem.eql(u8, actual_arg, pat) or mem.eql(u8, actual_arg, &upperPattern(pat))) {
                    return true;
                }
            }
            return false;
        }

        pub fn arg(p: *Self, comptime pat: []const u8) ?[]const u8 {
            return p.argPrefix(pat, "-") orelse p.argPrefix(pat, "/");
        }

        fn argPrefix(p: *Self, comptime pat: []const u8, comptime prefix: []const u8) ?[]const u8 {
            if (mem.startsWith(u8, p.next_arg, prefix)) {
                const actual_arg = p.next_arg[prefix.len..];
                if (mem.startsWith(u8, actual_arg, pat) or
                    mem.startsWith(u8, actual_arg, &upperPattern(pat)))
                {
                    if (mem.indexOf(u8, actual_arg, ":")) |index| {
                        if (index == pat.len) {
                            const value = actual_arg[index + 1 ..];
                            return mem.trim(u8, value, "\"");
                        }
                    }
                }
            }
            return null;
        }

        fn upperPattern(comptime pat: []const u8) [pat.len]u8 {
            comptime var buffer: [pat.len]u8 = undefined;
            inline for (&buffer, pat) |*out, c| {
                out.* = comptime std.ascii.toUpper(c);
            }
            return buffer;
        }

        const Self = @This();
    };
}

const usage =
    \\Usage: {s} [files...]
    \\
    \\General Options:
    \\-align:number                 Alignment value in bytes
    \\-debug-log:scope              Turn on debugging logs for 'scope' (requires zld compiled with -Dlog)
    \\-defaultlib:name              Link a default library
    \\-filealign:size               Section alignment size in bytes, must be power of two
    \\-help                         Print this help and exit
    \\-libpath:path                 Add additional library search path
    \\-nologo                       No comment...
    \\-out:path                     Specify output path fo the final artifact
    \\-v                            Print full linker invocation to stderr
;

const cmd = "link-zld.exe";

const builtin = @import("builtin");
const io = std.io;
const mem = std.mem;
const process = std.process;
const std = @import("std");

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Coff = @import("../Coff.zig");
const Options = @This();
const Zld = @import("../Zld.zig");
