emit: Zld.Emit,
cpu_arch: ?std.Target.Cpu.Arch = null,
positionals: []const Coff.LinkObject,

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage, .{cmd});

    var positionals = std.ArrayList(Coff.LinkObject).init(arena);
    var opts: Options = .{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = "a.exe",
        },
        .positionals = undefined,
    };
    var verbose = false;

    var it = Zld.Options.ArgsIterator{ .args = args };
    var p = ArgParser(@TypeOf(ctx)){ .it = &it, .ctx = ctx };
    while (p.hasMore()) {
        if (p.flag("help")) {
            ctx.fatal(usage ++ "\n", .{cmd});
        } else if (p.arg("debug-log")) |scope| {
            try ctx.log_scopes.append(scope);
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
        } else {
            try positionals.append(.{ .path = p.next_arg, .tag = .obj });
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

    opts.positionals = positionals.items;

    return opts;
}

fn ArgParser(comptime Ctx: type) type {
    return struct {
        next_arg: []const u8 = undefined,
        it: *Zld.Options.ArgsIterator,
        ctx: Ctx,

        pub fn hasMore(p: *Self) bool {
            p.next_arg = p.it.next() orelse return false;
            return true;
        }

        pub fn flag(p: *Self, comptime pat: []const u8) bool {
            return p.flagPrefix(pat, "-") or p.flagPrefix(pat, "/");
        }

        fn flagPrefix(p: *Self, comptime pat: []const u8, comptime prefix: []const u8) bool {
            if (mem.startsWith(u8, p.next_arg, prefix)) {
                const actual_arg = p.next_arg[prefix.len..];
                if (mem.eql(u8, actual_arg, pat)) {
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
                if (mem.startsWith(u8, actual_arg, pat)) {
                    if (mem.indexOf(u8, actual_arg, ":")) |index| {
                        if (index == pat.len) {
                            const value = actual_arg[index + 1 ..];
                            return value;
                        }
                    }
                }
            }
            return null;
        }

        const Self = @This();
    };
}

const usage =
    \\Usage: {s} [files...]
    \\
    \\General Options:
    \\-debug-log:scope              Turn on debugging logs for 'scope' (requires zld compiled with -Dlog)
    \\-help                         Print this help and exit
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
