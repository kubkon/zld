const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const mem = std.mem;
const tracy = @import("tracy.zig");

const Allocator = mem.Allocator;
const ThreadPool = std.Thread.Pool;
const Zld = @import("Zld.zig");

var tracy_alloc = tracy.tracyAllocator(std.heap.c_allocator);

const gpa = if (tracy.enable_allocation)
    tracy_alloc.allocator()
else
    std.heap.c_allocator;

const usage =
    \\zld is a generic linker driver.
    \\Call
    \\  ELF: ld.zld, ld
    \\  MachO: ld64.zld, ld64
    \\  COFF: link-dl
    \\  Wasm: wasm-zld
;

var log_scopes: std.ArrayList([]const u8) = std.ArrayList([]const u8).init(gpa);

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    // Hide debug messages unless:
    // * logging enabled with `-Dlog`.
    // * the --debug-log arg for the scope has been provided
    if (@intFromEnum(level) > @intFromEnum(std.options.log_level) or
        @intFromEnum(level) > @intFromEnum(std.log.Level.info))
    {
        if (!build_options.enable_logging) return;

        const scope_name = @tagName(scope);
        for (log_scopes.items) |log_scope| {
            if (mem.eql(u8, log_scope, scope_name)) break;
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

pub const std_options: std.Options = .{ .logFn = logFn };

fn print(comptime format: []const u8, args: anytype) void {
    const msg = std.fmt.allocPrint(gpa, format, args) catch return;
    std.io.getStdErr().writeAll(msg) catch {};
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    print(format, args);
    std.process.exit(1);
}

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const cmd = std.fs.path.basename(all_args[0]);
    const tag: Zld.Tag = blk: {
        if (mem.eql(u8, cmd, "ld")) break :blk switch (builtin.target.ofmt) {
            .elf => .elf,
            .macho => .macho,
            .coff => .coff,
            .wasm => .wasm,
            else => |other| fatal("unsupported file format '{s}'", .{@tagName(other)}),
        } else if (mem.eql(u8, cmd, "ld.zld")) {
            break :blk .elf;
        } else if (mem.eql(u8, cmd, "ld64.zld")) {
            break :blk .macho;
        } else if (mem.eql(u8, cmd, "link-zld")) {
            break :blk .coff;
        } else if (mem.eql(u8, cmd, "wasm-zld")) {
            break :blk .wasm;
        } else {
            std.io.getStdOut().writeAll(usage) catch {};
            std.process.exit(0);
        }
    };

    const opts = try Zld.Options.parse(arena, tag, all_args[1..], .{
        .print = print,
        .fatal = fatal,
        .log_scopes = &log_scopes,
    });

    var thread_pool: ThreadPool = undefined;
    try thread_pool.init(.{ .allocator = gpa });
    defer thread_pool.deinit();

    const zld = try Zld.openPath(gpa, tag, opts, &thread_pool);
    zld.flush() catch |err| switch (err) {
        error.InferCpuFailed,
        error.ParseFailed,
        error.MultipleSymbolDefinition,
        error.UndefinedSymbols,
        error.RelocError,
        error.ResolveFailed,
        error.Unimplemented,
        => {
            zld.reportWarnings();
            zld.reportErrors();
            std.process.exit(1);
        },
        else => |e| {
            print("unexpected linker error: {s}\n", .{@errorName(e)});
            return e;
        },
    };
    zld.reportWarnings();
}
