const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Zld = @import("Zld.zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = gpa_allocator.allocator();

const usage =
    \\zld is a generic linker driver.
    \\Call ld.zld (ELF), ld64.zld (MachO), link-zld (COFF).
;

fn printUsage() noreturn {
    io.getStdErr().writeAll(usage) catch {};
    process.exit(0);
}

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

pub fn main() !void {
    const all_args = try process.argsAlloc(gpa);
    defer process.argsFree(gpa, all_args);

    const cmd = std.fs.path.basename(all_args[0]);
    if (mem.eql(u8, cmd, "ld.zld")) {
        return Zld.parseAndFlush(gpa, .elf, all_args[1..]);
    } else if (mem.eql(u8, cmd, "ld64.zld")) {
        return Zld.parseAndFlush(gpa, .macho, all_args[1..]);
    } else if (mem.eql(u8, cmd, "link-zld")) {
        return Zld.parseAndFlush(gpa, .coff, all_args[1..]);
    } else {
        printUsage();
    }
}
