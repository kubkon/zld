const std = @import("std");
const builtin = @import("builtin");
const Wasm = @import("Wasm.zig");
const mem = std.mem;

const io = std.io;

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 10 }){};
const gpa = if (builtin.mode == .Debug or !builtin.link_libc)
    gpa_allocator.allocator()
else
    std.heap.c_allocator;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@import("build_flags").enable_logging) {
        std.log.defaultLog(level, scope, format, args);
    }
}

const usage =
    \\Usage: zwld [options] [files...] -o [path]
    \\
    \\Options:
    \\-h, --help                         Print this help and exit
    \\-o [path]                          Output path of the binary
    \\--entry <entry>                    Name of entry point symbol
    \\--global-base=<value>              Value from where the global data will start
    \\--import-memory                    Import memory from the host environment
    \\--import-table                     Import function table from the host environment
    \\--initial-memory=<value>           Initial size of the linear memory
    \\--max-memory=<value>               Maximum size of the linear memory
    \\--merge-data-segments[=false]      Enable merging data segments (default=true)
    \\--no-entry                         Do not output any entry point
    \\--stack-first                      Place stack at start of linear memory instead of after data
    \\--stack-size=<value>               Specifies the stack size in bytes
    \\--features=<value>                 Comma-delimited list of used features, inferred by object files if unset
;

pub fn main() !void {
    defer if (builtin.mode == .Debug) {
        _ = gpa_allocator.deinit();
    };

    // we use arena for the arguments and its parsing
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const process_args = try std.process.argsAlloc(arena);
    defer std.process.argsFree(arena, process_args);

    const args = process_args[1..]; // exclude 'zwld' binary
    if (args.len == 0) {
        printHelpAndExit();
    }

    var positionals = std.ArrayList([]const u8).init(arena);
    var entry_name: ?[]const u8 = null;
    var global_base: ?u32 = 1024;
    var import_memory: bool = false;
    var import_table: bool = false;
    var initial_memory: ?u32 = null;
    var max_memory: ?u32 = null;
    var merge_data_segments = true;
    var no_entry = false;
    var output_path: ?[]const u8 = null;
    var stack_first = false;
    var stack_size: ?u32 = null;
    var features: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            printHelpAndExit();
        }
        if (mem.eql(u8, arg, "--entry")) {
            if (i + 1 >= args.len) printErrorAndExit("Missing entry name argument", .{});
            entry_name = args[i + 1];
            i += 1;
            continue;
        }
        if (mem.startsWith(u8, arg, "--global-base")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for global base", .{});
            global_base = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch printErrorAndExit(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
            continue;
        }
        if (mem.eql(u8, arg, "--import-memory")) {
            import_memory = true;
            continue;
        }
        if (mem.eql(u8, arg, "--import-table")) {
            import_table = true;
            continue;
        }
        if (mem.startsWith(u8, arg, "--initial-memory")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for initial memory", .{});
            initial_memory = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch printErrorAndExit(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
            continue;
        }
        if (mem.startsWith(u8, arg, "--max-memory")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for max memory", .{});
            max_memory = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch printErrorAndExit(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
            continue;
        }
        if (mem.startsWith(u8, arg, "--merge-data-segments")) {
            merge_data_segments = true;
            if (mem.indexOfScalar(u8, arg, '=')) |index| {
                if (mem.eql(u8, arg[index + 1 ..], "false")) {
                    merge_data_segments = false;
                }
            }
            continue;
        }
        if (mem.eql(u8, arg, "--no-entry")) {
            no_entry = true;
            continue;
        }
        if (mem.eql(u8, arg, "--stack-first")) {
            stack_first = true;
            continue;
        }
        if (mem.startsWith(u8, arg, "--stack-size")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for stack size", .{});
            stack_size = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch printErrorAndExit(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
            continue;
        }
        if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) printErrorAndExit("Missing output file argument", .{});
            output_path = args[i + 1];
            i += 1;
            continue;
        }
        if (mem.startsWith(u8, arg, "--features")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse printErrorAndExit("Missing '=' symbol and value for features list", .{});
            features = arg[index + 1 ..];
            i += 1;
            continue;
        }
        if (mem.startsWith(u8, arg, "--")) {
            printErrorAndExit("Unknown argument '{s}'", .{arg});
        }
        try positionals.append(arg);
    }

    if (positionals.items.len == 0) {
        printErrorAndExit("Expected one or more object files, none were given", .{});
    }

    if (output_path == null) {
        printErrorAndExit("Missing output path", .{});
    }

    var wasm_bin = try Wasm.openPath(output_path.?, .{
        .entry_name = entry_name,
        .global_base = global_base,
        .import_memory = import_memory,
        .import_table = import_table,
        .initial_memory = initial_memory,
        .max_memory = max_memory,
        .merge_data_segments = merge_data_segments,
        .no_entry = no_entry,
        .stack_first = stack_first,
        .stack_size = stack_size,
        .features = features orelse &.{},
    });
    defer wasm_bin.deinit(gpa);

    try wasm_bin.parseInputFiles(gpa, positionals.items);
    try wasm_bin.flush(gpa);
}

fn printHelpAndExit() noreturn {
    io.getStdOut().writer().print("{s}\n", .{usage}) catch {};
    std.process.exit(0);
}

fn printErrorAndExit(comptime fmt: []const u8, args: anytype) noreturn {
    const writer = io.getStdErr().writer();
    writer.print(fmt, args) catch {};
    writer.writeByte('\n') catch {};
    std.process.exit(1);
}
