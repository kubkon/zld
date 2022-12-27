//! Options to pass to our linker which affects
//! the end result and tells the linker how to build the final binary.
const Options = @This();

const std = @import("std");
const Zld = @import("../Zld.zig");
const Wasm = @import("../Wasm.zig");

const mem = std.mem;
const Allocator = mem.Allocator;

const usage =
    \\Usage: {s} [options] [files...] -o [path]
    \\
    \\Options:
    \\-h, --help                         Print this help and exit
    \\--debug-log [scope]                Turn on debugging logs for [scope] (requires zld compiled with -Dlog)
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
    \\--strip                            Strip all debug information and symbol names
;

/// Result path of the binary
emit: Zld.Emit,
/// List of positionals (paths) of objects and archives
/// that may be linked into the final binary
positionals: []const []const u8,
/// When the entry name is different than `_start`
entry_name: ?[]const u8 = null,
/// Points to where the global data will start
global_base: ?u32 = null,
/// Tells the linker we will import memory from the host environment
import_memory: bool = false,
/// Tells the linker we will import the function table from the host environment
import_table: bool = false,
/// Sets the initial memory of the data section
/// Providing a value too low will result in a linking error.
initial_memory: ?u32 = null,
/// Sets the max memory for the data section.
/// Will result in a linking error when it's smaller than `initial_memory`m
/// or when the initial memory calculated by the linker is larger than the given maximum memory.
max_memory: ?u32 = null,
/// Tell the linker to merge data segments
/// i.e. all '.rodata' will be merged into a .rodata segment.
merge_data_segments: bool = true,
/// Tell the linker we do not require a starting entry
no_entry: bool = false,
/// Tell the linker to put the stack first, instead of after the data
stack_first: bool = false,
/// Specifies the size of the stack in bytes
stack_size: ?u32 = null,
/// Comma-delimited list of features to use.
/// When empty, the used features are inferred from the objects instead.
features: []const u8,
/// Strips all debug information and optional sections such as symbol names,
/// and the 'producers' section.
strip: bool = false,

pub fn parseArgs(arena: Allocator, context: Zld.MainCtx) !Options {
    if (context.args.len == 0) {
        context.printSuccess(usage, .{context.cmd});
    }

    const args = context.args;
    var positionals = std.ArrayList([]const u8).init(arena);
    var entry_name: ?[]const u8 = null;
    var global_base: ?u32 = null;
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
    var strip: ?bool = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            context.printSuccess(usage, .{context.cmd});
        } else if (mem.eql(u8, arg, "--debug-log")) {
            if (i + 1 >= args.len) context.printFailure("Missing scope for debug log", .{});
            i += 1;
            try context.log_scopes.append(args[i]);
        } else if (mem.eql(u8, arg, "--entry")) {
            if (i + 1 >= args.len) context.printFailure("Missing entry name argument", .{});
            entry_name = args[i + 1];
            i += 1;
        } else if (mem.startsWith(u8, arg, "--global-base")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse context.printFailure("Missing '=' symbol and value for global base", .{});
            global_base = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch context.printFailure(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
        } else if (mem.eql(u8, arg, "--import-memory")) {
            import_memory = true;
        } else if (mem.eql(u8, arg, "--import-table")) {
            import_table = true;
        } else if (mem.startsWith(u8, arg, "--initial-memory")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse context.printFailure("Missing '=' symbol and value for initial memory", .{});
            initial_memory = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch context.printFailure(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
        } else if (mem.startsWith(u8, arg, "--max-memory")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse context.printFailure("Missing '=' symbol and value for max memory", .{});
            max_memory = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch context.printFailure(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
        } else if (mem.startsWith(u8, arg, "--merge-data-segments")) {
            merge_data_segments = true;
            if (mem.indexOfScalar(u8, arg, '=')) |index| {
                if (mem.eql(u8, arg[index + 1 ..], "false")) {
                    merge_data_segments = false;
                }
            }
        } else if (mem.eql(u8, arg, "--no-entry")) {
            no_entry = true;
        } else if (mem.eql(u8, arg, "--stack-first")) {
            stack_first = true;
        } else if (mem.startsWith(u8, arg, "--stack-size")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse context.printFailure("Missing '=' symbol and value for stack size", .{});
            stack_size = std.fmt.parseInt(u32, arg[index + 1 ..], 10) catch context.printFailure(
                "Could not parse value '{s}' into integer",
                .{arg[index + 1 ..]},
            );
        } else if (mem.eql(u8, arg, "-o")) {
            if (i + 1 >= args.len) context.printFailure("Missing output file argument", .{});
            output_path = args[i + 1];
            i += 1;
        } else if (mem.startsWith(u8, arg, "--features")) {
            const index = mem.indexOfScalar(u8, arg, '=') orelse context.printFailure("Missing '=' symbol and value for features list", .{});
            features = arg[index + 1 ..];
            i += 1;
        } else if (mem.eql(u8, arg, "--strip")) {
            strip = true;
        } else {
            try positionals.append(arg);
        }
    }

    if (positionals.items.len == 0) {
        context.printFailure("Expected one or more object files, none were given", .{});
    }

    if (output_path == null) {
        context.printFailure("Missing output path", .{});
    }

    return Options{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = output_path.?,
        },
        .positionals = positionals.items,
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
        .strip = strip orelse false,
    };
}
