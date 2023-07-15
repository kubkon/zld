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
    \\--import-symbols                   Allows references to undefined symbols
    \\--import-memory                    Import memory from the host environment
    \\--export-memory                    Import memory from the host environment
    \\--import-table                     Import function table from the host environment
    \\--export-table                     Export function table to the host environment
    \\--initial-memory=<value>           Initial size of the linear memory
    \\--max-memory=<value>               Maximum size of the linear memory
    \\--merge-data-segments[=false]      Enable merging data segments (default=true)
    \\--no-entry                         Do not output any entry point
    \\--stack-first                      Place stack at start of linear memory instead of after data
    \\--stack-size=<value>               Specifies the stack size in bytes
    \\--features=<value>                 Comma-delimited list of used features, inferred by object files if unset
    \\--strip                            Strip all debug information and symbol names
    \\--export-dynamic                   Dynamically export non-hidden symbols
    \\--export=<value>                   Force exporting a global symbol (fails when symbol does not exist)
    \\--shared-memory                    Use shared linear memory (requires atomics and bulk memory)
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
/// Allow undefined symbols to be imported into the linker.
/// By default the linker will emit an error instead when one or multiple
/// undefined references are found.
import_symbols: bool = false,
/// Tells the linker we will import memory from the host environment
import_memory: bool = false,
/// Tells the linker we will export memory from the host environment
export_memory: bool = false,
/// Tells the linker we will import the function table from the host environment
import_table: bool = false,
/// Tells the linker we will export the function table to the host environment
export_table: bool = false,
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
/// Exports a symbol when it's defined, global and not hidden.
export_dynamic: bool = false,
/// Forcefully exports a symbol by its name, fails when the symbol
/// is unresolved.
exports: []const []const u8,
/// Enables shared linear memory. Requires to have the features
/// atomics and bulk-memory enabled.
shared_memory: bool = false,

const cmd = "wasm-zld";

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage, .{cmd});

    var positionals = std.ArrayList([]const u8).init(arena);
    var entry_name: ?[]const u8 = null;
    var global_base: ?u32 = null;
    var import_symbols: bool = false;
    var import_memory: bool = false;
    var export_memory: ?bool = null;
    var import_table: bool = false;
    var export_table: bool = false;
    var initial_memory: ?u32 = null;
    var max_memory: ?u32 = null;
    var merge_data_segments = true;
    var no_entry = false;
    var output_path: ?[]const u8 = null;
    var stack_first = false;
    var stack_size: ?u32 = null;
    var features: ?[]const u8 = null;
    var strip: ?bool = null;
    var export_dynamic: bool = false;
    var exports = std.ArrayList([]const u8).init(arena);
    var shared_memory: bool = false;

    var it = Zld.Options.ArgsIterator{ .args = args };
    while (it.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            ctx.fatal(usage, .{cmd});
        } else if (mem.eql(u8, arg, "--debug-log")) {
            try ctx.log_scopes.append(it.nextOrFatal(ctx));
        } else if (mem.eql(u8, arg, "--entry")) {
            entry_name = it.nextOrFatal(ctx);
        } else if (mem.startsWith(u8, arg, "--global-base=")) {
            const value = arg["--global-base=".len..];
            global_base = std.fmt.parseInt(u32, value, 10) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{value});
        } else if (mem.eql(u8, arg, "--import-symbols")) {
            import_symbols = true;
        } else if (mem.eql(u8, arg, "--import-memory")) {
            import_memory = true;
        } else if (mem.eql(u8, arg, "--export-memory")) {
            export_memory = true;
        } else if (mem.eql(u8, arg, "--import-table")) {
            import_table = true;
        } else if (mem.eql(u8, arg, "--export-table")) {
            export_table = true;
        } else if (mem.startsWith(u8, arg, "--initial-memory=")) {
            const value = arg["--initial-memory=".len..];
            initial_memory = std.fmt.parseInt(u32, value, 10) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{value});
        } else if (mem.startsWith(u8, arg, "--max-memory=")) {
            const value = arg["--max-memory=".len..];
            max_memory = std.fmt.parseInt(u32, value, 10) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{value});
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
            const value = arg["--stack-size=".len..];
            stack_size = std.fmt.parseInt(u32, value, 10) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{value});
        } else if (mem.eql(u8, arg, "-o")) {
            output_path = it.nextOrFatal(ctx);
        } else if (mem.startsWith(u8, arg, "--features=")) {
            features = arg["--features=".len..];
        } else if (mem.eql(u8, arg, "--strip")) {
            strip = true;
        } else if (mem.eql(u8, arg, "--export-dynamic")) {
            export_dynamic = true;
        } else if (mem.startsWith(u8, arg, "--export=")) {
            try exports.append(arg["--export=".len..]);
        } else if (mem.eql(u8, arg, "--shared-memory")) {
            shared_memory = true;
        } else {
            try positionals.append(arg);
        }
    }

    if (positionals.items.len == 0) ctx.fatal("Expected one or more object files, none were given", .{});
    if (output_path == null) ctx.fatal("Missing output path", .{});

    return Options{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = output_path.?,
        },
        .positionals = positionals.items,
        .entry_name = entry_name,
        .global_base = global_base,
        .import_symbols = import_symbols,
        .import_memory = import_memory,
        .export_memory = export_memory orelse !import_memory,
        .import_table = import_table,
        .export_table = export_table,
        .initial_memory = initial_memory,
        .max_memory = max_memory,
        .merge_data_segments = merge_data_segments,
        .no_entry = no_entry,
        .stack_first = stack_first,
        .stack_size = stack_size,
        .features = features orelse &.{},
        .strip = strip orelse false,
        .export_dynamic = export_dynamic,
        .exports = exports.items,
        .shared_memory = shared_memory,
    };
}
