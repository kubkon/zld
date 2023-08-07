const Options = @This();

const std = @import("std");
const builtin = @import("builtin");
const io = std.io;
const macho = std.macho;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const MachO = @import("../MachO.zig");
const Zld = @import("../Zld.zig");

pub const SearchStrategy = enum {
    paths_first,
    dylibs_first,
};

const usage =
    \\Usage: {s} [files...]
    \\
    \\General Options:
    \\
    \\-arch [name]
    \\    Specifies which architecture the output file should be
    \\
    \\-current_version [value]
    \\    Specifies the current version number of the library
    \\
    \\-compatibility_version [value]
    \\    Specifies the compatibility version number of the library
    \\
    \\-dead_strip
    \\    Remove functions and data that are unreachable by the entry point or exported symbols
    \\
    \\-dead_strip_dylibs
    \\    Remove dylibs that were unreachable by the entry point or exported symbols
    \\
    \\-dylib
    \\    Create dynamic library
    \\
    \\-dynamic
    \\    Perform dynamic linking
    \\
    \\-e [name]
    \\    Specifies the entry point of main executable
    \\
    \\-u [name]
    \\    Specifies symbol which has to be resolved at link time for the link to succeed.
    \\
    \\-force_load [path]
    \\    Loads all members of the specified static archive library
    \\
    \\-framework [name]
    \\    Link against framework
    \\
    \\-F[path]
    \\    Add search path for frameworks
    \\
    \\-headerpad [value]
    \\    Set minimum space for future expansion of the load commands in hexadecimal notation
    \\
    \\-headerpad_max_install_names
    \\    Set enough space as if all paths were MAXPATHLEN
    \\
    \\-install_name
    \\    Add dylib's install name
    \\
    \\-l[name]
    \\    Link against library
    \\    
    \\-L[path]
    \\    Add search path for libraries
    \\
    \\-needed_framework [name]
    \\    Link against framework (even if unused)
    \\
    \\-needed-l[name]
    \\    Alias of -needed_library
    \\
    \\-needed_library [name]
    \\    Link against library (even if unused)
    \\
    \\-rpath [path]
    \\    Specify runtime path
    \\
    \\-pagezero_size [value]
    \\    Size of the __PAGEZERO segment in hexademical notation
    \\
    \\-platform_version [platform] [min_version] [sdk_version]
    \\    Sets the platform, oldest supported version of that platform and the SDK it was built against
    \\
    \\-S
    \\    Do not put debug information (STABS or DWARF) in the output file
    \\
    \\-no_deduplicate
    \\    Do not run deduplication pass in linker
    \\
    \\-search_paths_first
    \\    Search each dir in library search paths for `libx.dylib` then `libx.a`
    \\
    \\-search_dylibs_first
    \\    Search `libx.dylib` in each dir in library search paths, then `libx.a`
    \\
    \\-stack_size [value]
    \\    Size of the default stack in hexadecimal notation
    \\
    \\-syslibroot [path]
    \\    Specify the syslibroot
    \\
    \\-undefined [value]
    \\    Specifies how undefined symbols are to be treated: error (default), warning, suppress, or dynamic_lookup.
    \\
    \\-weak_framework [name]
    \\    Link against framework and mark it and all referenced symbols as weak
    \\
    \\-weak-l[name]
    \\    Alias of -weak_library
    \\
    \\-weak_library [name]
    \\    Link against library and mark it and all referenced symbols as weak
    \\
    \\--entitlements
    \\    (Linker extension) add path to entitlements file for embedding in code signature
    \\
    \\-o [path]
    \\    Specify output path for the final artifact
    \\
    \\-h, --help
    \\    Print this help and exit
    \\
    \\--debug-log [scope]
    \\    Turn on debugging logs for [scope] (requires zld compiled with -Dlog)
;

emit: Zld.Emit,
output_mode: Zld.OutputMode,
cpu_arch: ?std.Target.Cpu.Arch,
platform: ?Platform,
objects: []const MachO.LinkObject,
lib_dirs: []const []const u8,
framework_dirs: []const []const u8,
rpath_list: []const []const u8,
dynamic: bool = false,
syslibroot: ?[]const u8 = null,
stack_size: ?u64 = null,
strip: bool = false,
entry: ?[]const u8 = null,
force_undefined_symbols: std.StringArrayHashMap(void),
current_version: ?std.SemanticVersion = null,
compatibility_version: ?std.SemanticVersion = null,
install_name: ?[]const u8 = null,
entitlements: ?[]const u8 = null,
pagezero_size: ?u64 = null,
search_strategy: ?SearchStrategy = null,
headerpad: ?u32 = null,
headerpad_max_install_names: bool = false,
dead_strip: bool = false,
dead_strip_dylibs: bool = false,
allow_undef: bool = false,
no_deduplicate: bool = false,

const cmd = "ld64.zld";

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage, .{cmd});

    var objects = std.ArrayList(MachO.LinkObject).init(arena);
    var libs = std.StringHashMap(usize).init(arena);
    var frameworks = std.StringHashMap(usize).init(arena);

    var lib_dirs = std.ArrayList([]const u8).init(arena);
    var framework_dirs = std.ArrayList([]const u8).init(arena);
    var rpath_list = std.ArrayList([]const u8).init(arena);
    var out_path: ?[]const u8 = null;
    var syslibroot: ?[]const u8 = null;
    var stack_size: ?u64 = null;
    var dynamic: bool = false;
    var dylib: bool = false;
    var install_name: ?[]const u8 = null;
    var current_version: ?std.SemanticVersion = null;
    var compatibility_version: ?std.SemanticVersion = null;
    var headerpad: ?u32 = null;
    var headerpad_max_install_names: bool = false;
    var pagezero_size: ?u64 = null;
    var dead_strip: bool = false;
    var dead_strip_dylibs: bool = false;
    var entry: ?[]const u8 = null;
    var force_undefined_symbols = std.StringArrayHashMap(void).init(arena);
    var strip: bool = false;
    var allow_undef: bool = false;
    var search_strategy: ?SearchStrategy = null;
    var no_deduplicate: bool = false;
    var cpu_arch: ?std.Target.Cpu.Arch = null;
    var platform: ?Platform = null;

    var it = Zld.Options.ArgsIterator{ .args = args };
    while (it.next()) |arg| {
        if (mem.eql(u8, arg, "--help") or mem.eql(u8, arg, "-h")) {
            ctx.fatal(usage, .{cmd});
        } else if (mem.eql(u8, arg, "--debug-log")) {
            try ctx.log_scopes.append(it.nextOrFatal(ctx));
        } else if (mem.eql(u8, arg, "-syslibroot")) {
            syslibroot = it.nextOrFatal(ctx);
        } else if (mem.eql(u8, arg, "-search_paths_first")) {
            search_strategy = .paths_first;
        } else if (mem.eql(u8, arg, "-search_dylibs_first")) {
            search_strategy = .dylibs_first;
        } else if (mem.eql(u8, arg, "-framework")) {
            try addFramework(it.nextOrFatal(ctx), &objects, &frameworks);
        } else if (mem.startsWith(u8, arg, "-F")) {
            try framework_dirs.append(arg[2..]);
        } else if (mem.startsWith(u8, arg, "-needed-l")) {
            try addNeededLib(arg["-needed-l".len..], &objects, &libs);
        } else if (mem.eql(u8, arg, "-needed_library")) {
            try addNeededLib(it.nextOrFatal(ctx), &objects, &libs);
        } else if (mem.eql(u8, arg, "-needed_framework")) {
            try addNeededFramework(it.nextOrFatal(ctx), &objects, &frameworks);
        } else if (mem.startsWith(u8, arg, "-weak-l")) {
            try addWeakLib(arg["-weak-l".len..], &objects, &libs);
        } else if (mem.eql(u8, arg, "-weak_library")) {
            try addWeakLib(it.nextOrFatal(ctx), &objects, &libs);
        } else if (mem.eql(u8, arg, "-weak_framework")) {
            try addWeakFramework(it.nextOrFatal(ctx), &objects, &frameworks);
        } else if (mem.eql(u8, arg, "-o")) {
            out_path = it.nextOrFatal(ctx);
        } else if (mem.eql(u8, arg, "-stack_size")) {
            const stack_s = it.nextOrFatal(ctx);
            stack_size = std.fmt.parseUnsigned(u64, eatIntPrefix(stack_s, 16), 16) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{stack_s});
        } else if (mem.eql(u8, arg, "-dylib")) {
            dylib = true;
        } else if (mem.eql(u8, arg, "-dynamic")) {
            dynamic = true;
        } else if (mem.eql(u8, arg, "-static")) {
            dynamic = false;
        } else if (mem.eql(u8, arg, "-rpath")) {
            try rpath_list.append(it.nextOrFatal(ctx));
        } else if (mem.eql(u8, arg, "-compatibility_version")) {
            const raw = it.nextOrFatal(ctx);
            compatibility_version = parseSdkVersion(raw) orelse
                ctx.fatal("Unable to parse version from '{s}'", .{raw});
        } else if (mem.eql(u8, arg, "-current_version")) {
            const raw = it.nextOrFatal(ctx);
            current_version = parseSdkVersion(raw) orelse
                ctx.fatal("Unable to parse version from '{s}'", .{raw});
        } else if (mem.eql(u8, arg, "-install_name")) {
            install_name = it.nextOrFatal(ctx);
        } else if (mem.eql(u8, arg, "-headerpad")) {
            const headerpad_s = it.nextOrFatal(ctx);
            headerpad = std.fmt.parseUnsigned(u32, eatIntPrefix(headerpad_s, 16), 16) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{headerpad_s});
        } else if (mem.eql(u8, arg, "-headerpad_max_install_names")) {
            headerpad_max_install_names = true;
        } else if (mem.eql(u8, arg, "-pagezero_size")) {
            const pagezero_s = it.nextOrFatal(ctx);
            pagezero_size = std.fmt.parseUnsigned(u64, eatIntPrefix(pagezero_s, 16), 16) catch
                ctx.fatal("Could not parse value '{s}' into integer", .{pagezero_s});
        } else if (mem.eql(u8, arg, "-dead_strip")) {
            dead_strip = true;
        } else if (mem.eql(u8, arg, "-dead_strip_dylibs")) {
            dead_strip_dylibs = true;
        } else if (mem.eql(u8, arg, "-e")) {
            entry = it.nextOrFatal(ctx);
        } else if (mem.eql(u8, arg, "-u")) {
            try force_undefined_symbols.put(it.nextOrFatal(ctx), {});
        } else if (mem.eql(u8, arg, "-S")) {
            strip = true;
        } else if (mem.eql(u8, arg, "-force_load")) {
            try objects.append(.{
                .path = it.nextOrFatal(ctx),
                .tag = .obj,
                .must_link = true,
            });
        } else if (mem.eql(u8, arg, "-arch")) {
            const arch_s = it.nextOrFatal(ctx);
            if (mem.eql(u8, arch_s, "arm64")) {
                cpu_arch = .aarch64;
            } else if (mem.eql(u8, arch_s, "x86_64")) {
                cpu_arch = .x86_64;
            } else {
                ctx.fatal("Could not parse CPU architecture from '{s}'", .{arch_s});
            }
        } else if (mem.eql(u8, arg, "-platform_version")) {
            const platform_s = it.next() orelse
                ctx.fatal("Expected platform name after '{s}'", .{arg});
            const min_v = it.next() orelse
                ctx.fatal("Expected minimum platform version after '{s}' '{s}'", .{ arg, platform });
            const sdk_v = it.next() orelse
                ctx.fatal("Expected SDK version after '{s}' '{s}' '{s}'", .{ arg, platform, min_v });

            var tmp_platform = Platform{
                .platform = undefined,
                .min_version = undefined,
                .sdk_version = undefined,
            };

            // First, try parsing platform as a numeric value.
            if (std.fmt.parseUnsigned(u32, platform_s, 10)) |ord| {
                tmp_platform.platform = @as(macho.PLATFORM, @enumFromInt(ord));
            } else |_| {
                if (mem.eql(u8, platform_s, "macos")) {
                    tmp_platform.platform = .MACOS;
                } else if (mem.eql(u8, platform_s, "ios")) {
                    tmp_platform.platform = .IOS;
                } else if (mem.eql(u8, platform_s, "tvos")) {
                    tmp_platform.platform = .TVOS;
                } else if (mem.eql(u8, platform_s, "watchos")) {
                    tmp_platform.platform = .WATCHOS;
                } else if (mem.eql(u8, platform_s, "ios-simulator")) {
                    tmp_platform.platform = .IOSSIMULATOR;
                } else if (mem.eql(u8, platform_s, "tvos-simulator")) {
                    tmp_platform.platform = .TVOSSIMULATOR;
                } else if (mem.eql(u8, platform_s, "watchos-simulator")) {
                    tmp_platform.platform = .WATCHOSSIMULATOR;
                } else {
                    ctx.fatal("Unsupported Apple OS: {s}", .{platform_s});
                }
            }

            tmp_platform.min_version = parseSdkVersion(min_v) orelse
                ctx.fatal("Unable to parse version from '{s}'", .{min_v});
            tmp_platform.sdk_version = parseSdkVersion(sdk_v) orelse
                ctx.fatal("Unable to parse version from '{s}'", .{sdk_v});
            platform = tmp_platform;
        } else if (mem.eql(u8, arg, "-undefined")) {
            const treatment = it.nextOrFatal(ctx);
            if (mem.eql(u8, treatment, "error")) {
                allow_undef = false;
            } else if (mem.eql(u8, treatment, "warning") or mem.eql(u8, treatment, "suppress")) {
                ctx.fatal("TODO unimplemented -undefined {s} option", .{treatment});
            } else if (mem.eql(u8, treatment, "dynamic_lookup")) {
                allow_undef = true;
            } else {
                ctx.fatal("Unknown option -undefined {s}", .{treatment});
            }
        } else if (mem.eql(u8, arg, "-lto_library")) {
            const lto_lib = it.nextOrFatal(ctx);
            std.log.debug("TODO unimplemented -lto_library {s} option", .{lto_lib});
        } else if (mem.eql(u8, arg, "-demangle")) {
            std.log.debug("TODO unimplemented -demangle option", .{});
        } else if (mem.startsWith(u8, arg, "-l")) {
            try addLib(arg[2..], &objects, &libs);
        } else if (mem.startsWith(u8, arg, "-L")) {
            try lib_dirs.append(arg[2..]);
        } else if (mem.eql(u8, arg, "-no_deduplicate")) {
            no_deduplicate = true;
        } else {
            try objects.append(.{
                .path = arg,
                .tag = .obj,
            });
        }
    }

    // Add some defaults
    try lib_dirs.append("/usr/lib");
    try framework_dirs.append("/System/Library/Frameworks");

    return Options{
        .emit = .{
            .directory = std.fs.cwd(),
            .sub_path = out_path orelse "a.out",
        },
        .dynamic = dynamic,
        .cpu_arch = cpu_arch,
        .platform = platform,
        .output_mode = if (dylib) .lib else .exe,
        .syslibroot = syslibroot,
        .objects = objects.items,
        .lib_dirs = lib_dirs.items,
        .framework_dirs = framework_dirs.items,
        .rpath_list = rpath_list.items,
        .stack_size = stack_size,
        .install_name = install_name,
        .current_version = current_version,
        .compatibility_version = compatibility_version,
        .dead_strip = dead_strip,
        .dead_strip_dylibs = dead_strip_dylibs,
        .headerpad = headerpad,
        .headerpad_max_install_names = headerpad_max_install_names,
        .pagezero_size = pagezero_size,
        .entry = entry,
        .force_undefined_symbols = force_undefined_symbols,
        .strip = strip,
        .allow_undef = allow_undef,
        .search_strategy = search_strategy,
        .no_deduplicate = no_deduplicate,
    };
}

fn eatIntPrefix(arg: []const u8, radix: u8) []const u8 {
    if (arg.len > 2 and arg[0] == '0') {
        switch (std.ascii.toLower(arg[1])) {
            'b' => if (radix == 2) return arg[2..],
            'o' => if (radix == 8) return arg[2..],
            'x' => if (radix == 16) return arg[2..],
            else => {},
        }
    }
    return arg;
}

const Objects = std.ArrayList(MachO.LinkObject);
const LibLookup = std.StringHashMap(usize);

fn newObjectWithLookup(name: []const u8, objects: *Objects, lookup: *LibLookup) !*MachO.LinkObject {
    const gop = try lookup.getOrPut(name);
    if (!gop.found_existing) {
        gop.value_ptr.* = objects.items.len;
        _ = try objects.addOne();
    }
    return &objects.items[gop.value_ptr.*];
}

fn addLib(name: []const u8, objects: *Objects, libs: *LibLookup) !void {
    const obj = try newObjectWithLookup(name, objects, libs);
    obj.* = .{
        .path = name,
        .tag = .lib,
    };
}

fn addNeededLib(name: []const u8, objects: *Objects, libs: *LibLookup) !void {
    const obj = try newObjectWithLookup(name, objects, libs);
    obj.* = .{
        .path = name,
        .tag = .lib,
        .needed = true,
    };
}

fn addWeakLib(name: []const u8, objects: *Objects, libs: *LibLookup) !void {
    const obj = try newObjectWithLookup(name, objects, libs);
    obj.* = .{
        .path = name,
        .tag = .lib,
        .weak = true,
    };
}

fn addFramework(name: []const u8, objects: *Objects, frameworks: *LibLookup) !void {
    const obj = try newObjectWithLookup(name, objects, frameworks);
    obj.* = .{
        .path = name,
        .tag = .framework,
    };
}

fn addNeededFramework(name: []const u8, objects: *Objects, frameworks: *LibLookup) !void {
    const obj = try newObjectWithLookup(name, objects, frameworks);
    obj.* = .{
        .path = name,
        .tag = .framework,
        .needed = true,
    };
}

fn addWeakFramework(name: []const u8, objects: *Objects, frameworks: *LibLookup) !void {
    const obj = try newObjectWithLookup(name, objects, frameworks);
    obj.* = .{
        .path = name,
        .tag = .framework,
        .weak = true,
    };
}

// Versions reported by Apple aren't exactly semantically valid as they usually omit
// the patch component. Hence, we do a simple check for the number of components and
// add the missing patch value if needed.
fn parseSdkVersion(raw: []const u8) ?std.SemanticVersion {
    var buffer: [128]u8 = undefined;
    if (raw.len > buffer.len) return null;
    @memcpy(buffer[0..raw.len], raw);
    const dots_count = mem.count(u8, raw, ".");
    if (dots_count < 1) return null;
    const len = if (dots_count < 2) blk: {
        const patch_suffix = ".0";
        buffer[raw.len..][0..patch_suffix.len].* = patch_suffix.*;
        break :blk raw.len + patch_suffix.len;
    } else raw.len;
    return std.SemanticVersion.parse(buffer[0..len]) catch null;
}

pub const Platform = struct {
    platform: macho.PLATFORM,
    min_version: std.SemanticVersion,
    sdk_version: std.SemanticVersion,
};

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

fn testParseSdkVersionSuccess(exp: std.SemanticVersion, raw: []const u8) !void {
    const maybe_ver = parseSdkVersion(raw);
    try expect(maybe_ver != null);
    const ver = maybe_ver.?;
    try expectEqual(exp.major, ver.major);
    try expectEqual(exp.minor, ver.minor);
    try expectEqual(exp.patch, ver.patch);
}

test "parseSdkVersion" {
    try testParseSdkVersionSuccess(.{ .major = 13, .minor = 4, .patch = 0 }, "13.4");
    try testParseSdkVersionSuccess(.{ .major = 13, .minor = 4, .patch = 1 }, "13.4.1");
    try testParseSdkVersionSuccess(.{ .major = 11, .minor = 15, .patch = 0 }, "11.15");

    try expect(parseSdkVersion("11") == null);
}
