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
current_version: ?Version = null,
compatibility_version: ?Version = null,
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

const bin_name = "ld64.zld";

pub fn parse(arena: Allocator, args: []const []const u8, ctx: anytype) !Options {
    if (args.len == 0) ctx.fatal(usage, .{bin_name});

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
    var current_version: ?Version = null;
    var compatibility_version: ?Version = null;
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
            ctx.fatal(usage, .{bin_name});
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
            compatibility_version = Version.parse(raw) orelse
                ctx.fatal("Unable to parse version from '{s}'", .{raw});
        } else if (mem.eql(u8, arg, "-current_version")) {
            const raw = it.nextOrFatal(ctx);
            current_version = Version.parse(raw) orelse
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
                ctx.fatal("Expected minimum platform version after '{s}' '{s}'", .{ arg, platform_s });
            const sdk_v = it.next() orelse
                ctx.fatal("Expected SDK version after '{s}' '{s}' '{s}'", .{ arg, platform_s, min_v });

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

            tmp_platform.min_version = Version.parse(min_v) orelse
                ctx.fatal("Unable to parse version from '{s}'", .{min_v});
            tmp_platform.sdk_version = Version.parse(sdk_v) orelse
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

pub const Platform = struct {
    platform: macho.PLATFORM,
    min_version: Version,
    sdk_version: Version,

    /// Using Apple's ld64 as our blueprint, `min_version` as well as `sdk_version` are set to
    /// the extracted minimum platform version.
    pub fn fromLoadCommand(lc: macho.LoadCommandIterator.LoadCommand) Platform {
        switch (lc.cmd()) {
            .BUILD_VERSION => {
                const cmd = lc.cast(macho.build_version_command).?;
                return .{
                    .platform = cmd.platform,
                    .min_version = .{ .value = cmd.minos },
                    .sdk_version = .{ .value = cmd.minos },
                };
            },
            .VERSION_MIN_MACOSX,
            .VERSION_MIN_IPHONEOS,
            .VERSION_MIN_TVOS,
            .VERSION_MIN_WATCHOS,
            => {
                const cmd = lc.cast(macho.version_min_command).?;
                return .{
                    .platform = switch (lc.cmd()) {
                        .VERSION_MIN_MACOSX => .MACOS,
                        .VERSION_MIN_IPHONEOS => .IOS,
                        .VERSION_MIN_TVOS => .TVOS,
                        .VERSION_MIN_WATCHOS => .WATCHOS,
                        else => unreachable,
                    },
                    .min_version = .{ .value = cmd.version },
                    .sdk_version = .{ .value = cmd.version },
                };
            },
            else => unreachable,
        }
    }

    pub fn isBuildVersionCompatible(plat: Platform) bool {
        inline for (supported_platforms) |sup_plat| {
            if (sup_plat[0] == plat.platform) {
                return sup_plat[1] <= plat.min_version.value;
            }
        }
        return false;
    }
};

pub const Version = struct {
    value: u32,

    pub fn major(v: Version) u16 {
        return @as(u16, @truncate(v.value >> 16));
    }

    pub fn minor(v: Version) u8 {
        return @as(u8, @truncate(v.value >> 8));
    }

    pub fn patch(v: Version) u8 {
        return @as(u8, @truncate(v.value));
    }

    pub fn parse(raw: []const u8) ?Version {
        var parsed: [3]u16 = [_]u16{0} ** 3;
        var count: usize = 0;
        var it = std.mem.splitAny(u8, raw, ".");
        while (it.next()) |comp| {
            if (count >= 3) return null;
            parsed[count] = std.fmt.parseInt(u16, comp, 10) catch return null;
            count += 1;
        }
        if (count == 0) return null;
        const maj = parsed[0];
        const min = std.math.cast(u8, parsed[1]) orelse return null;
        const pat = std.math.cast(u8, parsed[2]) orelse return null;
        return Version.new(maj, min, pat);
    }

    pub fn new(maj: u16, min: u8, pat: u8) Version {
        return .{ .value = (@as(u32, @intCast(maj)) << 16) | (@as(u32, @intCast(min)) << 8) | pat };
    }
};

const SupportedPlatforms = struct {
    macho.PLATFORM, // Platform identifier
    u32, // Min platform version for which to emit LC_BUILD_VERSION
    u32, // Min supported platform version
};

// Source: https://github.com/apple-oss-distributions/ld64/blob/59a99ab60399c5e6c49e6945a9e1049c42b71135/src/ld/PlatformSupport.cpp#L52
const supported_platforms = [_]SupportedPlatforms{
    .{ .MACOS, 0xA0E00, 0xA0800 },
    .{ .IOS, 0xC0000, 0x70000 },
    .{ .TVOS, 0xC0000, 0x70000 },
    .{ .WATCHOS, 0x50000, 0x20000 },
    .{ .IOSSIMULATOR, 0xD0000, 0x80000 },
    .{ .TVOSSIMULATOR, 0xD0000, 0x80000 },
    .{ .WATCHOSSIMULATOR, 0x60000, 0x20000 },
};

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

fn testParseVersionSuccess(exp: u32, raw: []const u8) !void {
    const maybe_ver = Version.parse(raw);
    try expect(maybe_ver != null);
    const ver = maybe_ver.?.value;
    try expectEqual(exp, ver);
}

test "parseVersionString" {
    try testParseVersionSuccess(0xD0400, "13.4");
    try testParseVersionSuccess(0xD0401, "13.4.1");
    try testParseVersionSuccess(0xB0F00, "11.15");

    try expect(Version.parse("") == null);
    try expect(Version.parse("11.xx") == null);
    try expect(Version.parse("11.11.11.11") == null);
}
