const Zld = @This();

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Elf = @import("Elf.zig");
const MachO = @import("MachO.zig");
const Coff = @import("Coff.zig");

tag: Tag,
allocator: Allocator,
file: fs.File,
options: Options,

pub const Tag = enum {
    coff,
    elf,
    macho,
};

pub const Emit = struct {
    directory: fs.Dir,
    sub_path: []const u8,
};

pub const OutputMode = enum {
    exe,
    lib,
};

pub const SystemLib = struct {
    needed: bool = false,
    weak: bool = false,
};

pub const LinkObject = struct {
    path: []const u8,
    must_link: bool = false,
};

pub const Options = struct {
    emit: Emit,
    dynamic: bool,
    output_mode: OutputMode,
    target: std.Target,
    syslibroot: ?[]const u8,
    positionals: []const LinkObject,
    libs: std.StringArrayHashMap(SystemLib),
    frameworks: std.StringArrayHashMap(SystemLib),
    lib_dirs: []const []const u8,
    framework_dirs: []const []const u8,
    rpath_list: []const []const u8,
    stack_size_override: ?u64 = null,
    gc_sections: ?bool = null,
    allow_shlib_undefined: ?bool = null,
    strip: bool = false,
    entry: ?[]const u8 = null,
    verbose: bool = false,

    version: ?std.builtin.Version = null,
    compatibility_version: ?std.builtin.Version = null,

    /// (Darwin) Install name for the dylib
    install_name: ?[]const u8 = null,

    /// (Darwin) Path to entitlements file
    entitlements: ?[]const u8 = null,

    /// (Darwin) size of the __PAGEZERO segment
    pagezero_size: ?u64 = null,

    /// (Darwin) search strategy for system libraries
    search_strategy: ?MachO.SearchStrategy = null,

    /// (Darwin) set minimum space for future expansion of the load commands
    headerpad_size: ?u32 = null,

    /// (Darwin) set enough space as if all paths were MATPATHLEN
    headerpad_max_install_names: bool = false,

    /// (Darwin) remove dylibs that are unreachable by the entry point or exported symbols
    dead_strip_dylibs: bool = false,
};

pub fn openPath(allocator: Allocator, options: Options) !*Zld {
    return switch (options.target.os.tag) {
        .linux => &(try Elf.openPath(allocator, options)).base,
        .macos => &(try MachO.openPath(allocator, options)).base,
        .windows => &(try Coff.openPath(allocator, options)).base,
        else => error.Unimplemented,
    };
}

pub fn deinit(base: *Zld) void {
    switch (base.tag) {
        .elf => @fieldParentPtr(Elf, "base", base).deinit(),
        .macho => @fieldParentPtr(MachO, "base", base).deinit(),
        .coff => @fieldParentPtr(Coff, "base", base).deinit(),
    }
}

pub fn flush(base: *Zld) !void {
    const gpa = base.allocator;
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    if (base.options.verbose) {
        var argv = std.ArrayList([]const u8).init(arena);
        try argv.append("zld");

        if (base.options.dynamic) {
            try argv.append("-dynamic");
        } else {
            try argv.append("-static");
        }

        if (base.options.syslibroot) |path| {
            try argv.append("-syslibroot");
            try argv.append(path);
        }
        if (base.options.output_mode == .lib) {
            try argv.append("-shared");
        }
        if (base.options.stack_size_override) |st| {
            switch (base.options.target.getObjectFormat()) {
                .elf => try argv.append(try std.fmt.allocPrint(arena, "-z stack-size={d}", .{st})),
                .macho => {
                    try argv.append("-stack");
                    try argv.append(try std.fmt.allocPrint(arena, "{d}", .{st}));
                },
                else => {},
            }
        }
        try argv.append("-o");
        try argv.append(base.options.emit.sub_path);
        for (base.options.libs.keys()) |lib| {
            try argv.append(try std.fmt.allocPrint(arena, "-l{s}", .{lib}));
        }
        for (base.options.lib_dirs) |dir| {
            try argv.append(try std.fmt.allocPrint(arena, "-L{s}", .{dir}));
        }
        for (base.options.frameworks.keys()) |fw| {
            try argv.append("-framework");
            try argv.append(fw);
        }
        for (base.options.framework_dirs) |dir| {
            try argv.append(try std.fmt.allocPrint(arena, "-F{s}", .{dir}));
        }
        for (base.options.rpath_list) |rpath| {
            try argv.append("-rpath");
            try argv.append(rpath);
        }
        if (base.options.gc_sections) |gc_sections| {
            if (gc_sections) {
                try argv.append("--gc-sections");
            } else {
                try argv.append("--no-gc-sections");
            }
        }
        for (base.options.positionals) |obj| {
            try argv.append(obj.path);
        }
        try argv.append("\n");

        try io.getStdOut().writeAll(try mem.join(arena, " ", argv.items));
    }

    switch (base.tag) {
        .elf => try @fieldParentPtr(Elf, "base", base).flush(),
        .macho => try @fieldParentPtr(MachO, "base", base).flush(),
        .coff => try @fieldParentPtr(Coff, "base", base).flush(),
    }
    base.file.close();
}
