const Zld = @This();

const std = @import("std");
const build_options = @import("build_options");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const Elf = @import("Elf.zig");
const MachO = @import("MachO.zig");

tag: Tag,
allocator: *Allocator,
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

pub const Options = struct {
    emit: Emit,
    dynamic: bool,
    output_mode: OutputMode,
    target: std.Target,
    syslibroot: ?[]const u8,
    positionals: []const []const u8,
    libs: []const []const u8,
    frameworks: []const []const u8,
    lib_dirs: []const []const u8,
    framework_dirs: []const []const u8,
    rpath_list: []const []const u8,
    stack_size_override: ?u64 = null,
};

pub fn openPath(allocator: *Allocator, options: Options) !*Zld {
    return switch (options.target.os.tag) {
        .linux => error.TODOElfLinker,
        .macos => &(try MachO.openPath(allocator, options)).base,
        .windows => error.TODOCoffLinker,
        else => error.Unimplemented,
    };
}

pub fn deinit(base: *Zld) void {
    return switch (base.tag) {
        .macho => base.cast(MachO).?.deinit(),
        else => {},
    };
}

pub fn closeFiles(base: *Zld) void {
    return switch (base.tag) {
        .macho => base.cast(MachO).?.closeFiles(),
        else => {},
    };
}

pub fn flush(base: *Zld) !void {
    return switch (base.tag) {
        .elf => error.TODOElfLinker,
        .macho => base.cast(MachO).?.flush(),
        .coff => error.TODOCoffLinker,
    };
}

fn cast(base: *Zld, comptime T: type) ?*T {
    if (base.tag != T.base_tag) {
        return null;
    }
    return @fieldParentPtr(T, "base", base);
}
