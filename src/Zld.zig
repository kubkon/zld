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
    bitcode,
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
    compatibility_version: ?std.builtin.Version = null,
    current_version: ?std.builtin.Version = null,
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
    switch (base.tag) {
        .elf => try @fieldParentPtr(Elf, "base", base).flush(),
        .macho => try @fieldParentPtr(MachO, "base", base).flush(),
        .coff => try @fieldParentPtr(Coff, "base", base).flush(),
    }
    base.file.close();
}
