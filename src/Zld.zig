const Zld = @This();

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const Elf = @import("Elf.zig");
const MachO = @import("MachO.zig");
const Coff = @import("Coff.zig");

tag: Tag,
allocator: Allocator,
file: fs.File,

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

pub const Options = union(Tag) {
    elf: Elf.Options,
    macho: MachO.Options,
    coff: Coff.Options,
};

pub fn parseOpts(arena: Allocator, target: std.Target, args: []const []const u8) !Options {
    return switch (target.os.tag) {
        .macos,
        .tvos,
        .watchos,
        .ios,
        => .{ .macho = try @import("MachO/opts.zig").parse(arena, target, args) },

        .linux => .{ .elf = try @import("Elf/opts.zig").parse(arena, target, args) },

        .windows => .{ .coff = try @import("Coff/opts.zig").parse(arena, target, args) },

        else => unreachable,
    };
}

pub fn openPath(allocator: Allocator, options: Options) !*Zld {
    return switch (options) {
        .macho => |opts| &(try MachO.openPath(allocator, opts)).base,
        .elf => |opts| &(try Elf.openPath(allocator, opts)).base,
        .coff => |opts| &(try Coff.openPath(allocator, opts)).base,
    };
}

pub fn deinit(base: *Zld) void {
    switch (base.tag) {
        .elf => @fieldParentPtr(Elf, "base", base).deinit(),
        .macho => @fieldParentPtr(MachO, "base", base).deinit(),
        .coff => @fieldParentPtr(Coff, "base", base).deinit(),
    }
    base.allocator.destroy(base);
}

pub fn flush(base: *Zld) !void {
    switch (base.tag) {
        .elf => try @fieldParentPtr(Elf, "base", base).flush(),
        .macho => try @fieldParentPtr(MachO, "base", base).flush(),
        .coff => try @fieldParentPtr(Coff, "base", base).flush(),
    }
    base.closeFiles();
}

fn closeFiles(base: *const Zld) void {
    switch (base.tag) {
        .elf => @fieldParentPtr(Elf, "base", base).closeFiles(),
        .macho => @fieldParentPtr(MachO, "base", base).closeFiles(),
        .coff => @fieldParentPtr(Coff, "base", base).closeFiles(),
    }
    base.file.close();
}
