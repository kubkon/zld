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

pub const Options = union {
    elf: Elf.Options,
    macho: MachO.Options,
    coff: Coff.Options,
};

pub fn parseAndFlush(allocator: Allocator, tag: Tag, args: []const []const u8) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const opts: Options = switch (tag) {
        .elf => .{ .elf = try Elf.Options.parseArgs(arena, args) },
        .macho => .{ .macho = try MachO.Options.parseArgs(arena, args) },
        .coff => .{ .coff = try Coff.Options.parseArgs(arena, args) },
    };
    const zld = try openPath(allocator, tag, opts);
    defer {
        zld.closeFiles();
        zld.deinit();
    }
    try zld.flush();
}

pub fn openPath(allocator: Allocator, tag: Tag, options: Options) !*Zld {
    return switch (tag) {
        .macho => &(try MachO.openPath(allocator, options.macho)).base,
        .elf => &(try Elf.openPath(allocator, options.elf)).base,
        .coff => &(try Coff.openPath(allocator, options.coff)).base,
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
}

pub fn closeFiles(base: *const Zld) void {
    switch (base.tag) {
        .elf => @fieldParentPtr(Elf, "base", base).closeFiles(),
        .macho => @fieldParentPtr(MachO, "base", base).closeFiles(),
        .coff => @fieldParentPtr(Coff, "base", base).closeFiles(),
    }
    base.file.close();
}
