const Elf = @This();

const std = @import("std");
const mem = std.mem;

const Allocator = mem.Allocator;
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.elf;

base: Zld,

pub fn openPath(allocator: *Allocator, options: Zld.Options) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (std.Target.current.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer self.base.destroy();

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: *Allocator, options: Zld.Options) !*Elf {
    const self = try gpa.create(Elf);

    self.* = .{
        .base = .{
            .tag = .elf,
            .options = options,
            .allocator = gpa,
            .file = undefined,
        },
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    _ = self;
}

pub fn closeFiles(self: *Elf) void {
    _ = self;
}

pub fn flush(self: *Elf) !void {
    _ = self;
    return error.TODOFlushInElfLinker;
}
