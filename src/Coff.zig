const Coff = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const coff = std.coff;
const fs = std.fs;
const log = std.log.scoped(.coff);
const mem = std.mem;

const Allocator = mem.Allocator;
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.coff;

base: Zld,

pub fn openPath(allocator: *Allocator, options: Zld.Options) !*Coff {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer allocator.destroy(self);

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: *Allocator, options: Zld.Options) !*Coff {
    const self = try gpa.create(Coff);

    self.* = .{
        .base = .{
            .tag = .coff,
            .options = options,
            .allocator = gpa,
            .file = undefined,
        },
    };

    return self;
}

pub fn deinit(self: *Coff) void {
    _ = self;
}

pub fn closeFiles(self: Coff) void {
    _ = self;
}

pub fn flush(self: *Coff) !void {
    _ = self;
    return error.TODOFlushInCoffLinker;
}
