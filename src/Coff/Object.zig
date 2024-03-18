path: []const u8,
file_handle: File.HandleIndex,
index: File.Index,

header: ?coff.CoffHeader = null,

pub fn deinit(self: *Object, allocator: Allocator) void {
    allocator.free(self.path);
}

pub fn parse(self: *Object, coff_file: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    log.debug("parsing input object file {}", .{self.fmtPath()});

    const offset: usize = 0;
    const file = coff_file.getFileHandle(self.file_handle);

    var header_buffer: [@sizeOf(coff.CoffHeader)]u8 = undefined;
    {
        const amt = try file.preadAll(&header_buffer, offset);
        if (amt != @sizeOf(coff.CoffHeader)) return error.InputOutput;
    }
    self.header = @as(*align(1) const coff.CoffHeader, @ptrCast(&header_buffer)).*;

    // TODO actually parse an object file
}

pub fn fmtPath(self: Object) std.fmt.Formatter(formatPath) {
    return .{ .data = self };
}

fn formatPath(
    object: Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll(object.path);
}

const assert = std.debug.assert;
const coff = std.coff;
const mem = std.mem;
const fs = std.fs;
const log = std.log.scoped(.coff);
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const Object = @This();
