path: []const u8,
index: File.Index,

alive: bool = false,

pub fn deinit(self: *Dll, allocator: Allocator) void {
    allocator.free(self.path);
}

pub fn addExport(self: *Dll, coff_file: *Coff, args: struct {
    name: [:0]const u8,
    strings: []const u8,
    type: coff.ImportType,
    name_type: coff.ImportNameType,
    hint: u16,
}) !void {
    _ = self;
    _ = coff_file;
    log.debug("TODO: add symbol '{s}' of type {s}, name_type {s} and hint {x}", .{
        args.name,
        @tagName(args.type),
        @tagName(args.name_type),
        args.hint,
    });
}

pub fn format(
    self: *Dll,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format Dll directly");
}

const coff = std.coff;
const log = std.log.scoped(.coff);
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const Dll = @This();
const File = @import("file.zig").File;
