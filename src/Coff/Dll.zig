path: []const u8,
index: File.Index,

exports: std.ArrayListUnmanaged(Export) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

alive: bool = false,

pub fn deinit(self: *Dll, allocator: Allocator) void {
    allocator.free(self.path);
    self.exports.deinit(allocator);
    self.strtab.deinit(allocator);
}

pub fn addExport(self: *Dll, coff_file: *Coff, args: struct {
    name: [:0]const u8,
    strings: []const u8,
    type: coff.ImportType,
    name_type: coff.ImportNameType,
    hint: u16,
}) !void {
    const gpa = coff_file.base.allocator;
    const actual_name = switch (args.name_type) {
        .ORDINAL, .NAME => args.name,
        .NAME_NOPREFIX => mem.trimLeft(u8, args.name, "?@_"),
        .NAME_UNDECORATE => blk: {
            const trimmed = std.mem.trimLeft(u8, args.name, "?@_");
            const index = std.mem.indexOf(u8, trimmed, "@") orelse trimmed.len;
            break :blk trimmed[0..index];
        },
        .NAME_EXPORTAS => blk: {
            const offset = args.name.len + 1 + self.path.len + 1;
            break :blk mem.sliceTo(@as([*:0]const u8, @ptrCast(args.strings.ptr + offset)), 0);
        },
        else => |other| {
            coff_file.base.fatal("{s}: unhandled IMPORT_OBJECT_NAME_TYPE variant: {}", .{
                self.path,
                other,
            });
            return error.ParseFailed;
        },
    };
    log.debug("{s}: adding export '{s}' of type {s} and hint {x}", .{
        self.path,
        actual_name,
        @tagName(args.type),
        args.hint,
    });
    try self.exports.append(gpa, .{
        .name = try self.addString(gpa, actual_name),
        .hint = args.hint,
        .type = args.type,
    });
}

fn addString(self: *Dll, allocator: Allocator, str: []const u8) error{OutOfMemory}!u32 {
    const off = @as(u32, @intCast(self.strtab.items.len));
    try self.strtab.writer(allocator).print("{s}\x00", .{str});
    return off;
}

pub fn getString(self: Dll, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
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

const Export = packed struct {
    name: u32,
    hint: u16,
    type: coff.ImportType,
};

const assert = std.debug.assert;
const coff = std.coff;
const log = std.log.scoped(.coff);
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const Dll = @This();
const File = @import("file.zig").File;
