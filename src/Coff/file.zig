pub const File = union(enum) {
    object: *Object,
    dll: *Dll,

    pub fn getIndex(file: File) Index {
        return switch (file) {
            inline else => |x| x.index,
        };
    }

    pub fn fmtPath(file: File) std.fmt.Formatter(formatPath) {
        return .{ .data = file };
    }

    fn formatPath(
        file: File,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        switch (file) {
            .object => |x| try writer.print("{}", .{x.fmtPath()}),
            .dll => |x| try writer.writeAll(x.path),
        }
    }

    pub const Index = u32;

    pub const Entry = union(enum) {
        null: void,
        object: Object,
        dll: Dll,
    };

    pub const Handle = std.fs.File;
    pub const HandleIndex = Index;
};

const std = @import("std");

const Allocator = std.mem.Allocator;
const Coff = @import("../Coff.zig");
const Dll = @import("Dll.zig");
const Object = @import("Object.zig");
