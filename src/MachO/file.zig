pub const File = union(enum) {
    internal: *InternalObject,
    object: *Object,
    dylib: *Dylib,

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
            .internal => try writer.writeAll(""),
            .object => |x| try writer.print("{}", .{x.fmtPath()}),
            .dylib => |x| try writer.writeAll(x.path),
        }
    }

    pub fn resolveSymbols(file: File, macho_file: *MachO) void {
        switch (file) {
            inline else => |x| x.resolveSymbols(macho_file),
        }
    }

    pub fn resetGlobals(file: File, macho_file: *MachO) void {
        switch (file) {
            inline else => |x| x.resetGlobals(macho_file),
        }
    }

    pub fn isAlive(file: File) bool {
        return switch (file) {
            inline else => |x| x.alive,
        };
    }

    /// Encodes symbol rank so that the following ordering applies:
    /// * strong defined
    /// * weak defined
    /// * strong in lib (dso/archive)
    /// * weak in lib (dso/archive)
    /// * tentative
    /// * tentative in lib (archive)
    /// * unclaimed
    pub fn getSymbolRank(file: File, sym: macho.nlist_64, in_archive: bool) u32 {
        const base: u3 = blk: {
            if (sym.tentative()) break :blk if (in_archive) 6 else 5;
            if (file == .dylib or in_archive) break :blk if (sym.pext() or sym.weakDef()) 4 else 3;
            break :blk if (sym.pext() or sym.weakDef()) 2 else 1;
        };
        return (@as(u32, base) << 24) + file.getIndex();
    }

    pub fn setAlive(file: File) void {
        switch (file) {
            inline else => |x| x.alive = true,
        }
    }

    pub fn markLive(file: File, macho_file: *MachO) void {
        switch (file) {
            .internal => {},
            inline else => |x| x.markLive(macho_file),
        }
    }

    pub fn getSymbols(file: File) []const Symbol.Index {
        return switch (file) {
            inline else => |x| x.symbols.items,
        };
    }

    pub fn calcSymtabSize(file: File, macho_file: *MachO) !void {
        return switch (file) {
            inline else => |x| x.calcSymtabSize(macho_file),
        };
    }

    pub fn writeSymtab(file: File, macho_file: *MachO) void {
        return switch (file) {
            inline else => |x| x.writeSymtab(macho_file),
        };
    }

    pub const Index = u32;

    pub const Entry = union(enum) {
        null: void,
        internal: InternalObject,
        object: Object,
        dylib: Dylib,
    };
};

const macho = std.macho;
const std = @import("std");

const Allocator = std.mem.Allocator;
const InternalObject = @import("InternalObject.zig");
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Dylib = @import("Dylib.zig");
const Symbol = @import("Symbol.zig");
