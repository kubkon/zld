pub const File = union(enum) {
    object: *Object,
    dll: *Dll,

    pub fn getIndex(file: File) Index {
        return switch (file) {
            inline else => |x| x.index,
        };
    }

    pub fn resolveSymbols(file: File, coff_file: *Coff) void {
        switch (file) {
            inline else => |x| x.resolveSymbols(coff_file),
        }
    }

    pub fn resetGlobals(file: File, coff_file: *Coff) void {
        for (file.getSymbols()) |global_index| {
            const global = coff_file.getSymbol(global_index);
            if (!global.flags.global) continue;
            const name = global.name;
            global.* = .{};
            global.name = name;
            global.flags.global = true;
        }
    }

    pub fn getSymbolRank(file: File, args: struct {
        archive: bool = false,
        weak: bool = false,
        tentative: bool = false,
    }) u32 {
        const base: u32 = blk: {
            if (args.tentative) break :blk if (args.archive) 6 else 5;
            if (file == .dll or args.archive) break :blk if (args.weak) 4 else 3;
            break :blk if (args.weak) 2 else 1;
        };
        return (base << 24) + file.getIndex();
    }

    pub fn getAtoms(file: File) []const Atom.Index {
        return switch (file) {
            .dll => unreachable,
            inline else => |x| x.atoms.items,
        };
    }

    pub fn getSymbols(file: File) []const Symbol.Index {
        return switch (file) {
            inline else => |x| x.symbols.items,
        };
    }

    pub fn isAlive(file: File) bool {
        return switch (file) {
            inline else => |x| x.alive,
        };
    }

    pub fn setAlive(file: File) void {
        switch (file) {
            inline else => |x| x.alive = true,
        }
    }

    pub fn markLive(file: File, coff_file: *Coff) void {
        switch (file) {
            .dll => unreachable,
            .object => |x| x.markLive(coff_file),
        }
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

const assert = std.debug.assert;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const Coff = @import("../Coff.zig");
const Dll = @import("Dll.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
