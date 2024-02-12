pub const File = union(enum) {
    internal: *InternalObject,
    object: *Object,
    shared: *SharedObject,

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
            .internal => unreachable,
            .object => |x| try writer.print("{}", .{x.fmtPath()}),
            .shared => |x| try writer.writeAll(x.path),
        }
    }

    pub fn resolveSymbols(file: File, elf_file: *Elf) void {
        switch (file) {
            inline else => |x| x.resolveSymbols(elf_file),
        }
    }

    pub fn resetGlobals(file: File, elf_file: *Elf) void {
        for (file.getGlobals()) |global_index| {
            const global = elf_file.getSymbol(global_index);
            const name = global.name;
            global.* = .{};
            global.name = name;
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
    /// * common
    /// * common in lib (archive)
    /// * unclaimed
    pub fn getSymbolRank(file: File, sym: elf.Elf64_Sym, in_archive: bool) u32 {
        const base: u3 = blk: {
            if (sym.st_shndx == elf.SHN_COMMON) break :blk if (in_archive) 6 else 5;
            if (file == .shared or in_archive) break :blk switch (sym.st_bind()) {
                elf.STB_GLOBAL => 3,
                else => 4,
            };
            break :blk switch (sym.st_bind()) {
                elf.STB_GLOBAL => 1,
                else => 2,
            };
        };
        return (@as(u32, base) << 24) + file.getIndex();
    }

    pub fn setAlive(file: File) void {
        switch (file) {
            inline else => |x| x.alive = true,
        }
    }

    pub fn markLive(file: File, elf_file: *Elf) void {
        switch (file) {
            .internal => {},
            inline else => |x| x.markLive(elf_file),
        }
    }

    pub fn getLocals(file: File) []const Symbol.Index {
        return switch (file) {
            .object => |x| x.getLocals(),
            inline else => &[0]Symbol.Index{},
        };
    }

    pub fn getGlobals(file: File) []const Symbol.Index {
        return switch (file) {
            inline else => |x| x.getGlobals(),
        };
    }

    pub fn calcSymtabSize(file: File, elf_file: *Elf) !void {
        return switch (file) {
            inline else => |x| x.calcSymtabSize(elf_file),
        };
    }

    pub fn writeSymtab(file: File, elf_file: *Elf) void {
        return switch (file) {
            inline else => |x| x.writeSymtab(elf_file),
        };
    }

    pub const Index = u32;

    pub const Entry = union(enum) {
        null: void,
        internal: InternalObject,
        object: Object,
        shared: SharedObject,
    };

    pub const Handle = std.fs.File;
    pub const HandleIndex = Index;
};

const std = @import("std");
const elf = std.elf;

const Allocator = std.mem.Allocator;
const Elf = @import("../Elf.zig");
const InternalObject = @import("InternalObject.zig");
const Object = @import("Object.zig");
const SharedObject = @import("SharedObject.zig");
const Symbol = @import("Symbol.zig");
