pub const File = union(enum) {
    internal: *InternalObject,
    object: *Object,
    shared: *SharedObject,

    pub fn getIndex(file: File) Index {
        return switch (file) {
            inline else => |x| x.index,
        };
    }

    pub fn getPath(file: File) []const u8 {
        return switch (file) {
            .internal => unreachable,
            .object => |x| x.name, // TODO wrap in archive path if extracted
            .shared => |x| x.name,
        };
    }

    pub fn resolveSymbols(file: File, elf_file: *Elf) void {
        switch (file) {
            inline else => |x| x.resolveSymbols(elf_file),
        }
    }

    pub fn resetGlobals(file: File, elf_file: *Elf) void {
        switch (file) {
            inline else => |x| x.resetGlobals(elf_file),
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
    /// * unclaimed
    pub fn getSymbolRank(file: File, sym: elf.Elf64_Sym, in_archive: bool) u32 {
        const base: u4 = blk: {
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

    pub const Index = u32;

    pub const Entry = union(enum) {
        null: void,
        internal: InternalObject,
        object: Object,
        shared: SharedObject,
    };
};

const std = @import("std");
const elf = std.elf;

const Elf = @import("../Elf.zig");
const InternalObject = @import("InternalObject.zig");
const Object = @import("Object.zig");
const SharedObject = @import("SharedObject.zig");
