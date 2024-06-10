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
            .internal => unreachable,
            inline else => |x| x.resolveSymbols(macho_file),
        }
    }

    pub fn resetGlobals(file: File, macho_file: *MachO) void {
        switch (file) {
            .internal => unreachable,
            inline else => |x| x.resetGlobals(macho_file),
        }
    }

    pub fn addSymbolExtra(file: File, macho_file: *MachO) !void {
        for (file.getSymbols()) |sym_index| {
            const sym = macho_file.getSymbol(sym_index);
            if (sym.getFile(macho_file)) |fsym| {
                if (file.getIndex() != fsym.getIndex()) continue;
            }
            sym.extra = try macho_file.addSymbolExtra(.{});
        }
    }

    /// Encodes symbol rank so that the following ordering applies:
    /// * strong in object
    /// * weak in object
    /// * tentative in object
    /// * strong in archive/dylib
    /// * weak in archive/dylib
    /// * tentative in archive
    /// * unclaimed
    pub fn getSymbolRank(file: File, args: struct {
        archive: bool = false,
        weak: bool = false,
        tentative: bool = false,
    }) u32 {
        if (file == .object and !args.archive) {
            const base: u32 = blk: {
                if (args.tentative) break :blk 3;
                break :blk if (args.weak) 2 else 1;
            };
            return (base << 16) + file.getIndex();
        }
        const base: u32 = blk: {
            if (args.tentative) break :blk 3;
            break :blk if (args.weak) 2 else 1;
        };
        return base + (file.getIndex() << 24);
    }

    pub fn getSymbols(file: File) []const Symbol.Index {
        return switch (file) {
            inline else => |x| x.symbols.items,
        };
    }

    pub fn getAtom(file: File, atom_index: Atom.Index) ?*Atom {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.getAtom(atom_index),
        };
    }

    pub fn getAtoms(file: File) []const Atom.Index {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.getAtoms(),
        };
    }

    pub fn addAtomExtra(file: File, allocator: Allocator, extra: Atom.Extra) !u32 {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.addAtomExtra(allocator, extra),
        };
    }

    pub fn getAtomExtra(file: File, index: u32) ?Atom.Extra {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.getAtomExtra(index),
        };
    }

    pub fn setAtomExtra(file: File, index: u32, extra: Atom.Extra) void {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.setAtomExtra(index, extra),
        };
    }

    pub fn getSymbol(file: File, sym_index: Symbol.Index) *Symbol {
        return switch (file) {
            inline else => |x| x.getSymbol(sym_index),
        };
    }

    pub fn initOutputSections(file: File, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();
        for (file.getAtoms()) |atom_index| {
            const atom = file.getAtom(atom_index) orelse continue;
            if (!atom.alive.load(.seq_cst)) continue;
            atom.out_n_sect = try Atom.initOutputSection(atom.getInputSection(macho_file), macho_file);
        }
    }

    pub fn calcSymtabSize(file: File, macho_file: *MachO) void {
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

    pub const Handle = std.fs.File;
    pub const HandleIndex = Index;
};

const assert = std.debug.assert;
const bind = @import("dyld_info/bind.zig");
const macho = std.macho;
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const InternalObject = @import("InternalObject.zig");
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Dylib = @import("Dylib.zig");
const Symbol = @import("Symbol.zig");
