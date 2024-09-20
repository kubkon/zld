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

    pub fn resolveSymbols(file: File, elf_file: *Elf) !void {
        return switch (file) {
            inline else => |x| x.resolveSymbols(elf_file),
        };
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

    pub fn createSymbolIndirection(file: File, elf_file: *Elf) !void {
        const symbols = switch (file) {
            inline else => |x| x.symbols.items,
        };
        for (symbols, 0..) |*sym, i| {
            const ref = file.resolveSymbol(@intCast(i), elf_file);
            const ref_sym = elf_file.getSymbol(ref) orelse continue;
            if (ref_sym.getFile(elf_file).?.getIndex() != file.getIndex()) continue;
            if (!sym.isLocal(elf_file) and !sym.flags.has_dynamic) {
                log.debug("'{s}' is non-local", .{sym.getName(elf_file)});
                try elf_file.dynsym.addSymbol(ref, elf_file);
            }
            if (sym.flags.got) {
                log.debug("'{s}' needs GOT", .{sym.getName(elf_file)});
                _ = try elf_file.got.addGotSymbol(ref, elf_file);
            }
            if (sym.flags.plt) {
                if (sym.flags.is_canonical) {
                    log.debug("'{s}' needs CPLT", .{sym.getName(elf_file)});
                    sym.flags.@"export" = true;
                    try elf_file.plt.addSymbol(ref, elf_file);
                } else if (sym.flags.got) {
                    log.debug("'{s}' needs PLTGOT", .{sym.getName(elf_file)});
                    try elf_file.plt_got.addSymbol(ref, elf_file);
                } else {
                    log.debug("'{s}' needs PLT", .{sym.getName(elf_file)});
                    try elf_file.plt.addSymbol(ref, elf_file);
                }
            }
            if (sym.flags.copy_rel and !sym.flags.has_copy_rel) {
                log.debug("'{s}' needs COPYREL", .{sym.getName(elf_file)});
                try elf_file.copy_rel.addSymbol(ref, elf_file);
            }
            if (sym.flags.tlsgd) {
                log.debug("'{s}' needs TLSGD", .{sym.getName(elf_file)});
                try elf_file.got.addTlsGdSymbol(ref, elf_file);
            }
            if (sym.flags.gottp) {
                log.debug("'{s}' needs GOTTP", .{sym.getName(elf_file)});
                try elf_file.got.addGotTpSymbol(ref, elf_file);
            }
            if (sym.flags.tlsdesc) {
                log.debug("'{s}' needs TLSDESC", .{sym.getName(elf_file)});
                try elf_file.got.addTlsDescSymbol(ref, elf_file);
            }
        }
    }

    pub fn getAtom(file: File, ind: Atom.Index) ?*Atom {
        return switch (file) {
            .internal, .shared => unreachable,
            .object => |x| x.getAtom(ind),
        };
    }

    pub fn getComdatGroup(file: File, ind: Elf.ComdatGroup.Index) *Elf.ComdatGroup {
        return switch (file) {
            .internal, .shared => unreachable,
            .object => |x| x.getComdatGroup(ind),
        };
    }

    pub fn resolveSymbol(file: File, ind: Symbol.Index, elf_file: *Elf) Elf.Ref {
        return switch (file) {
            inline else => |x| x.resolveSymbol(ind, elf_file),
        };
    }

    pub fn getSymbol(file: File, ind: Symbol.Index) *Symbol {
        return switch (file) {
            inline else => |x| &x.symbols.items[ind],
        };
    }

    pub fn getString(file: File, off: u32) [:0]const u8 {
        return switch (file) {
            inline else => |x| x.getString(off),
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
const log = std.log.scoped(.elf);

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const InternalObject = @import("InternalObject.zig");
const Object = @import("Object.zig");
const SharedObject = @import("SharedObject.zig");
const Symbol = @import("Symbol.zig");
