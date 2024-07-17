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

    pub fn resolveSymbols(file: File, macho_file: *MachO) !void {
        switch (file) {
            inline else => |x| try x.resolveSymbols(macho_file),
        }
    }

    pub fn checkDuplicates(file: File, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();

        const gpa = macho_file.base.allocator;

        for (file.getSymbols(), file.getNlists(), 0..) |sym, nlist, i| {
            if (sym.visibility != .global) continue;
            if (sym.flags.weak) continue;
            if (nlist.undf()) continue;
            const ref = file.getSymbolRef(@intCast(i), macho_file);
            const ref_file = ref.getFile(macho_file) orelse continue;
            if (ref_file.getIndex() == file.getIndex()) continue;

            macho_file.dupes_mutex.lock();
            defer macho_file.dupes_mutex.unlock();

            const gop = try macho_file.dupes.getOrPut(gpa, file.getGlobals()[i]);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{};
            }
            try gop.value_ptr.append(gpa, file.getIndex());
        }
    }

    pub fn scanRelocs(file: File, macho_file: *MachO) !void {
        switch (file) {
            .dylib => unreachable,
            .object => |x| try x.scanRelocs(macho_file),
            .internal => |x| x.scanRelocs(macho_file),
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
        if (file != .dylib and !args.archive) {
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

    pub fn getAtomExtra(file: File, index: u32) Atom.Extra {
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

    pub fn getSymbols(file: File) []Symbol {
        return switch (file) {
            inline else => |x| x.symbols.items,
        };
    }

    pub fn getSymbolRef(file: File, sym_index: Symbol.Index, macho_file: *MachO) MachO.Ref {
        return switch (file) {
            inline else => |x| x.getSymbolRef(sym_index, macho_file),
        };
    }

    pub fn getNlists(file: File) []macho.nlist_64 {
        return switch (file) {
            .dylib => unreachable,
            .internal => |x| x.symtab.items,
            .object => |x| x.symtab.items(.nlist),
        };
    }

    pub fn getGlobals(file: File) []MachO.SymbolResolver.Index {
        return switch (file) {
            inline else => |x| x.globals.items,
        };
    }

    pub fn markImportsAndExports(file: File, macho_file: *MachO) void {
        const nsyms = switch (file) {
            .dylib => unreachable,
            inline else => |x| x.symbols.items.len,
        };
        for (0..nsyms) |i| {
            const ref = file.getSymbolRef(@intCast(i), macho_file);
            if (ref.getFile(macho_file) == null) continue;
            const sym = ref.getSymbol(macho_file).?;
            if (sym.visibility != .global) continue;
            if (sym.getFile(macho_file).? == .dylib and !sym.flags.abs) {
                sym.flags.import = true;
                continue;
            }
            if (file.getIndex() == ref.file) {
                sym.flags.@"export" = true;
            }
        }
    }

    pub fn createSymbolIndirection(file: File, macho_file: *MachO) !void {
        const nsyms = switch (file) {
            inline else => |x| x.symbols.items.len,
        };
        for (0..nsyms) |i| {
            const ref = file.getSymbolRef(@intCast(i), macho_file);
            if (ref.getFile(macho_file) == null) continue;
            if (ref.file != file.getIndex()) continue;
            const sym = ref.getSymbol(macho_file).?;
            if (sym.getSectionFlags().got) {
                log.debug("'{s}' needs GOT", .{sym.getName(macho_file)});
                try macho_file.got.addSymbol(ref, macho_file);
            }
            if (sym.getSectionFlags().stubs) {
                log.debug("'{s}' needs STUBS", .{sym.getName(macho_file)});
                try macho_file.stubs.addSymbol(ref, macho_file);
            }
            if (sym.getSectionFlags().tlv_ptr) {
                log.debug("'{s}' needs TLV pointer", .{sym.getName(macho_file)});
                try macho_file.tlv_ptr.addSymbol(ref, macho_file);
            }
            if (sym.getSectionFlags().objc_stubs) {
                log.debug("'{s}' needs OBJC STUBS", .{sym.getName(macho_file)});
                try macho_file.objc_stubs.addSymbol(ref, macho_file);
            }
        }
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

    pub fn dedupLiterals(file: File, lp: MachO.LiteralPool, macho_file: *MachO) void {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.dedupLiterals(lp, macho_file),
        };
    }

    pub fn writeAtoms(file: File, macho_file: *MachO) !void {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.writeAtoms(macho_file),
        };
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
const log = std.log.scoped(.link);
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
