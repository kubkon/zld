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

    pub fn getAtoms(file: File) []const Atom.Index {
        return switch (file) {
            .dylib => unreachable,
            inline else => |x| x.atoms.items,
        };
    }

    pub fn addDyldRelocs(file: File, macho_file: *MachO) !void {
        const tracy = trace(@src());
        defer tracy.end();

        assert(file != .dylib);

        const cpu_arch = macho_file.options.cpu_arch.?;

        for (file.getAtoms()) |atom_index| {
            const atom = macho_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            if (atom.getInputSection(macho_file).isZerofill()) continue;
            const atom_addr = atom.getAddress(macho_file);
            const relocs = atom.getRelocs(macho_file);
            const seg_id = macho_file.sections.items(.segment_id)[atom.out_n_sect];
            const seg = macho_file.segments.items[seg_id];
            for (relocs) |rel| {
                if (rel.type != .unsigned or rel.meta.length != 3) continue;
                const rel_offset = rel.offset - atom.off;
                const addend = rel.addend + rel.getRelocAddend(cpu_arch);
                if (rel.tag == .@"extern") {
                    const sym = rel.getTargetSymbol(macho_file);
                    if (sym.isTlvInit(macho_file)) continue;
                    const entry = bind.Entry{
                        .target = rel.target,
                        .offset = atom_addr + rel_offset - seg.vmaddr,
                        .segment_id = seg_id,
                        .addend = addend,
                    };
                    if (sym.flags.import) {
                        macho_file.bind.entries.appendAssumeCapacity(entry);
                        if (sym.flags.weak) {
                            macho_file.weak_bind.entries.appendAssumeCapacity(entry);
                        }
                        continue;
                    }
                    if (sym.flags.@"export" and sym.flags.weak) {
                        macho_file.weak_bind.entries.appendAssumeCapacity(entry);
                    } else if (sym.flags.interposable) {
                        macho_file.bind.entries.appendAssumeCapacity(entry);
                    }
                }
                macho_file.rebase.entries.appendAssumeCapacity(.{
                    .offset = atom_addr + rel_offset - seg.vmaddr,
                    .segment_id = seg_id,
                });
            }
        }
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
