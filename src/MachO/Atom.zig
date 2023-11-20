/// Address allocated for this Atom.
value: u64 = 0,

/// Name of this Atom.
name: u32 = 0,

/// Index into linker's input file table.
file: File.Index = 0,

/// Size of this atom
size: u64 = 0,

/// Alignment of this atom as a power of two.
alignment: u32 = 0,

/// Index of the input section.
n_sect: u8 = 0,

/// Index of the output section.
out_n_sect: u8 = 0,

/// Offset within the parent section pointed to by n_sect.
/// off + size <= parent section size.
off: u64 = 0,

/// Relocations of this atom.
relocs: Loc = .{},

/// Data-in-code associated with this atom.
dice: Loc = .{},

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

flags: Flags = .{},

pub fn getName(self: Atom, macho_file: *MachO) [:0]const u8 {
    return macho_file.string_intern.getAssumeExists(self.name);
}

pub fn getFile(self: Atom, macho_file: *MachO) File {
    return macho_file.getFile(self.file).?;
}

pub fn getInputSection(self: Atom, macho_file: *MachO) macho.section_64 {
    return switch (self.getFile(macho_file)) {
        .internal => |x| x.sections.items[self.n_sect],
        .object => |x| x.sections[self.n_sect],
        else => unreachable,
    };
}

pub fn getPriority(self: Atom, macho_file: *MachO) u64 {
    const file = self.getFile(macho_file);
    return (@as(u64, @intCast(file.getIndex())) << 32) | @as(u64, @intCast(self.n_sect));
}

pub fn getCode(self: Atom, macho_file: *MachO) []const u8 {
    switch (self.getFile(macho_file)) {
        .internal => |x| return x.code.items[self.off..][0..self.size],
        .object => |x| {
            const in_sect = self.getInputSection(macho_file);
            return x.data[in_sect.offset + self.off ..][0..self.size];
        },
        else => unreachable,
    }
}

pub fn getRelocs(self: Atom, macho_file: *MachO) []const macho.relocation_info {
    return switch (self.getFile(macho_file)) {
        .internal => |x| x.relocations.items[self.relocs.pos..][0..self.relocs.len],
        .object => |x| x.relocations.items[self.relocs.pos..][0..self.relocs.len],
        else => unreachable,
    };
}

pub fn getDataInCode(self: Atom, macho_file: *MachO) []const macho.data_in_code {
    return switch (self.getFile(macho_file)) {
        .internal => &[0]macho.data_in_code{},
        .object => |x| x.data_in_code.items[self.dice.pos..][0..self.dice.len],
        else => unreachable,
    };
}

pub fn initOutputSection(sect: macho.section_64, macho_file: *MachO) !u8 {
    const segname, const sectname, const flags = blk: {
        if (sect.isCode()) break :blk .{
            "__TEXT",
            "__text",
            macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        };

        switch (sect.type()) {
            macho.S_4BYTE_LITERALS,
            macho.S_8BYTE_LITERALS,
            macho.S_16BYTE_LITERALS,
            => break :blk .{ "__TEXT", "__const", macho.S_REGULAR },

            macho.S_CSTRING_LITERALS => {
                if (mem.startsWith(u8, sect.sectName(), "__objc")) break :blk .{
                    sect.segName(), sect.sectName(), macho.S_REGULAR,
                };
                break :blk .{ "__TEXT", "__cstring", macho.S_CSTRING_LITERALS };
            },

            macho.S_MOD_INIT_FUNC_POINTERS,
            macho.S_MOD_TERM_FUNC_POINTERS,
            => break :blk .{ "__DATA_CONST", sect.sectName(), sect.flags },

            macho.S_LITERAL_POINTERS,
            macho.S_ZEROFILL,
            macho.S_GB_ZEROFILL,
            macho.S_THREAD_LOCAL_VARIABLES,
            macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
            macho.S_THREAD_LOCAL_REGULAR,
            macho.S_THREAD_LOCAL_ZEROFILL,
            => break :blk .{ sect.segName(), sect.sectName(), sect.flags },

            macho.S_COALESCED => break :blk .{
                sect.segName(),
                sect.sectName(),
                macho.S_REGULAR,
            },

            macho.S_REGULAR => {
                const segname = sect.segName();
                const sectname = sect.sectName();
                if (mem.eql(u8, segname, "__DATA")) {
                    if (mem.eql(u8, sectname, "__const") or
                        mem.eql(u8, sectname, "__cfstring") or
                        mem.eql(u8, sectname, "__objc_classlist") or
                        mem.eql(u8, sectname, "__objc_imageinfo")) break :blk .{
                        "__DATA_CONST",
                        sectname,
                        macho.S_REGULAR,
                    };
                }
                break :blk .{ segname, sectname, macho.S_REGULAR };
            },

            else => break :blk .{ sect.segName(), sect.sectName(), sect.flags },
        }
    };
    return macho_file.getSectionByName(segname, sectname) orelse try macho_file.addSection(
        segname,
        sectname,
        .{ .flags = flags },
    );
}

pub fn scanRelocs(self: Atom, macho_file: *MachO) !void {
    const file = self.getFile(macho_file);
    const relocs = self.getRelocs(macho_file);

    for (relocs) |rel| {
        if (rel.r_extern == 0) continue;
        if (try self.reportUndefSymbol(rel, macho_file)) continue;

        const sym_index = switch (file) {
            inline else => |x| x.symbols.items[rel.r_symbolnum],
        };
        const symbol = macho_file.getSymbol(sym_index);

        switch (@as(macho.reloc_type_x86_64, @enumFromInt(rel.r_type))) {
            .X86_64_RELOC_BRANCH => {
                if (symbol.flags.import) {
                    symbol.flags.stubs = true;
                }
            },

            .X86_64_RELOC_GOT_LOAD,
            .X86_64_RELOC_GOT,
            => {
                symbol.flags.got = true;
            },

            .X86_64_RELOC_TLV => {
                // TODO TLV and import
                assert(!symbol.flags.import);
            },

            .X86_64_RELOC_UNSIGNED => {
                if (symbol.flags.import) {
                    file.object.num_bind_relocs += 1;
                } else if (symbol.isTlvInit(macho_file)) {
                    macho_file.has_tlv = true;
                } else {
                    file.object.num_rebase_relocs += 1;
                }
            },

            else => {},
        }
    }
}

fn reportUndefSymbol(self: Atom, rel: macho.relocation_info, macho_file: *MachO) !bool {
    const file = self.getFile(macho_file);
    const sym_index = switch (file) {
        inline else => |x| x.symbols.items[rel.r_symbolnum],
    };
    const sym = macho_file.getSymbol(sym_index);
    const s_rel_sym = switch (file) {
        inline else => |x| x.symtab.items[rel.r_symbolnum],
    };

    const nlist = sym.getNlist(macho_file);
    if (s_rel_sym.undf() and s_rel_sym.ext() and sym.nlist_idx > 0 and !sym.flags.import and nlist.undf()) {
        const gpa = macho_file.base.allocator;
        const gop = try macho_file.undefs.getOrPut(gpa, sym_index);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(gpa, self.atom_index);
    }

    return false;
}

pub fn resolveRelocs(self: Atom, macho_file: *MachO, writer: anytype) !void {
    assert(!self.getInputSection(macho_file).isZerofill());
    const gpa = macho_file.base.allocator;
    const code = try gpa.dupe(u8, self.getCode(macho_file));
    defer gpa.free(code);
    const relocs = self.getRelocs(macho_file);
    const file = self.getFile(macho_file);

    relocs_log.debug("{x}: {s}", .{ self.value, self.getName(macho_file) });

    var stream = std.io.fixedBufferStream(code);
    const cwriter = stream.writer();

    var subtractor: i64 = 0;
    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        const rel_address = @as(usize, @intCast(rel.r_address));
        const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.r_type);

        const sym_index: ?Symbol.Index = if (rel.r_extern != 0) switch (file) {
            inline else => |x| x.symbols.items[rel.r_symbolnum],
        } else null;
        const sym = if (sym_index) |index| macho_file.getSymbol(index) else null;

        const P = @as(i64, @intCast(self.value)) + rel.r_address;

        const S: i64 = if (rel.r_extern == 0) blk: {
            assert(file == .object);
            const atom_index = file.object.atoms.items[rel.r_symbolnum - 1];
            const atom = macho_file.getAtom(atom_index).?;
            assert(atom.flags.alive);
            break :blk @intCast(atom.value);
        } else @intCast(sym.?.getAddress(.{}, macho_file));

        const A = switch (rel.r_length) {
            0 => code[rel_address],
            1 => mem.readInt(i16, code[rel_address..][0..2], .little),
            2 => mem.readInt(i32, code[rel_address..][0..4], .little),
            3 => mem.readInt(i64, code[rel_address..][0..8], .little),
        };

        const G = if (sym) |s| @as(i64, @intCast(s.getGotAddress(macho_file))) else 0;
        const TLS = @as(i64, @intCast(macho_file.getTlsAddress()));

        if (rel.r_extern == 0) {
            relocs_log.debug("  {s}: {x}: [{x} => {x}] sect({d})", .{
                fmtRelocType(rel.r_type, macho_file),
                rel_address,
                P,
                S + A - subtractor,
                rel.r_symbolnum,
            });
        } else {
            relocs_log.debug("  {s}: {x}: [{x} => {x}] G({x}) ({s})", .{
                fmtRelocType(rel.r_type, macho_file),
                rel_address,
                P,
                S + A - subtractor,
                G + A,
                sym.?.getName(macho_file),
            });
        }

        try stream.seekTo(rel_address);

        switch (rel_type) {
            .X86_64_RELOC_SUBTRACTOR => subtractor = S,

            .X86_64_RELOC_UNSIGNED => {
                if (sym) |s| {
                    if (!s.flags.import and s.isTlvInit(macho_file)) {
                        try cwriter.writeInt(u64, @intCast(S - TLS), .little);
                        continue;
                    }
                }
                try cwriter.writeInt(u64, @as(u64, @intCast(S + A - subtractor)), .little);
                subtractor = 0;
            },

            .X86_64_RELOC_GOT_LOAD => {
                if (!sym.?.flags.import) {
                    // TODO relax!
                }
                try cwriter.writeInt(i32, @as(i32, @intCast(G + A - P + 4)), .little);
            },

            .X86_64_RELOC_GOT => {
                try cwriter.writeInt(u64, @as(u64, @intCast(G + A)), .little);
            },

            .X86_64_RELOC_BRANCH => {
                try cwriter.writeInt(i32, @as(i32, @intCast(S + A - P + 4)), .little);
            },

            .X86_64_RELOC_TLV => {
                assert(!sym.?.flags.import);
                try cwriter.writeInt(i32, @as(i32, @intCast(S + A - P + 4)), .little);
            },

            .X86_64_RELOC_SIGNED => {
                try cwriter.writeInt(i32, @as(i32, @intCast(S + A - P + 4)), .little);
            },

            .X86_64_RELOC_SIGNED_1 => {
                try cwriter.writeInt(i32, @as(i32, @intCast(S + A + 4 - 1 - P)), .little);
            },

            .X86_64_RELOC_SIGNED_2 => {
                try cwriter.writeInt(i32, @as(i32, @intCast(S + A + 4 - 2 - P)), .little);
            },

            .X86_64_RELOC_SIGNED_4 => {
                try cwriter.writeInt(i32, @as(i32, @intCast(S + A + 4 - 4 - P)), .little);
            },
        }
    }

    try writer.writeAll(code);
}

pub fn format(
    atom: Atom,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = atom;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format symbols directly");
}

pub fn fmt(atom: Atom, macho_file: *MachO) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .macho_file = macho_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
    macho_file: *MachO,
};

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const atom = ctx.atom;
    const macho_file = ctx.macho_file;
    try writer.print("atom({d}) : {s} : @{x} : sect({d}) : align({x}) : size({x})", .{
        atom.atom_index, atom.getName(macho_file), atom.value,
        atom.out_n_sect, atom.alignment,           atom.size,
    });
    if (macho_file.options.dead_strip and !atom.flags.alive) {
        try writer.writeAll(" : [*]");
    }
}

const FormatRelocTypeContext = struct {
    r_type: u4,
    macho_file: *MachO,
};

pub fn fmtRelocType(r_type: u4, macho_file: *MachO) std.fmt.Formatter(formatRelocType) {
    return .{
        .data = .{
            .r_type = r_type,
            .macho_file = macho_file,
        },
    };
}

fn formatRelocType(
    ctx: FormatRelocTypeContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const str = switch (ctx.macho_file.options.cpu_arch.?) {
        .x86_64 => blk: {
            const rel_type: macho.reloc_type_x86_64 = @enumFromInt(ctx.r_type);
            break :blk @tagName(rel_type);
        },
        .aarch64 => blk: {
            const rel_type: macho.reloc_type_arm64 = @enumFromInt(ctx.r_type);
            break :blk @tagName(rel_type);
        },
        else => unreachable,
    };
    try writer.print("{s}", .{str});
}

pub const Index = u32;

pub const Flags = packed struct {
    /// Specifies whether this atom is alive or has been garbage collected.
    alive: bool = true,

    /// Specifies if the atom has been visited during garbage collection.
    visited: bool = false,
};

pub const Loc = struct {
    pos: usize = 0,
    len: usize = 0,
};

const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const macho = std.macho;
const log = std.log.scoped(.link);
const relocs_log = std.log.scoped(.relocs);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
