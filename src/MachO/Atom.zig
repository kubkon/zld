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

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

/// Unwind records associated with this atom.
unwind_records: Loc = .{},

/// FDEs associated with this atom.
fdes: Loc = .{},

flags: Flags = .{},

pub fn getName(self: Atom, macho_file: *MachO) [:0]const u8 {
    return macho_file.string_intern.getAssumeExists(self.name);
}

pub fn getObject(self: Atom, macho_file: *MachO) *Object {
    return macho_file.getFile(self.file).?.object;
}

pub fn getInputSection(self: Atom, macho_file: *MachO) macho.section_64 {
    const object = self.getObject(macho_file);
    return object.sections.items(.header)[self.n_sect];
}

pub fn getPriority(self: Atom, macho_file: *MachO) u64 {
    const object = self.getObject(macho_file);
    return (@as(u64, @intCast(object.index)) << 32) | @as(u64, @intCast(self.n_sect));
}

pub fn getCode(self: Atom, macho_file: *MachO) []const u8 {
    const object = self.getObject(macho_file);
    const code = object.getSectionData(self.n_sect);
    return code[self.off..][0..self.size];
}

pub fn getRelocs(self: Atom, macho_file: *MachO) []const Object.Relocation {
    const object = self.getObject(macho_file);
    const relocs = object.sections.items(.relocs)[self.n_sect];
    return relocs.items[self.relocs.pos..][0..self.relocs.len];
}

pub fn getUnwindRecords(self: Atom, macho_file: *MachO) []const UnwindInfo.Record.Index {
    const object = self.getObject(macho_file);
    return object.unwind_records.items[self.unwind_records.pos..][0..self.unwind_records.len];
}

pub fn getFdes(self: Atom, macho_file: *MachO) []const Fde {
    const object = self.getObject(macho_file);
    return object.fdes.items[self.fdes.pos..][0..self.fdes.len];
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
    const osec = macho_file.getSectionByName(segname, sectname) orelse try macho_file.addSection(
        segname,
        sectname,
        .{ .flags = flags },
    );
    if (mem.eql(u8, segname, "__DATA") and mem.eql(u8, sectname, "__data")) {
        macho_file.data_sect_index = osec;
    }
    return osec;
}

pub fn scanRelocs(self: Atom, macho_file: *MachO) !void {
    const object = self.getObject(macho_file);
    const relocs = self.getRelocs(macho_file);

    for (relocs) |rel| {
        if (try self.reportUndefSymbol(rel, macho_file)) continue;

        switch (@as(macho.reloc_type_x86_64, @enumFromInt(rel.meta.type))) {
            .X86_64_RELOC_BRANCH => {
                const symbol = rel.getTargetSymbol(macho_file);
                if (symbol.flags.import) {
                    symbol.flags.stubs = true;
                }
            },

            .X86_64_RELOC_GOT_LOAD,
            .X86_64_RELOC_GOT,
            => {
                rel.getTargetSymbol(macho_file).flags.got = true;
            },

            .X86_64_RELOC_TLV => {
                const symbol = rel.getTargetSymbol(macho_file);
                if (symbol.flags.import) {
                    symbol.flags.tlv_ptr = true;
                }
            },

            .X86_64_RELOC_UNSIGNED => {
                if (rel.tag == .@"extern") {
                    const symbol = rel.getTargetSymbol(macho_file);
                    if (symbol.flags.import) {
                        object.num_bind_relocs += 1;
                        continue;
                    } else if (symbol.isTlvInit(macho_file)) {
                        macho_file.has_tlv = true;
                        continue;
                    }
                }
                object.num_rebase_relocs += 1;
            },

            else => {},
        }
    }
}

fn reportUndefSymbol(self: Atom, rel: Object.Relocation, macho_file: *MachO) !bool {
    if (rel.tag == .local) return false;

    const sym = rel.getTargetSymbol(macho_file);
    if (sym.getNlist(macho_file).undf() and !sym.flags.import and
        sym.getFile(macho_file).?.getIndex() != macho_file.internal_object_index.?)
    {
        const gpa = macho_file.base.allocator;
        const gop = try macho_file.undefs.getOrPut(gpa, rel.target);
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

    relocs_log.debug("{x}: {s}", .{ self.value, self.getName(macho_file) });

    var stream = std.io.fixedBufferStream(code);
    const cwriter = stream.writer();

    var SUB: i64 = 0;
    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.meta.type);
        const rel_offset = rel.offset - self.off;
        const seg_id = macho_file.sections.items(.segment_id)[self.out_n_sect];
        const seg = macho_file.segments.items[seg_id];
        const sym = if (rel.tag == .@"extern") rel.getTargetSymbol(macho_file) else null;

        if (sym) |s| {
            if (s.getNlist(macho_file).undf() and !s.flags.import and
                s.getFile(macho_file).?.getIndex() != macho_file.internal_object_index.?) continue;
        }

        const P = @as(i64, @intCast(self.value)) + @as(i64, @intCast(rel_offset));
        const A = switch (rel.meta.length) {
            0 => code[rel_offset],
            1 => mem.readInt(i16, code[rel_offset..][0..2], .little),
            2 => mem.readInt(i32, code[rel_offset..][0..4], .little),
            3 => mem.readInt(i64, code[rel_offset..][0..8], .little),
        };
        const S: i64 = switch (rel.tag) {
            .local => @as(i64, @intCast(rel.getTargetAtom(macho_file).value)) + rel.addend,
            .@"extern" => @intCast(rel.getTargetSymbol(macho_file).getAddress(.{}, macho_file)),
        };
        const G: i64 = if (rel.tag == .@"extern")
            @intCast(rel.getTargetSymbol(macho_file).getGotAddress(macho_file))
        else
            0;
        const TLS = @as(i64, @intCast(macho_file.getTlsAddress()));

        switch (rel.tag) {
            .local => relocs_log.debug("  {s}: {x}: [{x} => {x}] atom({d})", .{
                fmtRelocType(rel.meta.type, macho_file),
                rel_offset,
                P,
                S + A - SUB,
                rel.getTargetAtom(macho_file).atom_index,
            }),
            .@"extern" => relocs_log.debug("  {s}: {x}: [{x} => {x}] G({x}) ({s})", .{
                fmtRelocType(rel.meta.type, macho_file),
                rel_offset,
                P,
                S + A - SUB,
                G + A,
                rel.getTargetSymbol(macho_file).getName(macho_file),
            }),
        }

        try stream.seekTo(rel_offset);

        switch (rel_type) {
            .X86_64_RELOC_SUBTRACTOR => SUB = S,

            .X86_64_RELOC_UNSIGNED => {
                assert(rel.meta.length == 3);
                assert(!rel.meta.pcrel);
                if (sym) |s| {
                    if (s.flags.import) {
                        macho_file.bind.entries.appendAssumeCapacity(.{
                            .target = rel.target,
                            .offset = @as(u64, @intCast(P)) - seg.vmaddr,
                            .segment_id = seg_id,
                            .addend = A,
                        });
                        continue;
                    } else if (s.isTlvInit(macho_file)) {
                        try cwriter.writeInt(u64, @intCast(S - TLS), .little);
                        continue;
                    }
                }
                macho_file.rebase.entries.appendAssumeCapacity(.{
                    .offset = @as(u64, @intCast(P)) - seg.vmaddr,
                    .segment_id = seg_id,
                });
                try cwriter.writeInt(u64, @intCast(S + A - SUB), .little);
                SUB = 0;
            },

            .X86_64_RELOC_GOT_LOAD => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                if (!sym.?.flags.import) {
                    try relaxGotLoad(code[rel_offset - 3 ..]);
                    try cwriter.writeInt(i32, @intCast(S + A - P - 4), .little);
                } else {
                    try cwriter.writeInt(i32, @intCast(G + A - P - 4), .little);
                }
            },

            .X86_64_RELOC_GOT => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                try cwriter.writeInt(i32, @intCast(G + A - P - 4), .little);
            },

            .X86_64_RELOC_BRANCH => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                try cwriter.writeInt(i32, @intCast(S + A - P - 4), .little);
            },

            .X86_64_RELOC_TLV => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                if (sym.?.flags.tlv_ptr) {
                    assert(sym.?.flags.import);
                    const S_: i64 = @intCast(sym.?.getTlvPtrAddress(macho_file));
                    try cwriter.writeInt(i32, @intCast(S_ + A - P - 4), .little);
                } else {
                    try relaxTlv(code[rel_offset - 3 ..]);
                    try cwriter.writeInt(i32, @intCast(S + A - P - 4), .little);
                }
            },

            .X86_64_RELOC_SIGNED => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                try cwriter.writeInt(i32, @intCast(S + A - P - 4), .little);
            },

            .X86_64_RELOC_SIGNED_1 => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                try cwriter.writeInt(i32, @intCast(S + A - P - 4 + 1), .little);
            },

            .X86_64_RELOC_SIGNED_2 => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                try cwriter.writeInt(i32, @intCast(S + A - P - 4 + 2), .little);
            },

            .X86_64_RELOC_SIGNED_4 => {
                assert(rel.meta.length == 2);
                assert(rel.meta.pcrel);
                try cwriter.writeInt(i32, @intCast(S + A - P - 4 + 4), .little);
            },
        }
    }

    try writer.writeAll(code);
}

fn relaxGotLoad(code: []u8) !void {
    const old_inst = disassemble(code) orelse return error.RelaxFail;
    switch (old_inst.encoding.mnemonic) {
        .mov => {
            const inst = try Instruction.new(old_inst.prefix, .lea, &old_inst.ops);
            relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
            encode(&.{inst}, code) catch return error.RelaxFail;
        },
        else => return error.RelaxFail,
    }
}

fn relaxTlv(code: []u8) !void {
    const old_inst = disassemble(code) orelse return error.RelaxFail;
    switch (old_inst.encoding.mnemonic) {
        .mov => {
            const inst = try Instruction.new(old_inst.prefix, .lea, &old_inst.ops);
            relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
            encode(&.{inst}, code) catch return error.RelaxFail;
        },
        else => return error.RelaxFail,
    }
}

fn disassemble(code: []const u8) ?Instruction {
    var disas = Disassembler.init(code);
    const inst = disas.next() catch return null;
    return inst;
}

fn encode(insts: []const Instruction, code: []u8) !void {
    var stream = std.io.fixedBufferStream(code);
    const writer = stream.writer();
    for (insts) |inst| {
        try inst.encode(writer, .{});
    }
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
    if (!atom.flags.alive) try writer.writeAll(" : [*]");
    if (atom.fdes.len > 0) {
        try writer.writeAll(" : fdes{ ");
        for (atom.getFdes(macho_file), atom.fdes.pos..) |fde, i| {
            try writer.print("{d}", .{i});
            if (!fde.alive) try writer.writeAll("([*])");
            if (i < atom.fdes.pos + atom.fdes.len - 1) try writer.writeAll(", ");
        }
        try writer.writeAll(" }");
    }
    if (atom.unwind_records.len > 0) {
        try writer.writeAll(" : unwind{ ");
        for (atom.getUnwindRecords(macho_file), atom.unwind_records.pos..) |index, i| {
            const rec = macho_file.getUnwindRecord(index);
            try writer.print("{d}", .{i});
            if (!rec.alive) try writer.writeAll("([*])");
            if (i < atom.unwind_records.pos + atom.unwind_records.len - 1) try writer.writeAll(", ");
        }
        try writer.writeAll(" }");
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
const dis_x86_64 = @import("dis_x86_64");
const eh_frame = @import("eh_frame.zig");
const macho = std.macho;
const log = std.log.scoped(.link);
const relocs_log = std.log.scoped(.relocs);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Disassembler = dis_x86_64.Disassembler;
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const Instruction = dis_x86_64.Instruction;
const Immediate = dis_x86_64.Immediate;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const UnwindInfo = @import("UnwindInfo.zig");
