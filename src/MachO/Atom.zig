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
n_sect: u32 = 0,

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

flags: Flags = .{},

pub fn getName(self: Atom, macho_file: *MachO) [:0]const u8 {
    return macho_file.string_intern.getAssumeExists(self.name);
}

pub fn getFile(self: Atom, macho_file: *MachO) File {
    return macho_file.getFile(self.file).?;
}

pub fn getInputSection(self: Atom, macho_file: *MachO) macho.section_64 {
    return switch (self.getFile(macho_file)) {
        .dylib => unreachable,
        inline else => |x| x.sections.items(.header)[self.n_sect],
    };
}

pub fn getInputAddress(self: Atom, macho_file: *MachO) u64 {
    return self.getInputSection(macho_file).addr + self.off;
}

pub fn getPriority(self: Atom, macho_file: *MachO) u64 {
    const file = self.getFile(macho_file);
    return (@as(u64, @intCast(file.getIndex())) << 32) | @as(u64, @intCast(self.n_sect));
}

pub fn getCode(self: Atom, macho_file: *MachO) []const u8 {
    const code = switch (self.getFile(macho_file)) {
        .dylib => unreachable,
        inline else => |x| x.getSectionData(self.n_sect),
    };
    return code[self.off..][0..self.size];
}

pub fn getRelocs(self: Atom, macho_file: *MachO) []const Relocation {
    const relocs = switch (self.getFile(macho_file)) {
        .dylib => unreachable,
        inline else => |x| x.sections.items(.relocs)[self.n_sect],
    };
    return relocs.items[self.relocs.pos..][0..self.relocs.len];
}

pub fn getUnwindRecords(self: Atom, macho_file: *MachO) []const UnwindInfo.Record.Index {
    return switch (self.getFile(macho_file)) {
        .dylib => unreachable,
        .internal => &[0]UnwindInfo.Record.Index{},
        .object => |x| x.unwind_records.items[self.unwind_records.pos..][0..self.unwind_records.len],
    };
}

pub fn markUnwindRecordsDead(self: Atom, macho_file: *MachO) void {
    for (self.getUnwindRecords(macho_file)) |cu_index| {
        const cu = macho_file.getUnwindRecord(cu_index);
        cu.alive = false;

        if (cu.getFdePtr(macho_file)) |fde| {
            fde.alive = false;
        }
    }
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
    const object = self.getFile(macho_file).object;
    const relocs = self.getRelocs(macho_file);

    for (relocs) |rel| {
        if (try self.reportUndefSymbol(rel, macho_file)) continue;

        switch (@as(macho.reloc_type_x86_64, @enumFromInt(rel.meta.type))) {
            .X86_64_RELOC_BRANCH => {
                const symbol = rel.getTargetSymbol(macho_file);
                if (symbol.flags.import or (symbol.flags.@"export" and (symbol.flags.weak or symbol.flags.interposable))) {
                    symbol.flags.stubs = true;
                    if (symbol.flags.weak) {
                        macho_file.binds_to_weak = true;
                    }
                } else if (mem.startsWith(u8, symbol.getName(macho_file), "_objc_msgSend$")) {
                    symbol.flags.objc_stubs = true;
                }
            },

            .X86_64_RELOC_GOT_LOAD => {
                const symbol = rel.getTargetSymbol(macho_file);
                if (symbol.flags.import or (symbol.flags.@"export" and (symbol.flags.weak or symbol.flags.interposable))) {
                    symbol.flags.got = true;
                    if (symbol.flags.weak) {
                        macho_file.binds_to_weak = true;
                    }
                }
            },

            .X86_64_RELOC_GOT => {
                rel.getTargetSymbol(macho_file).flags.got = true;
            },

            .X86_64_RELOC_TLV => {
                const symbol = rel.getTargetSymbol(macho_file);
                if (!symbol.flags.tlv) {
                    macho_file.base.fatal(
                        "{}: {s}: illegal thread-local variable reference to regular symbol {s}",
                        .{ object.fmtPath(), self.getName(macho_file), symbol.getName(macho_file) },
                    );
                }
                if (symbol.flags.import or (symbol.flags.@"export" and (symbol.flags.weak or symbol.flags.interposable))) {
                    symbol.flags.tlv_ptr = true;
                    if (symbol.flags.weak) {
                        macho_file.binds_to_weak = true;
                    }
                }
            },

            .X86_64_RELOC_UNSIGNED => {
                if (rel.meta.length == 3) { // TODO this really should check if this is pointer width
                    if (rel.tag == .@"extern") {
                        const symbol = rel.getTargetSymbol(macho_file);
                        if (symbol.isTlvInit(macho_file)) {
                            macho_file.has_tlv = true;
                            continue;
                        }
                        if (symbol.flags.import) {
                            object.num_bind_relocs += 1;
                            if (symbol.flags.weak) {
                                object.num_weak_bind_relocs += 1;
                                macho_file.binds_to_weak = true;
                            }
                            continue;
                        }
                        if (symbol.flags.@"export") {
                            if (symbol.flags.weak) {
                                object.num_weak_bind_relocs += 1;
                                macho_file.binds_to_weak = true;
                            } else if (symbol.flags.interposable) {
                                object.num_bind_relocs += 1;
                            }
                        }
                    }
                    object.num_rebase_relocs += 1;
                }
            },

            else => {},
        }
    }
}

fn reportUndefSymbol(self: Atom, rel: Relocation, macho_file: *MachO) !bool {
    if (rel.tag == .local) return false;

    const sym = rel.getTargetSymbol(macho_file);
    if (!sym.flags.import and sym.getFile(macho_file).? == .object and sym.getNlist(macho_file).undf()) {
        const gpa = macho_file.base.allocator;
        const gop = try macho_file.undefs.getOrPut(gpa, rel.target);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(gpa, self.atom_index);
        return true;
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
    const name = self.getName(macho_file);

    relocs_log.debug("{x}: {s}", .{ self.value, name });

    var stream = std.io.fixedBufferStream(code);

    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.meta.type);
        const rel_offset = rel.offset - self.off;
        const subtractor = if (rel.meta.has_subtractor) relocs[i - 1] else null;

        if (rel.tag == .@"extern") {
            const sym = rel.getTargetSymbol(macho_file);
            if (!sym.flags.import and sym.getFile(macho_file).? == .object and sym.getNlist(macho_file).undf())
                continue;
        }

        if (rel_type == .X86_64_RELOC_SUBTRACTOR) {
            if (i + 1 >= relocs.len) {
                macho_file.base.fatal(
                    "{}: {s}: 0x{x}: invalid relocation: unterminated X86_64_RELOC_SUBTRACTOR",
                    .{
                        file.fmtPath(), name, rel.offset,
                    },
                );
                continue;
            }
            const next_rel_type: macho.reloc_type_x86_64 = @enumFromInt(relocs[i + 1].meta.type);
            if (next_rel_type != .X86_64_RELOC_UNSIGNED) {
                macho_file.base.fatal(
                    "{}: {s}: 0x{x}: invalid relocation: invalid target relocation for X86_64_RELOC_SUBTRACTOR: {s}",
                    .{ file.fmtPath(), name, rel.offset, @tagName(next_rel_type) },
                );
                continue;
            }
        }

        try stream.seekTo(rel_offset);
        self.resolveRelocInner(rel, subtractor, code, macho_file, stream.writer()) catch |err| switch (err) {
            error.UnexpectedPcrel => macho_file.base.fatal(
                "{}: {s}: 0x{x}: invalid relocation: invalid PCrel option in {s}",
                .{ file.fmtPath(), name, rel.offset, @tagName(rel_type) },
            ),
            error.UnexpectedSize => macho_file.base.fatal(
                "{}: {s}: 0x{x}: invalid relocation: invalid size {d} in {s}",
                .{
                    file.fmtPath(),
                    name,
                    rel.offset,
                    @as(u8, 1) << rel.meta.length,
                    @tagName(rel_type),
                },
            ),
            error.NonExternTarget => macho_file.base.fatal(
                "{}: {s}: 0x{x}: invalid relocation: non-extern target in {s}",
                .{ file.fmtPath(), name, rel.offset, @tagName(rel_type) },
            ),
            error.RelaxFail => macho_file.base.fatal(
                "{}: {s}: 0x{x}: failed to relax relocation: in {s}",
                .{ file.fmtPath(), name, rel.offset, @tagName(rel_type) },
            ),
            else => |e| return e,
        };
    }

    try writer.writeAll(code);
}

const ResolveError = error{
    UnexpectedPcrel,
    UnexpectedSize,
    NonExternTarget,
    RelaxFail,
    NoSpaceLeft,
};

fn resolveRelocInner(
    self: Atom,
    rel: Relocation,
    subtractor: ?Relocation,
    code: []u8,
    macho_file: *MachO,
    writer: anytype,
) ResolveError!void {
    const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.meta.type);
    const rel_offset = rel.offset - self.off;
    const seg_id = macho_file.sections.items(.segment_id)[self.out_n_sect];
    const seg = macho_file.segments.items[seg_id];
    const P = @as(i64, @intCast(self.value)) + @as(i64, @intCast(rel_offset));
    const A = rel.addend;
    const S: i64 = @intCast(rel.getTargetAddress(macho_file));
    const G: i64 = @intCast(rel.getGotTargetAddress(macho_file));
    const TLS = @as(i64, @intCast(macho_file.getTlsAddress()));
    const SUB = if (subtractor) |sub| @as(i64, @intCast(sub.getTargetAddress(macho_file))) else 0;

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

    switch (rel_type) {
        .X86_64_RELOC_SUBTRACTOR => {},

        .X86_64_RELOC_UNSIGNED => {
            if (rel.meta.pcrel) return error.UnexpectedPcrel;
            if (rel.meta.length == 3) {
                if (rel.tag == .@"extern") {
                    const sym = rel.getTargetSymbol(macho_file);
                    if (sym.isTlvInit(macho_file)) {
                        try writer.writeInt(u64, @intCast(S - TLS), .little);
                        return;
                    }
                    const entry = bind.Entry{
                        .target = rel.target,
                        .offset = @as(u64, @intCast(P)) - seg.vmaddr,
                        .segment_id = seg_id,
                        .addend = A,
                    };
                    if (sym.flags.import) {
                        macho_file.bind.entries.appendAssumeCapacity(entry);
                        if (sym.flags.weak) {
                            macho_file.weak_bind.entries.appendAssumeCapacity(entry);
                        }
                        return;
                    }
                    if (sym.flags.@"export") {
                        if (sym.flags.weak) {
                            macho_file.weak_bind.entries.appendAssumeCapacity(entry);
                        } else if (sym.flags.interposable) {
                            macho_file.bind.entries.appendAssumeCapacity(entry);
                        }
                    }
                }
                macho_file.rebase.entries.appendAssumeCapacity(.{
                    .offset = @as(u64, @intCast(P)) - seg.vmaddr,
                    .segment_id = seg_id,
                });
                try writer.writeInt(u64, @intCast(S + A - SUB), .little);
            } else if (rel.meta.length == 2) {
                try writer.writeInt(u32, @bitCast(@as(i32, @intCast(S + A - SUB))), .little);
            } else return error.UnexpectedSize;
        },

        .X86_64_RELOC_GOT_LOAD => {
            if (rel.tag == .local) return error.NonExternTarget;
            if (rel.meta.length != 2) return error.UnexpectedSize;
            if (!rel.meta.pcrel) return error.UnexpectedPcrel;
            if (rel.getTargetSymbol(macho_file).flags.got) {
                try writer.writeInt(i32, @intCast(G + A - P - 4), .little);
            } else {
                try relaxGotLoad(code[rel_offset - 3 ..]);
                try writer.writeInt(i32, @intCast(S + A - P - 4), .little);
            }
        },

        .X86_64_RELOC_GOT => {
            if (rel.tag == .local) return error.NonExternTarget;
            if (rel.meta.length != 2) return error.UnexpectedSize;
            if (!rel.meta.pcrel) return error.UnexpectedPcrel;
            try writer.writeInt(i32, @intCast(G + A - P - 4), .little);
        },

        .X86_64_RELOC_BRANCH => {
            if (rel.meta.length != 2) return error.UnexpectedSize;
            if (!rel.meta.pcrel) return error.UnexpectedPcrel;
            try writer.writeInt(i32, @intCast(S + A - P - 4), .little);
        },

        .X86_64_RELOC_TLV => {
            if (rel.tag == .local) return error.NonExternTarget;
            if (rel.meta.length != 2) return error.UnexpectedSize;
            if (!rel.meta.pcrel) return error.UnexpectedPcrel;
            const sym = rel.getTargetSymbol(macho_file);
            if (sym.flags.tlv_ptr) {
                const S_: i64 = @intCast(sym.getTlvPtrAddress(macho_file));
                try writer.writeInt(i32, @intCast(S_ + A - P - 4), .little);
            } else {
                try relaxTlv(code[rel_offset - 3 ..]);
                try writer.writeInt(i32, @intCast(S + A - P - 4), .little);
            }
        },

        .X86_64_RELOC_SIGNED,
        .X86_64_RELOC_SIGNED_1,
        .X86_64_RELOC_SIGNED_2,
        .X86_64_RELOC_SIGNED_4,
        => {
            if (rel.meta.length != 2) return error.UnexpectedSize;
            if (!rel.meta.pcrel) return error.UnexpectedPcrel;
            const correction: i64 = switch (rel_type) {
                .X86_64_RELOC_SIGNED => 0,
                .X86_64_RELOC_SIGNED_1 => 1,
                .X86_64_RELOC_SIGNED_2 => 2,
                .X86_64_RELOC_SIGNED_4 => 4,
                else => unreachable,
            };
            try writer.writeInt(i32, @intCast(S + A - P - 4 - correction), .little);
        },
    }
}

fn relaxGotLoad(code: []u8) error{RelaxFail}!void {
    const old_inst = disassemble(code) orelse return error.RelaxFail;
    switch (old_inst.encoding.mnemonic) {
        .mov => {
            const inst = Instruction.new(old_inst.prefix, .lea, &old_inst.ops) catch return error.RelaxFail;
            relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
            encode(&.{inst}, code) catch return error.RelaxFail;
        },
        else => return error.RelaxFail,
    }
}

fn relaxTlv(code: []u8) error{RelaxFail}!void {
    const old_inst = disassemble(code) orelse return error.RelaxFail;
    switch (old_inst.encoding.mnemonic) {
        .mov => {
            const inst = Instruction.new(old_inst.prefix, .lea, &old_inst.ops) catch return error.RelaxFail;
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
    if (atom.unwind_records.len > 0) {
        try writer.writeAll(" : unwind{ ");
        for (atom.getUnwindRecords(macho_file), atom.unwind_records.pos..) |index, i| {
            const rec = macho_file.getUnwindRecord(index);
            try writer.print("{d}", .{index});
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
const bind = @import("dyld_info/bind.zig");
const dis_x86_64 = @import("dis_x86_64");
const macho = std.macho;
const log = std.log.scoped(.link);
const relocs_log = std.log.scoped(.relocs);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Disassembler = dis_x86_64.Disassembler;
const File = @import("file.zig").File;
const Instruction = dis_x86_64.Instruction;
const Immediate = dis_x86_64.Immediate;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
const UnwindInfo = @import("UnwindInfo.zig");
