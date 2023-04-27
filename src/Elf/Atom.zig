/// Address allocated for this Atom.
value: u64,

/// Name of this Atom.
name: u32,

file: u32,

/// Size of this atom
size: u32,

/// Alignment of this atom as a power of two.
alignment: u8,

/// Index of the input section.
shndx: u16,

/// Index of the output section.
out_shndx: u16,

/// Index of the input section containing this atom's relocs.
relocs_shndx: u16,

atom_index: Index,

/// Points to the previous and next neighbours
next: ?Index,
prev: ?Index,

pub const Index = u32;

pub const empty = Atom{
    .value = 0,
    .name = 0,
    .file = 0,
    .size = 0,
    .alignment = 0,
    .shndx = 0,
    .out_shndx = 0,
    .relocs_shndx = @bitCast(u16, @as(i16, -1)),
    .atom_index = 0,
    .prev = null,
    .next = null,
};

pub fn getName(self: Atom, elf_file: *Elf) []const u8 {
    return elf_file.getString(self.name);
}

pub fn getCode(self: Atom, elf_file: *Elf) []const u8 {
    const object = self.getFile(elf_file).?;
    return object.getShdrContents(self.shndx);
}

pub inline fn getFile(self: Atom, elf_file: *Elf) *Object {
    return elf_file.getFile(self.file).?;
}

pub fn getRelocs(self: Atom, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
    if (self.relocs_shndx == @bitCast(u16, @as(i16, -1))) return &[0]elf.Elf64_Rela{};
    const object = self.getFile(elf_file).?;
    const bytes = object.getShdrContents(self.relocs_shndx);
    const nrelocs = @divExact(bytes.len, @sizeOf(elf.Elf64_Rela));
    return @ptrCast([*]align(1) const elf.Elf64_Rela, bytes)[0..nrelocs];
}

pub fn getTargetAtomIndex(self: Atom, elf_file: *Elf, rel: elf.Elf64_Rela) ?Atom.Index {
    const r_sym = rel.r_sym();
    const r_type = rel.r_type();
    const tsym_name = elf_file.getSymbolName(.{
        .sym_index = r_sym,
        .file = self.file,
    });
    log.debug("  (getTargetAtom: %{d}: {s}, r_type={d})", .{ r_sym, tsym_name, r_type });
    const tsym = elf_file.getSymbol(.{
        .sym_index = r_sym,
        .file = self.file,
    });
    const tsym_st_bind = tsym.st_bind();
    const tsym_st_type = tsym.st_type();
    const is_section = tsym_st_type == elf.STT_SECTION;
    const is_local = is_section or tsym_st_bind == elf.STB_LOCAL;

    if (!is_local) {
        const global = elf_file.globals.get(tsym_name).?;
        return elf_file.getAtomIndexForSymbol(global);
    }

    return elf_file.getAtomIndexForSymbol(.{
        .sym_index = r_sym,
        .file = self.file,
    });
}

fn getTargetAddress(self: Atom, rel: elf.Elf64_Rela, elf_file: *Elf) ?u64 {
    const sym_loc = Elf.SymbolWithLoc{
        .sym_index = rel.r_sym(),
        .file = self.file,
    };
    const sym_name = elf_file.getSymbolName(sym_loc);
    switch (rel.r_type()) {
        elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCREL => {
            const global = elf_file.globals.get(sym_name).?;
            return elf_file.got_section.getAddress(global, elf_file);
        },
        else => {},
    }

    const sym = elf_file.getSymbol(sym_loc);
    const is_section = sym.st_type() == elf.STT_SECTION;
    const is_local = is_section or sym.st_bind() == elf.STB_LOCAL;
    log.debug("  (getTargetAddress: %{d}: {s}, local? {})", .{ rel.r_sym(), sym_name, is_local });

    if (!is_local) {
        const global = elf_file.globals.get(sym_name).?;
        return elf_file.getSymbol(global).st_value;
    }

    return sym.st_value;
}

pub fn scanRelocs(self: Atom, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;
    const object = self.getFile(elf_file).?;
    for (self.getRelocs(elf_file)) |rel| {
        // While traversing relocations, synthesize any missing atom.
        // TODO synthesize PLT atoms, GOT atoms, etc.
        const tsym_name = object.getSourceSymbolName(rel.r_sym());
        switch (rel.r_type()) {
            elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCREL => {
                const global = elf_file.globals.get(tsym_name).?;
                const gop = try elf_file.got_section.getOrCreate(gpa, global);
                if (!gop.found_existing) {
                    log.debug("{s}: creating GOT entry: [() -> {s}]", .{
                        switch (rel.r_type()) {
                            elf.R_X86_64_REX_GOTPCRELX => "REX_GOTPCRELX",
                            elf.R_X86_64_GOTPCREL => "GOTPCREL",
                            else => unreachable,
                        },
                        tsym_name,
                    });
                }
            },
            else => {},
        }
    }
}

pub fn resolveRelocs(self: Atom, elf_file: *Elf, writer: anytype) !void {
    const gpa = elf_file.base.allocator;
    const code = try gpa.dupe(u8, self.getCode(elf_file));
    defer gpa.free(code);
    const relocs = self.getRelocs(elf_file);

    for (relocs) |rel| {
        const tsym_loc = Elf.SymbolWithLoc{
            .sym_index = rel.r_sym(),
            .file = self.file,
        };
        const tsym = elf_file.getSymbol(tsym_loc);
        const tsym_name = elf_file.getSymbolName(tsym_loc);
        const tsym_st_type = tsym.st_type();
        const source = @intCast(i64, self.value + rel.r_offset);
        const target = @intCast(i64, self.getTargetAddress(rel, elf_file).?);

        const r_type = rel.r_type();
        switch (r_type) {
            elf.R_X86_64_NONE => {},
            elf.R_X86_64_64 => {
                const actual_target = target + rel.r_addend;
                log.debug("64: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, actual_target, tsym_name });
                mem.writeIntLittle(i64, code[rel.r_offset..][0..8], actual_target);
            },
            elf.R_X86_64_PC32,
            elf.R_X86_64_PLT32,
            elf.R_X86_64_GOTPCREL,
            elf.R_X86_64_REX_GOTPCRELX,
            => {
                const displacement = @intCast(i32, target - source + rel.r_addend);
                log.debug("{s}: {x}: [0x{x} => 0x{x}] ({s})", .{
                    switch (r_type) {
                        elf.R_X86_64_PC32 => "PC32",
                        elf.R_X86_64_PLT32 => "PLT32",
                        elf.R_X86_64_GOTPCREL => "GOTPCREL",
                        elf.R_X86_64_REX_GOTPCRELX => "REX_GOTPCRELX",
                        else => unreachable,
                    },
                    rel.r_offset,
                    source,
                    target,
                    tsym_name,
                });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], displacement);
            },
            elf.R_X86_64_32 => {
                const scaled = math.cast(u32, target + rel.r_addend) orelse {
                    log.err("32: target value overflows 32bits", .{});
                    log.err("  target value 0x{x}", .{target + rel.r_addend});
                    log.err("  target symbol {s}", .{tsym_name});
                    return error.RelocationOverflow;
                };
                log.debug("32: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, tsym_name });
                mem.writeIntLittle(u32, code[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_32S => {
                const scaled = math.cast(i32, target + rel.r_addend) orelse {
                    log.err("32S: target value overflows 32bits", .{});
                    log.err("  target value 0x{x}", .{target + rel.r_addend});
                    log.err("  target symbol {s}", .{tsym_name});
                    return error.RelocationOverflow;
                };
                log.debug("32S: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, tsym_name });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_TPOFF32 => {
                assert(tsym_st_type == elf.STT_TLS);
                const base_addr: u64 = base_addr: {
                    const index = if (elf_file.getSectionByName(".tbss")) |index|
                        index
                    else
                        elf_file.getSectionByName(".tdata").?;
                    const shdr = elf_file.sections.items(.shdr)[index];
                    break :base_addr shdr.sh_addr + shdr.sh_size;
                };
                const tls_offset = @truncate(u32, @bitCast(u64, -(@intCast(i64, base_addr) - target) + rel.r_addend));
                log.debug("TPOFF32: {x}: [0x{x} => 0x{x} (TLS)] ({s})", .{
                    rel.r_offset,
                    source,
                    tls_offset,
                    tsym_name,
                });
                mem.writeIntLittle(u32, code[rel.r_offset..][0..4], tls_offset);
            },
            elf.R_X86_64_DTPOFF64,
            elf.R_X86_64_GOTTPOFF,
            elf.R_X86_64_TLSGD,
            => {
                // TODO I believe here we should emit a dynamic relocation pointing
                // at a GOT cell.
                log.debug("TODO {s}: {x}: [0x{x} => 0x{x}] ({s})", .{
                    switch (r_type) {
                        elf.R_X86_64_DTPOFF64 => "DTPOFF64",
                        elf.R_X86_64_GOTTPOFF => "GOTTPOFF",
                        elf.R_X86_64_TLSGD => "TLSGD",
                        else => unreachable,
                    },
                    rel.r_offset,
                    source,
                    tsym.st_value,
                    tsym_name,
                });
            },
            else => {
                log.debug("TODO {d}: {x}: [0x{x} => 0x{x}] ({s})", .{
                    r_type,
                    rel.r_offset,
                    source,
                    tsym.st_value,
                    tsym_name,
                });
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

pub fn fmt(atom: Atom, elf_file: *Elf) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
    elf_file: *Elf,
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
    try writer.print("%%%{d} : {s} : @{x} : align({x}) : size({x})", .{
        atom.atom_index, atom.getName(ctx.elf_file), atom.value,
        atom.alignment,  atom.size,
    });
}

const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const dis_x86_64 = @import("dis_x86_64");
const elf = std.elf;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Disassembler = dis_x86_64.Disassembler;
const Elf = @import("../Elf.zig");
const Instruction = dis_x86_64.Instruction;
const Immediate = dis_x86_64.Immediate;
const Object = @import("Object.zig");
