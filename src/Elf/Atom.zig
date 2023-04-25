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

/// Each decl always gets a local symbol with the fully qualified name.
/// The vaddr and size are found here directly.
/// The file offset is found by computing the vaddr offset from the section vaddr
/// the symbol references, and adding that to the file offset of the section.
/// If this field is 0, it means the codegen size = 0 and there is no symbol or
/// offset table entry.
sym_index: u32,

/// null means global synthetic symbol table.
file: ?u32,

/// List of symbols contained within this atom
contained: std.ArrayListUnmanaged(SymbolAtOffset) = .{},

/// Size of this atom
/// TODO is this really needed given that size is a field of a symbol?
size: u32,

/// Alignment of this atom. Unlike in MachO, minimum alignment is 1.
alignment: u32,

/// Index of the input section.
shndx: u16,

/// Index of the input section containing this atom's relocs.
relocs_shndx: u16,

/// Points to the previous and next neighbours
next: ?Index,
prev: ?Index,

pub const Index = u32;

pub const SymbolAtOffset = struct {
    sym_index: u32,
    offset: u64,

    pub fn format(
        self: SymbolAtOffset,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "{{ {d}: .offset = {d} }}", .{ self.sym_index, self.offset });
    }
};

pub const empty = Atom{
    .sym_index = 0,
    .file = undefined,
    .size = 0,
    .alignment = 0,
    .shndx = 0,
    .relocs_shndx = @bitCast(u16, @as(i16, -1)),
    .prev = null,
    .next = null,
};

pub fn deinit(self: *Atom, allocator: Allocator) void {
    self.contained.deinit(allocator);
}

pub fn getSymbol(self: Atom, elf_file: *Elf) elf.Elf64_Sym {
    return self.getSymbolPtr(elf_file).*;
}

pub fn getSymbolPtr(self: Atom, elf_file: *Elf) *elf.Elf64_Sym {
    return elf_file.getSymbolPtr(.{
        .sym_index = self.sym_index,
        .file = self.file,
    });
}

pub fn getSymbolWithLoc(self: Atom) Elf.SymbolWithLoc {
    return .{ .sym_index = self.sym_index, .file = self.file };
}

pub fn getName(self: Atom, elf_file: *Elf) []const u8 {
    return elf_file.getSymbolName(.{
        .sym_index = self.sym_index,
        .file = self.file,
    });
}

pub fn getCode(self: Atom, elf_file: *Elf) []const u8 {
    assert(self.file != null);
    const object = elf_file.objects.items[self.file.?];
    return object.getShdrContents(self.shndx);
}

pub fn getRelocs(self: Atom, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
    if (self.relocs_shndx == @bitCast(u16, @as(i16, -1))) return &[0]elf.Elf64_Rela{};
    assert(self.file != null);
    const object = elf_file.objects.items[self.file.?];
    const bytes = object.getShdrContents(self.relocs_shndx);
    const nrelocs = @divExact(bytes.len, @sizeOf(elf.Elf64_Rela));
    return @ptrCast([*]align(1) const elf.Elf64_Rela, bytes)[0..nrelocs];
}

pub fn getTargetAtomIndex(self: Atom, elf_file: *Elf, rel: elf.Elf64_Rela) ?Atom.Index {
    const sym = self.getSymbol(elf_file);
    const is_got_atom = if (elf_file.got_sect_index) |ndx| ndx == sym.st_shndx else false;

    const r_sym = rel.r_sym();
    const r_type = rel.r_type();

    if (r_type == elf.R_X86_64_64 and is_got_atom) {
        // Special handling as we have repurposed r_addend for out GOT atoms.
        // Now, r_addend in those cases contains the index to the object file where
        // the target symbol is defined.
        const file: ?u32 = if (rel.r_addend > -1) @intCast(u32, rel.r_addend) else null;
        return elf_file.getAtomIndexForSymbol(.{
            .sym_index = r_sym,
            .file = file,
        });
    }

    const tsym_name = elf_file.getSymbolName(.{
        .sym_index = r_sym,
        .file = self.file,
    });
    log.debug("  (getTargetAtom: %{d}: {s}, r_type={d})", .{ r_sym, tsym_name, r_type });

    switch (r_type) {
        elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCRELX, elf.R_X86_64_GOTPCREL => {
            const global = elf_file.globals.get(tsym_name).?;
            const got_atom_index = elf_file.got_entries_map.get(global).?;
            return got_atom_index;
        },
        else => {
            const tsym = elf_file.getSymbol(.{
                .sym_index = r_sym,
                .file = self.file,
            });
            const tsym_st_bind = tsym.st_info >> 4;
            const tsym_st_type = tsym.st_info & 0xf;
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
        },
    }
}

fn getTargetAddress(self: Atom, r_sym: u32, elf_file: *Elf) u64 {
    const tsym = elf_file.getSymbol(.{
        .sym_index = r_sym,
        .file = self.file,
    });
    const tsym_name = elf_file.getSymbolName(.{
        .sym_index = r_sym,
        .file = self.file,
    });
    const tsym_st_bind = tsym.st_info >> 4;
    const tsym_st_type = tsym.st_info & 0xf;
    const is_section = tsym_st_type == elf.STT_SECTION;
    const is_local = is_section or tsym_st_bind == elf.STB_LOCAL;
    log.debug("  (getTargetAddress: %{d}: {s}, local? {})", .{ r_sym, tsym_name, is_local });

    if (!is_local) {
        const global = elf_file.globals.get(tsym_name).?;
        const sym = elf_file.getSymbol(global);
        return sym.st_value;
    }

    return tsym.st_value;
}

pub fn scanRelocs(self: Atom, elf_file: *Elf) !void {
    const file = self.file orelse return;
    const gpa = elf_file.base.allocator;
    const object = elf_file.objects.items[file];
    for (self.getRelocs(elf_file)) |rel| {
        // While traversing relocations, synthesize any missing atom.
        // TODO synthesize PLT atoms, GOT atoms, etc.
        const tsym_name = object.getSourceSymbolName(rel.r_sym());
        switch (rel.r_type()) {
            elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCREL => blk: {
                const global = elf_file.globals.get(tsym_name).?;
                if (elf_file.got_entries_map.contains(global)) break :blk;
                log.debug("R_X86_64_GOTPCREL: creating GOT atom: [() -> {s}]", .{
                    tsym_name,
                });
                const got_atom = try elf_file.createGotAtom(global);
                try elf_file.got_entries_map.putNoClobber(gpa, global, got_atom);
            },
            else => {},
        }
    }
}

fn isDefinitionAvailable(elf_file: *Elf, global: Elf.SymbolWithLoc) bool {
    const sym = if (global.file) |file| sym: {
        const object = elf_file.objects.items[file];
        break :sym object.symtab.items[global.sym_index];
    } else elf_file.locals.items[global.sym_index];
    return sym.st_info & 0xf != elf.STT_NOTYPE or sym.st_shndx != elf.SHN_UNDEF;
}

pub fn resolveRelocs(self: Atom, atom_index: Atom.Index, elf_file: *Elf, writer: anytype) !void {
    const gpa = elf_file.base.allocator;
    const sym = self.getSymbol(elf_file);
    const is_got_atom = if (elf_file.got_sect_index) |ndx| ndx == sym.st_shndx else false;

    const code = if (self.file) |_|
        try gpa.dupe(u8, self.getCode(elf_file))
    else
        try gpa.alloc(u8, 8);
    defer gpa.free(code);

    const relocs = if (self.file) |_|
        self.getRelocs(elf_file)
    else
        &[1]elf.Elf64_Rela{elf_file.relocs.get(atom_index).?};

    for (relocs) |rel| {
        const r_sym = rel.r_sym();
        const r_type = rel.r_type();

        if (r_type == elf.R_X86_64_64 and is_got_atom) {
            // Special handling as we have repurposed r_addend for out GOT atoms.
            // Now, r_addend in those cases contains the index to the object file where
            // the target symbol is defined.
            const file: ?u32 = if (rel.r_addend > -1) @intCast(u32, rel.r_addend) else null;
            const tsym = elf_file.getSymbol(.{
                .sym_index = r_sym,
                .file = file,
            });
            const target = tsym.st_value;
            const tsym_name = elf_file.getSymbolName(.{
                .sym_index = r_sym,
                .file = file,
            });
            log.debug("R_X86_64_64: (GOT) {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, target, tsym_name });
            mem.writeIntLittle(u64, code[rel.r_offset..][0..8], target);
            continue;
        }

        const tsym = elf_file.getSymbol(.{
            .sym_index = r_sym,
            .file = self.file,
        });
        const tsym_name = elf_file.getSymbolName(.{
            .sym_index = r_sym,
            .file = self.file,
        });
        const tsym_st_type = tsym.st_info & 0xf;

        switch (r_type) {
            elf.R_X86_64_NONE => {},
            elf.R_X86_64_64 => {
                const target = @intCast(i64, self.getTargetAddress(r_sym, elf_file)) + rel.r_addend;
                log.debug("R_X86_64_64: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, target, tsym_name });
                mem.writeIntLittle(i64, code[rel.r_offset..][0..8], target);
            },
            elf.R_X86_64_PC32 => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const target = @intCast(i64, self.getTargetAddress(r_sym, elf_file));
                const displacement = @intCast(i32, target - source + rel.r_addend);
                log.debug("R_X86_64_PC32: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    target,
                    tsym_name,
                });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], displacement);
            },
            elf.R_X86_64_PLT32 => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const target = @intCast(i64, self.getTargetAddress(r_sym, elf_file));
                const displacement = @intCast(i32, target - source + rel.r_addend);
                log.debug("R_X86_64_PLT32: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    target,
                    tsym_name,
                });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], displacement);
            },
            elf.R_X86_64_32 => {
                const target = self.getTargetAddress(r_sym, elf_file);
                const scaled = math.cast(u32, @intCast(i64, target) + rel.r_addend) orelse {
                    log.err("R_X86_64_32: target value overflows 32bits", .{});
                    log.err("  target value 0x{x}", .{@intCast(i64, target) + rel.r_addend});
                    log.err("  target symbol {s}", .{tsym_name});
                    return error.RelocationOverflow;
                };
                log.debug("R_X86_64_32: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, tsym_name });
                mem.writeIntLittle(u32, code[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_32S => {
                const target = self.getTargetAddress(r_sym, elf_file);
                const scaled = math.cast(i32, @intCast(i64, target) + rel.r_addend) orelse {
                    log.err("R_X86_64_32: target value overflows 32bits", .{});
                    log.err("  target value 0x{x}", .{@intCast(i64, target) + rel.r_addend});
                    log.err("  target symbol {s}", .{tsym_name});
                    return error.RelocationOverflow;
                };
                log.debug("R_X86_64_32S: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, tsym_name });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCREL => outer: {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const global = elf_file.globals.get(tsym_name).?;
                const got_atom_index = elf_file.got_entries_map.get(global) orelse {
                    log.debug("TODO R_X86_64_REX_GOTPCRELX unhandled: no GOT entry found", .{});
                    log.debug("TODO R_X86_64_REX_GOTPCRELX: {x}: [0x{x} => 0x{x}] ({s})", .{
                        rel.r_offset,
                        source,
                        tsym.st_value,
                        tsym_name,
                    });
                    break :outer;
                };
                const got_atom = elf_file.getAtom(got_atom_index);
                const target: i64 = blk: {
                    if (got_atom.file) |file| {
                        const actual_object = elf_file.objects.items[file];
                        const actual_tsym = actual_object.symtab.items[got_atom.sym_index];
                        break :blk @intCast(i64, actual_tsym.st_value);
                    }
                    const actual_tsym = elf_file.locals.items[got_atom.sym_index];
                    break :blk @intCast(i64, actual_tsym.st_value);
                };
                log.debug("R_X86_64_REX_GOTPCRELX: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    target,
                    tsym_name,
                });
                const displacement = @intCast(i32, target - source + rel.r_addend);
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], displacement);
            },
            elf.R_X86_64_TPOFF32 => {
                assert(tsym_st_type == elf.STT_TLS);
                const source = sym.st_value + rel.r_offset;
                const target = self.getTargetAddress(r_sym, elf_file);
                const base_addr: u64 = base_addr: {
                    const index = if (elf_file.getSectionByName(".tbss")) |index|
                        index
                    else
                        elf_file.getSectionByName(".tdata").?;
                    const shdr = elf_file.sections.items(.shdr)[index];
                    break :base_addr shdr.sh_addr + shdr.sh_size;
                };
                const tls_offset = @truncate(u32, @bitCast(u64, -@intCast(i64, base_addr - target) + rel.r_addend));
                log.debug("R_X86_64_TPOFF32: {x}: [0x{x} => 0x{x} (TLS)] ({s})", .{
                    rel.r_offset,
                    source,
                    tls_offset,
                    tsym_name,
                });
                mem.writeIntLittle(u32, code[rel.r_offset..][0..4], tls_offset);
            },
            elf.R_X86_64_DTPOFF64 => {
                const source = sym.st_value + rel.r_offset;
                // TODO I believe here we should emit a dynamic relocation pointing
                // at a GOT cell.
                log.debug("TODO R_X86_64_DTPOFF64: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    tsym.st_value,
                    tsym_name,
                });
            },
            elf.R_X86_64_GOTTPOFF => {
                const source = sym.st_value + rel.r_offset;
                log.debug("TODO R_X86_64_GOTTPOFF: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    tsym.st_value,
                    tsym_name,
                });
            },
            elf.R_X86_64_TLSGD => {
                const source = sym.st_value + rel.r_offset;
                log.debug("TODO R_X86_64_TLSGD: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    tsym.st_value,
                    tsym_name,
                });
            },
            else => {
                const source = sym.st_value + rel.r_offset;
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
