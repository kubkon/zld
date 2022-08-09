const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Elf = @import("../Elf.zig");

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

/// Code (may be non-relocated) this atom represents
code: std.ArrayListUnmanaged(u8) = .{},

/// Size of this atom
/// TODO is this really needed given that size is a field of a symbol?
size: u32,

/// Alignment of this atom. Unlike in MachO, minimum alignment is 1.
alignment: u32,

/// List of relocations belonging to this atom.
relocs: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},

/// Points to the previous and next neighbours
next: ?*Atom,
prev: ?*Atom,

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

pub fn createEmpty(allocator: Allocator) !*Atom {
    const self = try allocator.create(Atom);
    self.* = .{
        .sym_index = 0,
        .file = undefined,
        .size = 0,
        .alignment = 0,
        .prev = null,
        .next = null,
    };
    return self;
}

pub fn deinit(self: *Atom, allocator: Allocator) void {
    self.relocs.deinit(allocator);
    self.code.deinit(allocator);
    self.contained.deinit(allocator);
}

pub fn format(self: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    try std.fmt.format(writer, "Atom {{ ", .{});
    try std.fmt.format(writer, "  .sym_index = {d}, ", .{self.sym_index});
    try std.fmt.format(writer, "  .file = {d}, ", .{self.file});
    try std.fmt.format(writer, "  .contained = {any}, ", .{self.contained.items});
    try std.fmt.format(writer, "  .code = {x}, ", .{std.fmt.fmtSliceHexLower(if (self.code.items.len > 64)
        self.code.items[0..64]
    else
        self.code.items)});
    try std.fmt.format(writer, "  .size = {d}, ", .{self.size});
    try std.fmt.format(writer, "  .alignment = {d}, ", .{self.alignment});
    try std.fmt.format(writer, "  .relocs = {any}, ", .{self.relocs.items});
    try std.fmt.format(writer, "}}", .{});
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

pub fn getTargetAtom(self: Atom, elf_file: *Elf, rel: elf.Elf64_Rela) ?*Atom {
    const sym = self.getSymbol(elf_file);
    const is_got_atom = if (elf_file.got_sect_index) |ndx| ndx == sym.st_shndx else false;

    const r_sym = rel.r_sym();
    const r_type = rel.r_type();

    if (r_type == elf.R_X86_64_64 and is_got_atom) {
        // Special handling as we have repurposed r_addend for out GOT atoms.
        // Now, r_addend in those cases contains the index to the object file where
        // the target symbol is defined.
        const file: ?u32 = if (rel.r_addend > -1) @intCast(u32, rel.r_addend) else null;
        return elf_file.getAtomForSymbol(.{
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
            const got_atom = elf_file.got_entries_map.get(global).?;
            return got_atom;
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
                return elf_file.getAtomForSymbol(global);
            }

            return elf_file.getAtomForSymbol(.{
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

pub fn resolveRelocs(self: *Atom, elf_file: *Elf) !void {
    const sym = self.getSymbol(elf_file);
    const sym_name = self.getName(elf_file);
    log.debug("resolving relocs in atom '{s}'", .{sym_name});

    const is_got_atom = if (elf_file.got_sect_index) |ndx| ndx == sym.st_shndx else false;

    for (self.relocs.items) |rel| {
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
            mem.writeIntLittle(u64, self.code.items[rel.r_offset..][0..8], target);
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
                mem.writeIntLittle(i64, self.code.items[rel.r_offset..][0..8], target);
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
                mem.writeIntLittle(i32, self.code.items[rel.r_offset..][0..4], displacement);
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
                mem.writeIntLittle(i32, self.code.items[rel.r_offset..][0..4], displacement);
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
                mem.writeIntLittle(u32, self.code.items[rel.r_offset..][0..4], scaled);
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
                mem.writeIntLittle(i32, self.code.items[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCREL => outer: {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const global = elf_file.globals.get(tsym_name).?;
                const got_atom = elf_file.got_entries_map.get(global) orelse {
                    log.debug("TODO R_X86_64_REX_GOTPCRELX unhandled: no GOT entry found", .{});
                    log.debug("TODO R_X86_64_REX_GOTPCRELX: {x}: [0x{x} => 0x{x}] ({s})", .{
                        rel.r_offset,
                        source,
                        tsym.st_value,
                        tsym_name,
                    });
                    break :outer;
                };
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
                mem.writeIntLittle(i32, self.code.items[rel.r_offset..][0..4], displacement);
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
                mem.writeIntLittle(u32, self.code.items[rel.r_offset..][0..4], tls_offset);
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
}
