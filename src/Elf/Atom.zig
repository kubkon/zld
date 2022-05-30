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
local_sym_index: u32,

/// null means global synthetic symbol table.
file: ?u32,

/// List of symbol aliases pointing to the same atom via different entries
aliases: std.ArrayListUnmanaged(u32) = .{},

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
    local_sym_index: u32,
    offset: u64,

    pub fn format(
        self: SymbolAtOffset,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "{{ {d}: .offset = {d} }}", .{ self.local_sym_index, self.offset });
    }
};

pub fn createEmpty(allocator: Allocator) !*Atom {
    const self = try allocator.create(Atom);
    self.* = .{
        .local_sym_index = 0,
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
    self.aliases.deinit(allocator);
}

pub fn format(self: Atom, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = fmt;
    _ = options;
    try std.fmt.format(writer, "Atom {{ ", .{});
    try std.fmt.format(writer, "  .local_sym_index = {d}, ", .{self.local_sym_index});
    try std.fmt.format(writer, "  .file = {d}, ", .{self.file});
    try std.fmt.format(writer, "  .aliases = {any}, ", .{self.aliases.items});
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

fn getSymbol(self: Atom, elf_file: *Elf, index: u32) elf.Elf64_Sym {
    if (self.file) |file| {
        const object = elf_file.objects.items[file];
        return object.symtab.items[index];
    } else {
        return elf_file.locals.items[index];
    }
}

pub fn resolveRelocs(self: *Atom, elf_file: *Elf) !void {
    const sym = self.getSymbol(elf_file, self.local_sym_index);
    const sym_name = if (self.file) |file|
        elf_file.objects.items[file].getString(sym.st_name)
    else
        elf_file.getString(sym.st_name);
    log.debug("resolving relocs in atom '{s}'", .{sym_name});

    const is_got_atom = if (elf_file.got_sect_index) |ndx| ndx == sym.st_shndx else false;

    for (self.relocs.items) |rel| {
        const r_sym = rel.r_sym();
        const r_type = rel.r_type();

        if (r_type == elf.R_X86_64_64 and is_got_atom) {
            // Special handling as we have repurposed r_addend for out GOT atoms.
            // Now, r_addend in those cases contains the index to the object file where
            // the target symbol is defined.
            const target: u64 = blk: {
                if (rel.r_addend > -1) {
                    const object = elf_file.objects.items[@intCast(u64, rel.r_addend)];
                    const tsym = object.symtab.items[r_sym];
                    break :blk tsym.st_value;
                } else {
                    const tsym = elf_file.locals.items[r_sym];
                    break :blk tsym.st_value;
                }
            };
            const tsym_name = if (rel.r_addend > -1) blk: {
                const object = elf_file.objects.items[@intCast(u64, rel.r_addend)];
                const tsym = object.symtab.items[r_sym];
                break :blk object.getString(tsym.st_name);
            } else elf_file.getString(elf_file.locals.items[r_sym].st_name);
            log.debug("R_X86_64_64: (GOT) {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, target, tsym_name });
            mem.writeIntLittle(u64, self.code.items[rel.r_offset..][0..8], target);
            continue;
        }

        const tsym = if (self.file) |file| blk: {
            const object = elf_file.objects.items[file];
            break :blk object.symtab.items[r_sym];
        } else elf_file.locals.items[r_sym];
        const tsym_name = if (self.file) |file| blk: {
            const object = elf_file.objects.items[file];
            break :blk object.getString(tsym.st_name);
        } else elf_file.getString(tsym.st_name);
        const tsym_st_bind = tsym.st_info >> 4;
        const tsym_st_type = tsym.st_info & 0xf;

        switch (r_type) {
            elf.R_X86_64_NONE => {},
            elf.R_X86_64_64 => {
                const is_local = tsym_st_type == elf.STT_SECTION or tsym_st_bind == elf.STB_LOCAL;
                const target: u64 = blk: {
                    if (!is_local) {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (global.file) |file| {
                            const actual_object = elf_file.objects.items[file];
                            const actual_tsym = actual_object.symtab.items[global.sym_index];
                            break :blk actual_tsym.st_value;
                        } else {
                            const actual_tsym = elf_file.locals.items[global.sym_index];
                            break :blk actual_tsym.st_value;
                        }
                    }

                    break :blk tsym.st_value;
                };
                log.debug("R_X86_64_64: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, target, tsym_name });
                mem.writeIntLittle(u64, self.code.items[rel.r_offset..][0..8], target);
            },
            elf.R_X86_64_PC32 => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const is_local = tsym_st_type == elf.STT_SECTION or tsym_st_bind == elf.STB_LOCAL;
                const target: i64 = blk: {
                    if (!is_local) {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (global.file) |file| {
                            const actual_object = elf_file.objects.items[file];
                            const actual_tsym = actual_object.symtab.items[global.sym_index];
                            break :blk @intCast(i64, actual_tsym.st_value);
                        } else {
                            const actual_tsym = elf_file.locals.items[global.sym_index];
                            break :blk @intCast(i64, actual_tsym.st_value);
                        }
                    }

                    break :blk @intCast(i64, tsym.st_value);
                };
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
                const is_local = tsym_st_type == elf.STT_SECTION or tsym_st_bind == elf.STB_LOCAL;
                const target: i64 = blk: {
                    if (!is_local) {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (global.file) |file| {
                            const actual_object = elf_file.objects.items[file];
                            const actual_tsym = actual_object.symtab.items[global.sym_index];
                            if (actual_tsym.st_info & 0xf == elf.STT_NOTYPE and
                                actual_tsym.st_shndx == elf.SHN_UNDEF)
                            {
                                log.debug("TODO handle R_X86_64_PLT32 to an UND symbol via PLT table", .{});
                                break :blk source;
                            }
                            break :blk @intCast(i64, actual_tsym.st_value);
                        } else {
                            const actual_tsym = elf_file.locals.items[global.sym_index];
                            break :blk @intCast(i64, actual_tsym.st_value);
                        }
                    }

                    break :blk @intCast(i64, tsym.st_value);
                };
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
                const is_local = tsym_st_type == elf.STT_SECTION or tsym_st_bind == elf.STB_LOCAL;
                const target: u64 = blk: {
                    if (!is_local) {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (global.file) |file| {
                            const actual_object = elf_file.objects.items[file];
                            const actual_tsym = actual_object.symtab.items[global.sym_index];
                            break :blk actual_tsym.st_value;
                        } else {
                            const actual_tsym = elf_file.locals.items[global.sym_index];
                            break :blk actual_tsym.st_value;
                        }
                    }

                    break :blk tsym.st_value;
                };
                const scaled = math.cast(u32, @intCast(i64, target) + rel.r_addend) catch |err| switch (err) {
                    error.Overflow => {
                        log.err("R_X86_64_32: target value overflows 32bits", .{});
                        log.err("  target value 0x{x}", .{@intCast(i64, target) + rel.r_addend});
                        log.err("  target symbol {s}", .{tsym_name});
                        return error.RelocationOverflow;
                    },
                    else => |e| return e,
                };
                log.debug("R_X86_64_32: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, tsym_name });
                mem.writeIntLittle(u32, self.code.items[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_REX_GOTPCRELX => outer: {
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
                        const actual_tsym = actual_object.symtab.items[got_atom.local_sym_index];
                        break :blk @intCast(i64, actual_tsym.st_value);
                    }
                    const actual_tsym = elf_file.locals.items[got_atom.local_sym_index];
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
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const is_global_tls = tsym_st_type == elf.STT_TLS and tsym_st_bind == elf.STB_GLOBAL;
                assert(is_global_tls);
                const base_addr: u64 = base_addr: {
                    const shdr = if (elf_file.tdata_sect_index) |index|
                        elf_file.shdrs.items[index]
                    else
                        elf_file.shdrs.items[elf_file.tbss_sect_index.?];
                    break :base_addr shdr.sh_addr;
                };
                const tls_offset = tsym.st_value - base_addr;
                log.debug("R_X86_64_TPOFF32: {x}: [0x{x} => 0x{x} (TLS)] ({s})", .{
                    rel.r_offset,
                    source,
                    tls_offset,
                    tsym_name,
                });
                mem.writeIntLittle(u32, self.code.items[rel.r_offset..][0..4], @intCast(u32, tls_offset));
            },
            elf.R_X86_64_DTPOFF64 => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const is_global_tls = tsym_st_type == elf.STT_TLS and tsym_st_bind == elf.STB_GLOBAL;
                if (is_global_tls) {
                    // Since the symbol is defined locally (in the linkage unit), we
                    // can statically relocate the offset. To put it another way,
                    // we convert this relocation into TPOFF32.
                    const base_addr: u64 = base_addr: {
                        const shdr = if (elf_file.tdata_sect_index) |index|
                            elf_file.shdrs.items[index]
                        else
                            elf_file.shdrs.items[elf_file.tbss_sect_index.?];
                        break :base_addr shdr.sh_addr;
                    };
                    const tls_offset = tsym.st_value - base_addr;
                    log.debug("R_X86_64_DTPOFF64: {x}: [0x{x} => 0x{x} (TLS)] ({s})", .{
                        rel.r_offset,
                        source,
                        tls_offset,
                        tsym_name,
                    });
                    mem.writeIntLittle(u64, self.code.items[rel.r_offset..][0..8], tls_offset);
                } else {
                    // TODO I believe here we should emit a dynamic relocation pointing
                    // at a GOT cell.
                    log.debug("TODO R_X86_64_DTPOFF64: {x}: [0x{x} => 0x{x}] ({s})", .{
                        rel.r_offset,
                        source,
                        tsym.st_value,
                        tsym_name,
                    });
                }
            },
            elf.R_X86_64_GOTTPOFF => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                const is_global_tls = tsym_st_type == elf.STT_TLS and tsym_st_bind == elf.STB_GLOBAL;
                if (is_global_tls) {
                    // Since the symbol is defined locally (in the linkage unit), we
                    // can statically relocate the offset. To put it another way,
                    // we convert this relocation into TPOFF32.
                    const global = elf_file.globals.get(tsym_name).?;
                    const actual_object = elf_file.objects.items[global.file.?];
                    const actual_tsym = actual_object.symtab.items[global.sym_index];
                    const base_addr: u64 = base_addr: {
                        const shdr = if (elf_file.tdata_sect_index) |index|
                            elf_file.shdrs.items[index]
                        else
                            elf_file.shdrs.items[elf_file.tbss_sect_index.?];
                        break :base_addr shdr.sh_addr;
                    };
                    const tls_offset = actual_tsym.st_value - base_addr;
                    log.debug("R_X86_64_GOTTPOFF: {x}: [0x{x} => 0x{x} (TLS)] ({s})", .{
                        rel.r_offset,
                        source,
                        tls_offset,
                        tsym_name,
                    });
                    // TODO move all this into parsing objects into atoms. By then,
                    // we should already know if the definition is available or not.
                    // ADDQ -> LEAQ
                    log.debug("{x}", .{std.fmt.fmtSliceHexLower(self.code.items[rel.r_offset - 4 ..][0..8])});
                    self.code.items[rel.r_offset - 2] = 0xc7;
                    self.code.items[rel.r_offset - 1] = 0xc3;
                    mem.writeIntLittle(i32, self.code.items[rel.r_offset..][0..4], @intCast(i32, tls_offset));
                } else {
                    // TODO
                    log.debug("TODO R_X86_64_GOTTPOFF: {x}: [0x{x} => 0x{x}] ({s})", .{
                        rel.r_offset,
                        source,
                        tsym.st_value,
                        tsym_name,
                    });
                }
            },
            elf.R_X86_64_TLSGD => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
                log.debug("TODO R_X86_64_TLSGD: {x}: [0x{x} => 0x{x}] ({s})", .{
                    rel.r_offset,
                    source,
                    tsym.st_value,
                    tsym_name,
                });
            },
            else => {
                const source = @intCast(i64, sym.st_value + rel.r_offset);
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
