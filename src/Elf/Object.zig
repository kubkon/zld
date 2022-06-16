const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");

const dis_x86_64 = @import("dis_x86_64");
const Disassembler = dis_x86_64.Disassembler;
const Instruction = dis_x86_64.Instruction;
const RegisterOrMemory = dis_x86_64.RegisterOrMemory;

file: fs.File,
name: []const u8,
file_offset: ?u32 = null,

header: ?elf.Elf64_Ehdr = null,

shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},

sections: std.ArrayListUnmanaged(u16) = .{},
relocs: std.AutoHashMapUnmanaged(u16, u16) = .{},

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symtab_index: ?u16 = null,

pub fn deinit(self: *Object, allocator: Allocator) void {
    self.shdrs.deinit(allocator);
    self.sections.deinit(allocator);
    self.relocs.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    allocator.free(self.name);
}

pub fn parse(self: *Object, allocator: Allocator, target: std.Target) !void {
    const reader = self.file.reader();
    if (self.file_offset) |offset| {
        try reader.context.seekTo(offset);
    }
    const header = try reader.readStruct(elf.Elf64_Ehdr);

    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) {
        log.debug("Invalid ELF magic {s}, expected \x7fELF", .{header.e_ident[0..4]});
        return error.NotObject;
    }
    if (header.e_ident[elf.EI_VERSION] != 1) {
        log.debug("Unknown ELF version {d}, expected 1", .{header.e_ident[elf.EI_VERSION]});
        return error.NotObject;
    }
    if (header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) {
        log.err("TODO big endian support", .{});
        return error.TODOBigEndianSupport;
    }
    if (header.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) {
        log.err("TODO 32bit support", .{});
        return error.TODOElf32bitSupport;
    }
    if (header.e_type != elf.ET.REL) {
        log.debug("Invalid file type {any}, expected ET.REL", .{header.e_type});
        return error.NotObject;
    }
    if (header.e_machine != target.cpu.arch.toElfMachine()) {
        log.debug("Invalid architecture {any}, expected {any}", .{
            header.e_machine,
            target.cpu.arch.toElfMachine(),
        });
        return error.InvalidCpuArch;
    }
    if (header.e_version != 1) {
        log.debug("Invalid ELF version {d}, expected 1", .{header.e_version});
        return error.NotObject;
    }

    assert(header.e_entry == 0);
    assert(header.e_phoff == 0);
    assert(header.e_phnum == 0);

    self.header = header;

    try self.parseShdrs(allocator, reader);
    try self.parseSymtab(allocator);
}

fn parseShdrs(self: *Object, allocator: Allocator, reader: anytype) !void {
    const shnum = self.header.?.e_shnum;
    if (shnum == 0) return;

    const offset = self.file_offset orelse 0;
    try reader.context.seekTo(offset + self.header.?.e_shoff);
    try self.shdrs.ensureTotalCapacity(allocator, shnum);

    var i: u16 = 0;
    while (i < shnum) : (i += 1) {
        const shdr = try reader.readStruct(elf.Elf64_Shdr);
        self.shdrs.appendAssumeCapacity(shdr);

        switch (shdr.sh_type) {
            elf.SHT_SYMTAB => {
                self.symtab_index = i;
            },
            elf.SHT_PROGBITS, elf.SHT_NOBITS => {
                try self.sections.append(allocator, i);
            },
            elf.SHT_REL, elf.SHT_RELA => {
                try self.relocs.putNoClobber(allocator, @intCast(u16, shdr.sh_info), i);
            },
            else => {},
        }
    }

    // Parse shstrtab
    var buffer = try self.readShdrContents(allocator, self.header.?.e_shstrndx);
    defer allocator.free(buffer);
    try self.strtab.appendSlice(allocator, buffer);
}

fn parseSymtab(self: *Object, allocator: Allocator) !void {
    if (self.symtab_index == null) return;

    const symtab_shdr = self.shdrs.items[self.symtab_index.?];

    // We first read the contents of string table associated with this symbol table
    // noting the offset at which it is appended to the existing string table, which
    // we will then use to fixup st_name offset within each symbol.
    const strtab_offset = @intCast(u32, self.strtab.items.len);
    var str_buffer = try self.readShdrContents(allocator, @intCast(u16, symtab_shdr.sh_link));
    defer allocator.free(str_buffer);
    try self.strtab.appendSlice(allocator, str_buffer);

    var sym_buffer = try self.readShdrContents(allocator, self.symtab_index.?);
    defer allocator.free(sym_buffer);
    const syms = @alignCast(@alignOf(elf.Elf64_Sym), mem.bytesAsSlice(elf.Elf64_Sym, sym_buffer));
    try self.symtab.ensureTotalCapacity(allocator, syms.len);

    for (syms) |sym| {
        var out_sym = sym;
        if (sym.st_name > 0) {
            out_sym.st_name += strtab_offset;
        } else if (sym.st_info & 0xf == elf.STT_SECTION) {
            // If the symbol is pointing to a section header, copy the sh_name offset as the new
            // st_name offset.
            const shdr = self.shdrs.items[sym.st_shndx];
            out_sym.st_name = shdr.sh_name;
        }
        self.symtab.appendAssumeCapacity(out_sym);
    }
}

pub fn parseIntoAtoms(self: *Object, allocator: Allocator, object_id: u16, elf_file: *Elf) !void {
    log.debug("parsing '{s}' into atoms", .{self.name});

    var symbols_by_shndx = std.AutoHashMap(u16, std.ArrayList(u32)).init(allocator);
    defer symbols_by_shndx.deinit();
    for (self.sections.items) |ndx| {
        try symbols_by_shndx.putNoClobber(ndx, std.ArrayList(u32).init(allocator));
    }
    for (self.symtab.items) |sym, sym_id| {
        if (sym.st_shndx == elf.SHN_UNDEF) continue;
        if (elf.SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < elf.SHN_HIRESERVE) continue;
        const map = symbols_by_shndx.getPtr(sym.st_shndx) orelse continue;
        try map.append(@intCast(u32, sym_id));
    }

    for (self.sections.items) |ndx| {
        const shdr = self.shdrs.items[ndx];
        const shdr_name = self.getString(shdr.sh_name);

        log.debug("  parsing section '{s}'", .{shdr_name});

        const syms = symbols_by_shndx.get(ndx).?;
        const tshdr_ndx = (try elf_file.getMatchingSection(object_id, ndx)) orelse {
            log.debug("unhandled section", .{});
            continue;
        };

        const atom = try Atom.createEmpty(allocator);
        errdefer {
            atom.deinit(allocator);
            allocator.destroy(atom);
        }
        try elf_file.managed_atoms.append(allocator, atom);

        atom.file = object_id;
        atom.size = @intCast(u32, shdr.sh_size);
        atom.alignment = @intCast(u32, shdr.sh_addralign);

        var local_sym_index: ?u32 = null;

        for (syms.items) |sym_id| {
            const sym = self.symtab.items[sym_id];
            const is_sect_sym = sym.st_info & 0xf == elf.STT_SECTION;
            if (is_sect_sym) {
                local_sym_index = sym_id;
                continue;
            }
            try atom.contained.append(allocator, .{
                .local_sym_index = sym_id,
                .offset = sym.st_value,
            });
        }

        atom.local_sym_index = local_sym_index orelse blk: {
            const sym_index = @intCast(u32, self.symtab.items.len);
            try self.symtab.append(allocator, .{
                .st_name = shdr.sh_name,
                .st_info = (elf.STB_LOCAL << 4) | elf.STT_OBJECT,
                .st_other = 0,
                .st_shndx = 0,
                .st_value = 0,
                .st_size = atom.size,
            });
            break :blk sym_index;
        };

        var code = if (shdr.sh_type == elf.SHT_NOBITS) blk: {
            var code = try allocator.alloc(u8, atom.size);
            mem.set(u8, code, 0);
            break :blk code;
        } else try self.readShdrContents(allocator, ndx);
        defer allocator.free(code);

        if (self.relocs.get(ndx)) |rel_ndx| {
            const rel_shdr = self.shdrs.items[rel_ndx];
            var raw_relocs = try self.readShdrContents(allocator, rel_ndx);
            defer allocator.free(raw_relocs);

            const nrelocs = @divExact(rel_shdr.sh_size, rel_shdr.sh_entsize);
            try atom.relocs.ensureTotalCapacity(allocator, nrelocs);

            var count: usize = 0;
            while (count < nrelocs) : (count += 1) {
                const bytes = raw_relocs[count * rel_shdr.sh_entsize ..][0..rel_shdr.sh_entsize];
                var rel = blk: {
                    if (rel_shdr.sh_type == elf.SHT_REL) {
                        const rel = @ptrCast(*const elf.Elf64_Rel, @alignCast(@alignOf(elf.Elf64_Rel), bytes)).*;
                        // TODO parse addend from the placeholder
                        // const addend = mem.readIntLittle(i32, code[rel.r_offset..][0..4]);
                        // break :blk .{
                        //     .r_offset = rel.r_offset,
                        //     .r_info = rel.r_info,
                        //     .r_addend = addend,
                        // };
                        log.err("TODO need to parse addend embedded in the relocation placeholder for SHT_REL", .{});
                        log.err("  for relocation {}", .{rel});
                        return error.TODOParseAddendFromPlaceholder;
                    }

                    break :blk @ptrCast(*const elf.Elf64_Rela, @alignCast(@alignOf(elf.Elf64_Rela), bytes)).*;
                };

                // While traversing relocations, synthesize any missing atom.
                // TODO synthesize PLT atoms, GOT atoms, etc.
                const tsym = self.symtab.items[rel.r_sym()];
                const tsym_name = self.getString(tsym.st_name);
                switch (rel.r_type()) {
                    elf.R_X86_64_REX_GOTPCRELX => blk: {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (isDefinitionAvailable(elf_file, global)) opt: {
                            // Link-time constant, try to optimize it away.
                            var disassembler = Disassembler.init(code[rel.r_offset - 3 ..]);
                            const maybe_inst = disassembler.next() catch break :opt;
                            const inst = maybe_inst orelse break :opt;

                            // TODO can we optimise anything that isn't an RM encoding?
                            if (inst.enc != .rm) break :opt;
                            const rm = inst.data.rm;
                            if (rm.reg_or_mem != .mem) break :opt;
                            if (rm.reg_or_mem.mem.base != .rip) break :opt;
                            const dst = rm.reg;
                            const src = rm.reg_or_mem;

                            var stream = std.io.fixedBufferStream(code[rel.r_offset - 3 ..][0..7]);
                            const writer = stream.writer();

                            switch (inst.tag) {
                                .mov => {
                                    // rewrite to LEA
                                    const new_inst = Instruction{
                                        .tag = .lea,
                                        .enc = .rm,
                                        .data = Instruction.Data.rm(dst, src),
                                    };
                                    try new_inst.encode(writer);

                                    const r_sym = rel.r_sym();
                                    rel.r_info = (@intCast(u64, r_sym) << 32) | elf.R_X86_64_PC32;
                                    log.debug("rewriting R_X86_64_REX_GOTPCRELX -> R_X86_64_PC32: MOV -> LEA", .{});
                                    break :blk;
                                },
                                .cmp => {
                                    // rewrite to CMP MI encoding
                                    const new_inst = Instruction{
                                        .tag = .cmp,
                                        .enc = .mi,
                                        .data = Instruction.Data.mi(RegisterOrMemory.reg(dst), 0x0),
                                    };
                                    try new_inst.encode(writer);

                                    const r_sym = rel.r_sym();
                                    rel.r_info = (@intCast(u64, r_sym) << 32) | elf.R_X86_64_32;
                                    rel.r_addend = 0;
                                    log.debug("rewriting R_X86_64_REX_GOTPCRELX -> R_X86_64_32: CMP r64, r/m64 -> CMP r/m64, imm32", .{});

                                    break :blk;
                                },
                                else => {},
                            }
                        }

                        if (elf_file.got_entries_map.contains(global)) break :blk;
                        log.debug("R_X86_64_REX_GOTPCRELX: creating GOT atom: [() -> {s}]", .{
                            tsym_name,
                        });
                        const got_atom = try elf_file.createGotAtom(global);
                        try elf_file.got_entries_map.putNoClobber(allocator, global, got_atom);
                    },
                    elf.R_X86_64_GOTPCREL => blk: {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (elf_file.got_entries_map.contains(global)) break :blk;
                        log.debug("R_X86_64_GOTPCREL: creating GOT atom: [() -> {s}]", .{
                            tsym_name,
                        });
                        const got_atom = try elf_file.createGotAtom(global);
                        try elf_file.got_entries_map.putNoClobber(allocator, global, got_atom);
                    },
                    elf.R_X86_64_GOTTPOFF => blk: {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (isDefinitionAvailable(elf_file, global)) {
                            // Link-time constant, try to optimize it away.
                            var disassembler = Disassembler.init(code[rel.r_offset - 3 ..]);
                            const maybe_inst = disassembler.next() catch break :blk;
                            const inst = maybe_inst orelse break :blk;

                            if (inst.enc != .rm) break :blk;
                            const rm = inst.data.rm;
                            if (rm.reg_or_mem != .mem) break :blk;
                            if (rm.reg_or_mem.mem.base != .rip) break :blk;
                            const dst = rm.reg;

                            var stream = std.io.fixedBufferStream(code[rel.r_offset - 3 ..][0..7]);
                            const writer = stream.writer();

                            switch (inst.tag) {
                                .mov => {
                                    // rewrite to MOV MI encoding
                                    const new_inst = Instruction{
                                        .tag = .mov,
                                        .enc = .mi,
                                        .data = Instruction.Data.mi(RegisterOrMemory.reg(dst), 0x0),
                                    };
                                    try new_inst.encode(writer);

                                    const r_sym = rel.r_sym();
                                    rel.r_info = (@intCast(u64, r_sym) << 32) | elf.R_X86_64_TPOFF32;
                                    rel.r_addend = 0;
                                    log.debug("rewriting R_X86_64_GOTTPOFF -> R_X86_64_TPOFF32: MOV r64, r/m64 -> MOV r/m64, imm32", .{});
                                },
                                else => {},
                            }
                        }
                    },
                    elf.R_X86_64_DTPOFF64 => {
                        const global = elf_file.globals.get(tsym_name).?;
                        if (isDefinitionAvailable(elf_file, global)) {
                            // rewrite into TPOFF32
                            const r_sym = rel.r_sym();
                            rel.r_info = (@intCast(u64, r_sym) << 32) | elf.R_X86_64_TPOFF32;
                            assert(rel.r_addend == 0); // expected r_addend == 0 when rewriting
                            rel.r_addend = rel.r_addend;
                            log.debug("rewriting R_X86_64_DTPOFF64 -> R_X86_64_TPOFF32", .{});
                        }
                    },
                    else => {},
                }

                atom.relocs.appendAssumeCapacity(rel);
            }
        }

        try atom.code.appendSlice(allocator, code);

        // Update target section's metadata
        const tshdr = &elf_file.shdrs.items[tshdr_ndx];
        tshdr.sh_addralign = math.max(tshdr.sh_addralign, atom.alignment);
        tshdr.sh_size = mem.alignForwardGeneric(
            u64,
            mem.alignForwardGeneric(u64, tshdr.sh_size, atom.alignment) + atom.size,
            tshdr.sh_addralign,
        );

        if (elf_file.atoms.getPtr(tshdr_ndx)) |last| {
            last.*.next = atom;
            atom.prev = last.*;
            last.* = atom;
        } else {
            try elf_file.atoms.putNoClobber(allocator, tshdr_ndx, atom);
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

pub fn getString(self: Object, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.items.ptr + off), 0);
}

/// Caller owns the memory.
fn readShdrContents(self: Object, allocator: Allocator, shdr_index: u16) ![]u8 {
    const shdr = self.shdrs.items[shdr_index];
    var buffer = try allocator.alloc(u8, shdr.sh_size);
    errdefer allocator.free(buffer);

    const offset = self.file_offset orelse 0;
    const amt = try self.file.preadAll(buffer, shdr.sh_offset + offset);
    if (amt != buffer.len) {
        return error.InputOutput;
    }

    return buffer;
}
