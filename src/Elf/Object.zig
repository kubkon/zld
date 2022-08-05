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

name: []const u8,
data: []align(@alignOf(u64)) const u8,

header: elf.Elf64_Ehdr = undefined,

shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},

sections: std.ArrayListUnmanaged(u16) = .{},
relocs: std.AutoHashMapUnmanaged(u16, u16) = .{},

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: []const u8 = &.{},
shstrtab: []const u8 = &.{},

atom_table: std.AutoHashMapUnmanaged(u32, *Atom) = .{},

symtab_index: ?u16 = null,

pub fn deinit(self: *Object, allocator: Allocator) void {
    self.shdrs.deinit(allocator);
    self.sections.deinit(allocator);
    self.relocs.deinit(allocator);
    self.symtab.deinit(allocator);
    self.atom_table.deinit(allocator);
    allocator.free(self.name);
    allocator.free(self.data);
}

pub fn parse(self: *Object, allocator: Allocator, cpu_arch: std.Target.Cpu.Arch) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);

    if (!mem.eql(u8, self.header.e_ident[0..4], "\x7fELF")) {
        log.debug("Invalid ELF magic {s}, expected \x7fELF", .{self.header.e_ident[0..4]});
        return error.NotObject;
    }
    if (self.header.e_ident[elf.EI_VERSION] != 1) {
        log.debug("Unknown ELF version {d}, expected 1", .{self.header.e_ident[elf.EI_VERSION]});
        return error.NotObject;
    }
    if (self.header.e_ident[elf.EI_DATA] != elf.ELFDATA2LSB) {
        log.err("TODO big endian support", .{});
        return error.TODOBigEndianSupport;
    }
    if (self.header.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) {
        log.err("TODO 32bit support", .{});
        return error.TODOElf32bitSupport;
    }
    if (self.header.e_type != elf.ET.REL) {
        log.debug("Invalid file type {any}, expected ET.REL", .{self.header.e_type});
        return error.NotObject;
    }
    if (self.header.e_machine != cpu_arch.toElfMachine()) {
        log.debug("Invalid architecture {any}, expected {any}", .{
            self.header.e_machine,
            cpu_arch.toElfMachine(),
        });
        return error.InvalidCpuArch;
    }
    if (self.header.e_version != 1) {
        log.debug("Invalid ELF version {d}, expected 1", .{self.header.e_version});
        return error.NotObject;
    }

    assert(self.header.e_entry == 0);
    assert(self.header.e_phoff == 0);
    assert(self.header.e_phnum == 0);

    const shnum = self.header.e_shnum;
    if (shnum == 0) return;

    try reader.context.seekTo(self.header.e_shoff);
    try self.shdrs.ensureTotalCapacityPrecise(allocator, shnum);

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
    self.shstrtab = self.readShdrContents(self.header.e_shstrndx);

    try self.parseSymtab(allocator);
}

fn parseSymtab(self: *Object, allocator: Allocator) !void {
    const symtab_index = self.symtab_index orelse return;
    const symtab_shdr = self.shdrs.items[symtab_index];
    self.strtab = self.readShdrContents(@intCast(u16, symtab_shdr.sh_link));
    try self.symtab.appendSlice(allocator, self.getSourceSymtab());
}

pub fn getSourceSymtab(self: Object) []const elf.Elf64_Sym {
    const index = self.symtab_index orelse return &[0]elf.Elf64_Sym{};
    const raw_symtab = self.readShdrContents(index);
    return mem.bytesAsSlice(elf.Elf64_Sym, @alignCast(@alignOf(elf.Elf64_Sym), raw_symtab));
}

pub fn getSourceSymbol(self: Object, index: u32) ?elf.Elf64_Sym {
    const symtab = self.getSourceSymtab();
    return symtab[index];
}

pub fn getSourceShdr(self: Object, index: u16) elf.Elf64_Shdr {
    assert(index < self.shdrs.items.len);
    return self.shdrs.items[index];
}

pub fn getSourceSymbolName(self: Object, index: u32) []const u8 {
    const sym = self.getSourceSymbol(index).?;
    if (sym.st_info & 0xf == elf.STT_SECTION) {
        const shdr = self.shdrs.items[sym.st_shndx];
        return self.getShString(shdr.sh_name);
    } else {
        return self.getString(sym.st_name);
    }
}

pub fn getSymbolPtr(self: *Object, index: u32) *elf.Elf64_Sym {
    return &self.symtab.items[index];
}

pub fn getSymbol(self: Object, index: u32) elf.Elf64_Sym {
    return self.symtab.items[index];
}

pub fn getSymbolName(self: Object, index: u32) []const u8 {
    const sym = self.getSymbol(index);
    return self.getString(sym.st_name);
}

pub fn parseIntoAtoms(self: *Object, allocator: Allocator, object_id: u16, elf_file: *Elf) !void {
    log.debug("parsing '{s}' into atoms", .{self.name});

    var symbols_by_shndx = std.AutoHashMap(u16, std.ArrayList(u32)).init(allocator);
    defer {
        var it = symbols_by_shndx.valueIterator();
        while (it.next()) |value| {
            value.deinit();
        }
        symbols_by_shndx.deinit();
    }

    for (self.sections.items) |ndx| {
        try symbols_by_shndx.putNoClobber(ndx, std.ArrayList(u32).init(allocator));
    }
    for (self.getSourceSymtab()) |sym, sym_id| {
        if (sym.st_shndx == elf.SHN_UNDEF) continue;
        if (elf.SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < elf.SHN_HIRESERVE) continue;
        const map = symbols_by_shndx.getPtr(sym.st_shndx) orelse continue;
        try map.append(@intCast(u32, sym_id));
    }

    for (self.sections.items) |ndx| {
        const shdr = self.getSourceShdr(ndx);
        const shdr_name = self.getShString(shdr.sh_name);

        log.debug("  parsing section '{s}'", .{shdr_name});

        if (shdr.sh_flags & elf.SHF_GROUP != 0) {
            log.err("section '{s}' is part of a section group", .{shdr_name});
            return error.HandleSectionGroups;
        }

        const tshdr_ndx = (try elf_file.getMatchingSection(object_id, ndx)) orelse {
            log.debug("unhandled section", .{});
            continue;
        };

        const syms = symbols_by_shndx.get(ndx).?;

        const atom = try Atom.createEmpty(allocator);
        errdefer {
            atom.deinit(allocator);
            allocator.destroy(atom);
        }
        try elf_file.managed_atoms.append(allocator, atom);

        atom.file = object_id;
        atom.size = @intCast(u32, shdr.sh_size);
        atom.alignment = @intCast(u32, shdr.sh_addralign);

        // TODO if --gc-sections and there is exactly one contained symbol,
        // we can prune the main one. For example, in this situation we
        // get something like this:
        //
        // .text.__udivti3
        //    => __udivti3
        //
        // which can be pruned to:
        //
        // __udivti3
        var local_sym_index: ?u32 = null;

        for (syms.items) |sym_id| {
            const sym = self.getSourceSymbol(sym_id).?;
            const is_sect_sym = sym.st_info & 0xf == elf.STT_SECTION;
            if (is_sect_sym) {
                const osym = self.getSymbolPtr(sym_id);
                osym.* = .{
                    .st_name = 0,
                    .st_info = (elf.STB_LOCAL << 4) | elf.STT_OBJECT,
                    .st_other = 0,
                    .st_shndx = 0,
                    .st_value = 0,
                    .st_size = sym.st_size,
                };
                local_sym_index = sym_id;
                continue;
            }
            try atom.contained.append(allocator, .{
                .local_sym_index = sym_id,
                .offset = sym.st_value,
            });
            try self.atom_table.putNoClobber(allocator, sym_id, atom);
        }

        atom.local_sym_index = local_sym_index orelse blk: {
            const sym_index = @intCast(u32, self.symtab.items.len);
            try self.symtab.append(allocator, .{
                .st_name = 0,
                .st_info = (elf.STB_LOCAL << 4) | elf.STT_OBJECT,
                .st_other = 0,
                .st_shndx = 0,
                .st_value = 0,
                .st_size = atom.size,
            });
            break :blk sym_index;
        };
        try self.atom_table.putNoClobber(allocator, atom.local_sym_index, atom);

        var code = if (shdr.sh_type == elf.SHT_NOBITS) blk: {
            var code = try allocator.alloc(u8, atom.size);
            mem.set(u8, code, 0);
            break :blk code;
        } else try allocator.dupe(u8, self.readShdrContents(ndx));
        defer allocator.free(code);

        if (self.relocs.get(ndx)) |rel_ndx| {
            const rel_shdr = self.getSourceShdr(rel_ndx);
            const raw_relocs = self.readShdrContents(rel_ndx);

            const nrelocs = @divExact(rel_shdr.sh_size, rel_shdr.sh_entsize);
            try atom.relocs.ensureTotalCapacityPrecise(allocator, nrelocs);

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
                const tsym_name = self.getSourceSymbolName(rel.r_sym());
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
                            rel.r_addend = 0;
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
            last.*.?.next = atom;
            atom.prev = last.*.?;
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
    assert(off < self.strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.ptr + off), 0);
}

pub fn getShString(self: Object, off: u32) []const u8 {
    assert(off < self.shstrtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.shstrtab.ptr + off), 0);
}

fn readShdrContents(self: Object, shdr_index: u16) []const u8 {
    const shdr = self.shdrs.items[shdr_index];
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}
