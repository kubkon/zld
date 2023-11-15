pub fn flush(elf_file: *Elf) !void {
    claimUnresolved(elf_file);
    try initSections(elf_file);
    try elf_file.sortSections();
    try elf_file.addAtomsToSections();
    try calcSectionSizes(elf_file);

    allocateSections(elf_file, @sizeOf(elf.Elf64_Ehdr));
    // self.allocateAtoms();
    // self.allocateLocals();
    // self.allocateGlobals();
    // self.allocateSyntheticSymbols();

    elf_file.shoff = blk: {
        const shdr = elf_file.sections.items(.shdr)[elf_file.sections.len - 1];
        const offset = shdr.sh_offset + shdr.sh_size;
        break :blk mem.alignForward(u64, offset, @alignOf(elf.Elf64_Shdr));
    };

    state_log.debug("{}", .{elf_file.dumpState()});

    // try self.writeAtomsRelocatable();
    try writeSyntheticSections(elf_file);
    try elf_file.writeShdrs();
    try writeHeader(elf_file);

    elf_file.base.reportWarningsAndErrorsAndExit();
}

fn claimUnresolved(elf_file: *Elf) void {
    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;
        const first_global = object.first_global orelse return;
        for (object.getGlobals(), 0..) |global_index, i| {
            const sym_idx = @as(u32, @intCast(first_global + i));
            const sym = object.symtab[sym_idx];
            if (sym.st_shndx != elf.SHN_UNDEF) continue;

            const global = elf_file.getSymbol(global_index);
            if (global.getFile(elf_file)) |_| {
                if (global.getSourceSymbol(elf_file).st_shndx != elf.SHN_UNDEF) continue;
            }

            global.value = 0;
            global.atom = 0;
            global.sym_idx = sym_idx;
            global.file = object.index;
        }
    }
}

fn initSections(elf_file: *Elf) !void {
    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;

        for (object.atoms.items) |atom_index| {
            const atom = elf_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_shndx = try object.initOutputSection(elf_file, atom.getInputShdr(elf_file));

            const rela_shdr = object.getShdrs()[atom.relocs_shndx];
            if (rela_shdr.sh_type != elf.SHT_NULL) {
                const out_rela_shndx = try object.initOutputSection(elf_file, rela_shdr);
                const out_rela_shdr = &elf_file.sections.items(.shdr)[out_rela_shndx];
                out_rela_shdr.sh_flags |= elf.SHF_INFO_LINK;
                out_rela_shdr.sh_addralign = @alignOf(elf.Elf64_Rela);
                out_rela_shdr.sh_entsize = @sizeOf(elf.Elf64_Rela);
                elf_file.sections.items(.rela_shndx)[atom.out_shndx] = out_rela_shndx;
            }
        }
    }

    const needs_eh_frame = for (elf_file.objects.items) |index| {
        if (elf_file.getFile(index).?.object.cies.items.len > 0) break true;
    } else false;
    if (needs_eh_frame) {
        elf_file.eh_frame_sect_index = try elf_file.addSection(.{
            .name = ".eh_frame",
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_PROGBITS,
            .addralign = @alignOf(u64),
        });
        elf_file.sections.items(.rela_shndx)[elf_file.eh_frame_sect_index.?] = try elf_file.addSection(.{
            .name = ".rela.eh_frame",
            .type = elf.SHT_RELA,
            .flags = elf.SHF_INFO_LINK,
            .entsize = @sizeOf(elf.Elf64_Rela),
            .addralign = @alignOf(elf.Elf64_Rela),
        });
    }

    try initComdatGroups(elf_file);
    try elf_file.initSymtab();
    try elf_file.initShStrtab();
}

fn initComdatGroups(elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;

        for (object.comdat_groups.items) |cg_index| {
            const cg = elf_file.getComdatGroup(cg_index);
            const cg_owner = elf_file.getComdatGroupOwner(cg.owner);
            if (cg_owner.file != index) continue;

            const cg_sec = try elf_file.comdat_group_sections.addOne(gpa);
            cg_sec.* = .{
                .shndx = try elf_file.addSection(.{
                    .name = ".group",
                    .type = elf.SHT_GROUP,
                    .entsize = @sizeOf(u32),
                    .addralign = @alignOf(u32),
                }),
                .cg_index = cg_index,
            };
        }
    }
}

fn calcSectionSizes(elf_file: *Elf) !void {
    for (
        elf_file.sections.items(.shdr),
        elf_file.sections.items(.atoms),
        elf_file.sections.items(.rela_shndx),
    ) |*shdr, atoms, rela_shndx| {
        if (atoms.items.len == 0) continue;

        const rela_shdr = if (rela_shndx != 0) &elf_file.sections.items(.shdr)[rela_shndx] else null;

        for (atoms.items) |atom_index| {
            const atom = elf_file.getAtom(atom_index).?;
            const alignment = try math.powi(u64, 2, atom.alignment);
            const offset = mem.alignForward(u64, shdr.sh_size, alignment);
            const padding = offset - shdr.sh_size;
            atom.value = offset;
            shdr.sh_size += padding + atom.size;
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);

            if (rela_shdr) |rshdr| {
                rshdr.sh_size += rshdr.sh_entsize * atom.getRelocs(elf_file).len;
            }
        }
    }

    if (elf_file.eh_frame_sect_index) |index| {
        const shdr = &elf_file.sections.items(.shdr)[index];
        shdr.sh_size = try eh_frame.calcEhFrameSize(elf_file);
        shdr.sh_addralign = @alignOf(u64);

        const rela_shndx = elf_file.sections.items(.rela_shndx)[index];
        const rela_shdr = &elf_file.sections.items(.shdr)[rela_shndx];
        rela_shdr.sh_size = eh_frame.calcEhFrameRelocs(elf_file) * rela_shdr.sh_entsize;
    }

    try elf_file.calcSymtabSize();
    calcComdatGroupsSizes(elf_file);

    if (elf_file.shstrtab_sect_index) |index| {
        const shdr = &elf_file.sections.items(.shdr)[index];
        shdr.sh_size = elf_file.shstrtab.buffer.items.len;
    }
}

fn calcComdatGroupsSizes(elf_file: *Elf) void {
    for (elf_file.comdat_group_sections.items) |cg| {
        const shdr = &elf_file.sections.items(.shdr)[cg.shndx];
        shdr.sh_size = cg.size(elf_file);
        shdr.sh_link = elf_file.symtab_sect_index.?;

        const sym = elf_file.getSymbol(cg.getSymbol(elf_file));
        shdr.sh_info = sym.getOutputSymtabIndex(elf_file) orelse
            elf_file.sections.items(.sym_index)[sym.shndx];
    }
}

fn allocateSections(elf_file: *Elf, base_offset: u64) void {
    const shdrs = elf_file.sections.slice().items(.shdr)[1..];
    var offset = base_offset;
    for (shdrs) |*shdr| {
        if (Elf.shdrIsZerofill(shdr)) continue;
        shdr.sh_offset = mem.alignForward(u64, offset, shdr.sh_addralign);
        offset = shdr.sh_offset + shdr.sh_size;
    }
}

fn writeSyntheticSections(elf_file: *Elf) !void {
    try elf_file.writeSymtab();

    if (elf_file.shstrtab_sect_index) |shndx| {
        const shdr = elf_file.sections.items(.shdr)[shndx];
        try elf_file.base.file.pwriteAll(elf_file.shstrtab.buffer.items, shdr.sh_offset);
    }
}

fn writeHeader(elf_file: *Elf) !void {
    var header = elf.Elf64_Ehdr{
        .e_ident = undefined,
        .e_type = .REL,
        .e_machine = elf_file.options.cpu_arch.?.toElfMachine(),
        .e_version = 1,
        .e_entry = 0,
        .e_phoff = 0,
        .e_shoff = elf_file.shoff,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = 0,
        .e_phnum = 0,
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @as(u16, @intCast(elf_file.sections.items(.shdr).len)),
        .e_shstrndx = elf_file.shstrtab_sect_index.?,
    };
    // Magic
    mem.copy(u8, header.e_ident[0..4], "\x7fELF");
    // Class
    header.e_ident[4] = elf.ELFCLASS64;
    // Endianness
    header.e_ident[5] = elf.ELFDATA2LSB;
    // ELF version
    header.e_ident[6] = 1;
    // OS ABI, often set to 0 regardless of target platform
    // ABI Version, possibly used by glibc but not by static executables
    // padding
    @memset(header.e_ident[7..][0..9], 0);
    log.debug("writing ELF header {} at 0x{x}", .{ header, 0 });
    try elf_file.base.file.pwriteAll(mem.asBytes(&header), 0);
}

const eh_frame = @import("eh_frame.zig");
const elf = std.elf;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;
const state_log = std.log.scoped(.state);
const std = @import("std");

const Elf = @import("../Elf.zig");
