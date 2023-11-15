pub fn flush(elf_file: *Elf) !void {
    claimUnresolved(elf_file);
    try initSections(elf_file);
    try elf_file.sortSections();
    // try self.addAtomsToSections();
    // try self.calcSectionSizesRelocatable();

    // try self.allocateSectionsRelocatable();
    // self.allocateAtoms();
    // self.allocateLocals();
    // self.allocateGlobals();
    // self.allocateSyntheticSymbols();

    // self.shoff = blk: {
    //     const shdr = self.sections.items(.shdr)[self.sections.len - 1];
    //     const offset = shdr.sh_offset + shdr.sh_size;
    //     break :blk mem.alignForward(u64, offset, @alignOf(elf.Elf64_Shdr));
    // };

    Elf.state_log.debug("{}", .{elf_file.dumpState()});

    // try self.writeAtomsRelocatable();
    // try self.writeSyntheticSectionsRelocatable();
    // try self.writeShdrs();
    // try self.writeHeader();

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
                elf_file.sections.items(.shdr)[out_rela_shndx].sh_flags |= elf.SHF_INFO_LINK;
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

// fn calcSectionSizesRelocatable(self: *Elf) !void {
//     for (self.sections.items(.shdr), self.sections.items(.atoms)) |*shdr, atoms| {
//         if (atoms.items.len == 0) continue;

//         for (atoms.items) |atom_index| {
//             const atom = self.getAtom(atom_index).?;
//             const alignment = try math.powi(u64, 2, atom.alignment);
//             const offset = mem.alignForward(u64, shdr.sh_size, alignment);
//             const padding = offset - shdr.sh_size;
//             atom.value = offset;
//             shdr.sh_size += padding + atom.size;
//             shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
//         }
//     }

//     // TODO rela sections

//     if (self.eh_frame_sect_index) |index| {
//         const shdr = &self.sections.items(.shdr)[index];
//         shdr.sh_size = try eh_frame.calcEhFrameSize(self);
//         shdr.sh_addralign = @alignOf(u64);
//     }

//     try self.calcSymtabSize();
//     self.calcComdatGroupsSizes();

//     if (self.shstrtab_sect_index) |index| {
//         const shdr = &self.sections.items(.shdr)[index];
//         shdr.sh_size = self.shstrtab.buffer.items.len;
//     }
// }

// fn calcComdatGroupsSizes(self: *Elf) void {
//     for (self.comdat_group_sections.items) |cg| {
//         const shdr = &self.sections.items(.shdr)[cg.shndx];
//         shdr.sh_size = cg.size(self);
//         shdr.sh_link = self.symtab_sect_index.?;

//         const sym = self.getSymbol(cg.getSymbol(self));
//         shdr.sh_info = sym.getOutputSymtabIndex(self) orelse
//             self.getSectionSymbolOutputSymtabIndex(sym.shndx);
//     }
// }

const elf = std.elf;
const std = @import("std");

const Elf = @import("../Elf.zig");
