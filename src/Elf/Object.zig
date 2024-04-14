archive: ?Archive = null,
path: []const u8,
file_handle: File.HandleIndex,
index: File.Index,

header: ?elf.Elf64_Ehdr = null,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
shstrtab: StringTable = .{},
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
first_global: ?Symbol.Index = null,

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
comdat_groups: std.ArrayListUnmanaged(Elf.ComdatGroup.Index) = .{},
comdat_group_data: std.ArrayListUnmanaged(u32) = .{},
relocs: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},

merge_sections: std.ArrayListUnmanaged(InputMergeSection.Index) = .{},

fdes: std.ArrayListUnmanaged(Fde) = .{},
cies: std.ArrayListUnmanaged(Cie) = .{},
eh_frame_data: std.ArrayListUnmanaged(u8) = .{},

needs_exec_stack: bool = false,
alive: bool = true,
num_dynrelocs: u32 = 0,

output_symtab_ctx: Elf.SymtabCtx = .{},

pub fn isValidHeader(header: *const elf.Elf64_Ehdr) bool {
    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) return false;
    if (header.e_ident[elf.EI_VERSION] != 1) return false;
    if (header.e_type != elf.ET.REL) return false;
    if (header.e_version != 1) return false;
    return true;
}

pub fn deinit(self: *Object, allocator: Allocator) void {
    if (self.archive) |*ar| allocator.free(ar.path);
    allocator.free(self.path);
    self.shdrs.deinit(allocator);
    self.shstrtab.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.atoms.deinit(allocator);
    self.comdat_groups.deinit(allocator);
    self.comdat_group_data.deinit(allocator);
    self.relocs.deinit(allocator);
    self.fdes.deinit(allocator);
    self.cies.deinit(allocator);
    self.merge_sections.deinit(allocator);
}

pub fn parse(self: *Object, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = elf_file.base.allocator;
    const offset = if (self.archive) |ar| ar.offset else 0;
    const file = elf_file.getFileHandle(self.file_handle);
    const file_size = (try file.stat()).size;

    const header_buffer = try Elf.preadAllAlloc(gpa, file, offset, @sizeOf(elf.Elf64_Ehdr));
    defer gpa.free(header_buffer);
    self.header = @as(*align(1) const elf.Elf64_Ehdr, @ptrCast(header_buffer)).*;

    if (self.header.?.e_shnum == 0) return;

    const shdrs_size = @as(usize, @intCast(self.header.?.e_shnum)) * @sizeOf(elf.Elf64_Shdr);
    if (file_size < self.header.?.e_shoff + offset or file_size < self.header.?.e_shoff + offset + shdrs_size) {
        elf_file.base.fatal("{}: corrupt header: section header table extends past the end of file", .{
            self.fmtPath(),
        });
        return error.ParseFailed;
    }

    const shdrs_buffer = try Elf.preadAllAlloc(gpa, file, offset + self.header.?.e_shoff, shdrs_size);
    defer gpa.free(shdrs_buffer);
    const shdrs = @as([*]align(1) const elf.Elf64_Shdr, @ptrCast(shdrs_buffer.ptr))[0..self.header.?.e_shnum];
    try self.shdrs.appendUnalignedSlice(gpa, shdrs);

    const shstrtab = try self.preadShdrContentsAlloc(gpa, file, self.header.?.e_shstrndx);
    defer gpa.free(shstrtab);
    try self.shstrtab.buffer.appendSlice(gpa, shstrtab);

    const symtab_index = for (self.shdrs.items, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_SYMTAB => break @as(u32, @intCast(i)),
        else => {},
    } else null;

    if (symtab_index) |index| {
        const shdr = self.shdrs.items[index];
        self.first_global = shdr.sh_info;

        const symtab = try self.preadShdrContentsAlloc(gpa, file, index);
        defer gpa.free(symtab);
        const nsyms = math.divExact(usize, symtab.len, @sizeOf(elf.Elf64_Sym)) catch {
            elf_file.base.fatal("{}: symbol table not evenly divisible", .{self.fmtPath()});
            return error.ParseFailed;
        };
        try self.symtab.appendUnalignedSlice(gpa, @as([*]align(1) const elf.Elf64_Sym, @ptrCast(symtab.ptr))[0..nsyms]);

        const strtab = try self.preadShdrContentsAlloc(gpa, file, shdr.sh_link);
        defer gpa.free(strtab);
        try self.strtab.appendSlice(gpa, strtab);
    }

    try self.initAtoms(gpa, file, elf_file);
    try self.initSymtab(gpa, elf_file);

    for (self.shdrs.items, 0..) |shdr, i| {
        const atom = elf_file.getAtom(self.atoms.items[i]) orelse continue;
        if (!atom.flags.alive) continue;
        if ((elf_file.options.cpu_arch.? == .x86_64 and shdr.sh_type == elf.SHT_X86_64_UNWIND) or
            mem.eql(u8, atom.getName(elf_file), ".eh_frame"))
        {
            try self.parseEhFrame(gpa, file, @as(u32, @intCast(i)), elf_file);
        }
    }
}

fn initAtoms(self: *Object, allocator: Allocator, file: std.fs.File, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const shdrs = self.shdrs.items;
    try self.atoms.resize(allocator, shdrs.len);
    @memset(self.atoms.items, 0);

    for (shdrs, 0..) |shdr, i| {
        if (shdr.sh_flags & elf.SHF_EXCLUDE != 0 and
            shdr.sh_flags & elf.SHF_ALLOC == 0 and
            shdr.sh_type != elf.SHT_LLVM_ADDRSIG) continue;

        switch (shdr.sh_type) {
            elf.SHT_GROUP => {
                if (shdr.sh_info >= self.symtab.items.len) {
                    elf_file.base.fatal("{}: invalid symbol index in sh_info", .{self.fmtPath()});
                    return error.ParseFailed;
                }
                const group_info_sym = self.symtab.items[shdr.sh_info];
                const group_signature = blk: {
                    if (group_info_sym.st_name == 0 and group_info_sym.st_type() == elf.STT_SECTION) {
                        const sym_shdr = shdrs[group_info_sym.st_shndx];
                        break :blk self.getShString(sym_shdr.sh_name);
                    }
                    break :blk self.getString(group_info_sym.st_name);
                };

                const group_raw_data = try self.preadShdrContentsAlloc(allocator, file, @intCast(i));
                defer allocator.free(group_raw_data);
                const group_nmembers = @divExact(group_raw_data.len, @sizeOf(u32));
                const group_members = @as([*]align(1) const u32, @ptrCast(group_raw_data.ptr))[0..group_nmembers];

                if (group_members[0] != 0x1) { // GRP_COMDAT
                    elf_file.base.fatal("{}: unknown SHT_GROUP format", .{self.fmtPath()});
                    return error.ParseFailed;
                }

                const group_start = @as(u32, @intCast(self.comdat_group_data.items.len));
                try self.comdat_group_data.appendUnalignedSlice(allocator, group_members[1..]);

                const group_signature_off = try elf_file.internString("{s}", .{group_signature});
                const gop = try elf_file.getOrCreateComdatGroupOwner(group_signature_off);
                const comdat_group_index = try elf_file.addComdatGroup();
                const comdat_group = elf_file.getComdatGroup(comdat_group_index);
                comdat_group.* = .{
                    .owner = gop.index,
                    .file = self.index,
                    .shndx = @intCast(i),
                    .members_start = group_start,
                    .members_len = @intCast(group_nmembers - 1),
                };
                try self.comdat_groups.append(allocator, comdat_group_index);
            },

            elf.SHT_SYMTAB_SHNDX => @panic("TODO"),

            elf.SHT_NULL,
            elf.SHT_REL,
            elf.SHT_RELA,
            elf.SHT_SYMTAB,
            elf.SHT_STRTAB,
            => {},

            else => {
                const name = self.getShString(shdr.sh_name);
                const shndx = @as(u32, @intCast(i));

                if (mem.eql(u8, ".note.GNU-stack", name)) {
                    if (shdr.sh_flags & elf.SHF_EXECINSTR != 0) {
                        if (!elf_file.options.z_execstack or !elf_file.options.z_execstack_if_needed) {
                            elf_file.base.warn(
                                "{}: may cause segmentation fault as this file requested executable stack",
                                .{self.fmtPath()},
                            );
                        }
                        self.needs_exec_stack = true;
                    }
                    continue;
                }

                if (self.skipShdr(shndx, elf_file)) continue;
                try self.addAtom(allocator, file, shdr, shndx, name, elf_file);
            },
        }
    }

    // Parse relocs sections if any.
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_REL, elf.SHT_RELA => {
            const atom_index = self.atoms.items[shdr.sh_info];
            if (elf_file.getAtom(atom_index)) |atom| {
                const relocs = try self.preadRelocsAlloc(allocator, file, @intCast(i));
                defer allocator.free(relocs);
                atom.relocs_shndx = @intCast(i);
                const rel_index: u32 = @intCast(self.relocs.items.len);
                const rel_count: u32 = @intCast(relocs.len);
                try atom.addExtra(.{ .rel_index = rel_index, .rel_count = rel_count }, elf_file);
                try self.relocs.appendUnalignedSlice(allocator, relocs);
                sortRelocs(self.relocs.items[rel_index..][0..rel_count], elf_file);
            }
        },
        else => {},
    };
}

fn addAtom(self: *Object, allocator: Allocator, file: std.fs.File, shdr: elf.Elf64_Shdr, shndx: u32, name: [:0]const u8, elf_file: *Elf) !void {
    const atom_index = try elf_file.addAtom();
    const atom = elf_file.getAtom(atom_index).?;
    atom.atom_index = atom_index;
    atom.name = try elf_file.string_intern.insert(elf_file.base.allocator, name);
    atom.file = self.index;
    atom.shndx = shndx;
    self.atoms.items[shndx] = atom_index;

    if (shdr.sh_flags & elf.SHF_COMPRESSED != 0) {
        const data = try self.preadShdrContentsAlloc(allocator, file, shndx);
        defer allocator.free(data);
        const chdr = @as(*align(1) const elf.Elf64_Chdr, @ptrCast(data.ptr)).*;
        atom.size = chdr.ch_size;
        atom.alignment = math.log2_int(u64, chdr.ch_addralign);
    } else {
        atom.size = shdr.sh_size;
        atom.alignment = math.log2_int(u64, shdr.sh_addralign);
    }
}

fn skipShdr(self: *Object, index: u32, elf_file: *Elf) bool {
    const shdr = self.shdrs.items[index];
    const name = self.getShString(shdr.sh_name);
    const ignore = blk: {
        if (mem.startsWith(u8, name, ".note")) break :blk true;
        if (mem.startsWith(u8, name, ".llvm_addrsig")) break :blk true;
        if (mem.startsWith(u8, name, ".riscv.attributes")) break :blk true; // TODO: riscv attributes
        if ((elf_file.options.strip_debug or elf_file.options.strip_all) and
            shdr.sh_flags & elf.SHF_ALLOC == 0 and
            mem.startsWith(u8, name, ".debug")) break :blk true;
        break :blk false;
    };
    return ignore;
}

fn initSymtab(self: *Object, allocator: Allocator, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const first_global = self.first_global orelse self.symtab.items.len;
    const shdrs = self.shdrs.items;

    try self.symbols.ensureTotalCapacityPrecise(allocator, self.symtab.items.len);

    for (self.symtab.items[0..first_global], 0..) |sym, i| {
        const index = try elf_file.addSymbol();
        self.symbols.appendAssumeCapacity(index);
        const symbol = elf_file.getSymbol(index);
        const name = blk: {
            if (sym.st_name == 0 and sym.st_type() == elf.STT_SECTION) {
                const shdr = shdrs[sym.st_shndx];
                break :blk self.getShString(shdr.sh_name);
            }
            break :blk self.getString(sym.st_name);
        };
        symbol.* = .{
            .value = @intCast(sym.st_value),
            .name = try elf_file.string_intern.insert(elf_file.base.allocator, name),
            .sym_idx = @as(u32, @intCast(i)),
            .atom = if (sym.st_shndx == elf.SHN_ABS) 0 else self.atoms.items[sym.st_shndx],
            .file = self.index,
        };
    }

    for (self.symtab.items[first_global..]) |sym| {
        const name = self.getString(sym.st_name);
        const off = try elf_file.internString("{s}", .{name});
        const gop = try elf_file.getOrCreateGlobal(off);
        self.symbols.addOneAssumeCapacity().* = gop.index;
    }
}

pub fn initOutputSection(self: Object, elf_file: *Elf, shdr: elf.Elf64_Shdr) !u32 {
    const name = blk: {
        const name = self.getShString(shdr.sh_name);
        if (elf_file.options.relocatable) break :blk name;
        const sh_name_prefixes: []const [:0]const u8 = &.{
            ".text",       ".data.rel.ro", ".data", ".rodata", ".bss.rel.ro",       ".bss",
            ".init_array", ".fini_array",  ".tbss", ".tdata",  ".gcc_except_table", ".ctors",
            ".dtors",      ".gnu.warning",
        };
        inline for (sh_name_prefixes) |prefix| {
            if (std.mem.eql(u8, name, prefix) or std.mem.startsWith(u8, name, prefix ++ ".")) {
                break :blk prefix;
            }
        }
        break :blk name;
    };
    const @"type" = tt: {
        if (elf_file.options.cpu_arch.? == .x86_64 and shdr.sh_type == elf.SHT_X86_64_UNWIND) break :tt elf.SHT_PROGBITS;

        const @"type" = switch (shdr.sh_type) {
            elf.SHT_NULL => unreachable,
            elf.SHT_PROGBITS => blk: {
                if (std.mem.eql(u8, name, ".init_array") or std.mem.startsWith(u8, name, ".init_array."))
                    break :blk elf.SHT_INIT_ARRAY;
                if (std.mem.eql(u8, name, ".fini_array") or std.mem.startsWith(u8, name, ".fini_array."))
                    break :blk elf.SHT_FINI_ARRAY;
                break :blk shdr.sh_type;
            },
            else => shdr.sh_type,
        };
        break :tt @"type";
    };
    const flags = blk: {
        var flags = shdr.sh_flags;
        if (!elf_file.options.relocatable) {
            flags &= ~@as(u64, elf.SHF_COMPRESSED | elf.SHF_GROUP | elf.SHF_GNU_RETAIN);
        }
        break :blk switch (@"type") {
            elf.SHT_INIT_ARRAY, elf.SHT_FINI_ARRAY => flags | elf.SHF_WRITE,
            else => flags,
        };
    };
    return elf_file.getSectionByName(name) orelse try elf_file.addSection(.{
        .type = @"type",
        .flags = flags,
        .name = name,
    });
}

fn parseEhFrame(self: *Object, allocator: Allocator, file: std.fs.File, shndx: u32, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const relocs_shndx = for (self.shdrs.items, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_RELA => if (shdr.sh_info == shndx) break @as(u32, @intCast(i)),
        else => {},
    } else null;

    const raw = try self.preadShdrContentsAlloc(allocator, file, shndx);
    defer allocator.free(raw);
    const data_start = @as(u32, @intCast(self.eh_frame_data.items.len));
    try self.eh_frame_data.appendSlice(allocator, raw);
    const relocs = if (relocs_shndx) |index|
        try self.preadRelocsAlloc(allocator, file, index)
    else
        &[0]elf.Elf64_Rela{};
    defer allocator.free(relocs);
    const rel_start = @as(u32, @intCast(self.relocs.items.len));
    try self.relocs.appendUnalignedSlice(allocator, relocs);
    sortRelocs(self.relocs.items[rel_start..][0..relocs.len], elf_file);
    const fdes_start = self.fdes.items.len;
    const cies_start = self.cies.items.len;

    var it = eh_frame.Iterator{ .data = self.eh_frame_data.items };
    while (try it.next()) |rec| {
        const rel_range = filterRelocs(self.relocs.items[rel_start..][0..relocs.len], rec.offset, rec.size + 4);
        switch (rec.tag) {
            .cie => try self.cies.append(allocator, .{
                .offset = data_start + rec.offset,
                .size = rec.size,
                .rel_index = rel_start + @as(u32, @intCast(rel_range.start)),
                .rel_num = @as(u32, @intCast(rel_range.len)),
                .shndx = shndx,
                .file = self.index,
            }),
            .fde => try self.fdes.append(allocator, .{
                .offset = data_start + rec.offset,
                .size = rec.size,
                .cie_index = undefined,
                .rel_index = rel_start + @as(u32, @intCast(rel_range.start)),
                .rel_num = @as(u32, @intCast(rel_range.len)),
                .shndx = shndx,
                .file = self.index,
            }),
        }
    }

    // Tie each FDE to its CIE
    for (self.fdes.items[fdes_start..]) |*fde| {
        const cie_ptr = fde.offset + 4 - fde.getCiePointer(elf_file);
        const cie_index = for (self.cies.items[cies_start..], cies_start..) |cie, cie_index| {
            if (cie.offset == cie_ptr) break @as(u32, @intCast(cie_index));
        } else {
            elf_file.base.fatal("{s}: no matching CIE found for FDE at offset {x}", .{
                self.fmtPath(),
                fde.offset,
            });
            return error.ParseFailed;
        };
        fde.cie_index = cie_index;
    }

    // Tie each FDE record to its matching atom
    const SortFdes = struct {
        pub fn lessThan(ctx: *Elf, lhs: Fde, rhs: Fde) bool {
            const lhs_atom = lhs.getAtom(ctx);
            const rhs_atom = rhs.getAtom(ctx);
            return lhs_atom.getPriority(ctx) < rhs_atom.getPriority(ctx);
        }
    };
    mem.sort(Fde, self.fdes.items[fdes_start..], elf_file, SortFdes.lessThan);

    // Create a back-link from atom to FDEs
    var i: u32 = @as(u32, @intCast(fdes_start));
    while (i < self.fdes.items.len) {
        const fde = self.fdes.items[i];
        const atom = fde.getAtom(elf_file);
        const start = i;
        i += 1;
        while (i < self.fdes.items.len) : (i += 1) {
            const next_fde = self.fdes.items[i];
            if (atom.atom_index != next_fde.getAtom(elf_file).atom_index) break;
        }
        try atom.addExtra(.{ .fde_start = start, .fde_count = i - start }, elf_file);
        atom.flags.fde = true;
    }
}

fn sortRelocs(relocs: []elf.Elf64_Rela, ctx: *Elf) void {
    const sortFn = struct {
        fn lessThan(c: void, lhs: elf.Elf64_Rela, rhs: elf.Elf64_Rela) bool {
            _ = c;
            return lhs.r_offset < rhs.r_offset;
        }
    }.lessThan;

    if (ctx.options.cpu_arch.? == .riscv64) {
        mem.sort(elf.Elf64_Rela, relocs, {}, sortFn);
    }
}

fn filterRelocs(
    relocs: []const elf.Elf64_Rela,
    start: u64,
    len: u64,
) struct { start: u64, len: u64 } {
    const tracy = trace(@src());
    defer tracy.end();

    const Predicate = struct {
        value: u64,

        pub fn predicate(self: @This(), rel: elf.Elf64_Rela) bool {
            return rel.r_offset < self.value;
        }
    };
    const LPredicate = struct {
        value: u64,

        pub fn predicate(self: @This(), rel: elf.Elf64_Rela) bool {
            return rel.r_offset >= self.value;
        }
    };

    const f_start = Zld.binarySearch(elf.Elf64_Rela, relocs, Predicate{ .value = start });
    const f_len = Zld.linearSearch(elf.Elf64_Rela, relocs[f_start..], LPredicate{ .value = start + len });

    return .{ .start = f_start, .len = f_len };
}

pub fn scanRelocs(self: *Object, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.atoms.items) |atom_index| {
        const atom = elf_file.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        const shdr = atom.getInputShdr(elf_file);
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) continue;
        try atom.scanRelocs(elf_file);
    }

    for (self.cies.items) |cie| {
        for (cie.getRelocs(elf_file)) |rel| {
            const sym = self.getSymbol(rel.r_sym(), elf_file);
            if (sym.flags.import) {
                if (sym.getType(elf_file) != elf.STT_FUNC) {
                    elf_file.base.fatal("{s}: {s}: CIE referencing external data reference", .{
                        self.fmtPath(),
                        sym.getName(elf_file),
                    });
                }
                sym.flags.plt = true;
            }
        }
    }
}

pub fn resolveSymbols(self: *Object, elf_file: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

    const first_global = self.first_global orelse return;
    for (self.getGlobals(), 0..) |index, i| {
        const sym_idx = @as(Symbol.Index, @intCast(first_global + i));
        const this_sym = self.symtab.items[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        if (this_sym.st_shndx != elf.SHN_ABS and this_sym.st_shndx != elf.SHN_COMMON) {
            const atom_index = self.atoms.items[this_sym.st_shndx];
            const atom = elf_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
        }

        const global = elf_file.getSymbol(index);
        if (self.asFile().getSymbolRank(this_sym, !self.alive) < global.getSymbolRank(elf_file)) {
            const atom = switch (this_sym.st_shndx) {
                elf.SHN_ABS, elf.SHN_COMMON => 0,
                else => self.atoms.items[this_sym.st_shndx],
            };
            global.value = @intCast(this_sym.st_value);
            global.atom = atom;
            global.sym_idx = sym_idx;
            global.file = self.index;
            global.ver_idx = elf_file.default_sym_version;
            if (this_sym.st_bind() == elf.STB_WEAK) global.flags.weak = true;
        }
    }
}

pub fn markLive(self: *Object, elf_file: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

    const first_global = self.first_global orelse return;
    for (self.getGlobals(), 0..) |index, i| {
        const sym_idx = first_global + i;
        const sym = self.symtab.items[sym_idx];
        if (sym.st_bind() == elf.STB_WEAK) continue;

        const global = elf_file.getSymbol(index);
        const file = global.getFile(elf_file) orelse continue;
        const should_keep = sym.st_shndx == elf.SHN_UNDEF or
            (sym.st_shndx == elf.SHN_COMMON and global.getSourceSymbol(elf_file).st_shndx != elf.SHN_COMMON);
        if (should_keep and !file.isAlive()) {
            file.setAlive();
            file.markLive(elf_file);
        }
    }
}

pub fn checkDuplicates(self: *Object, elf_file: *Elf) bool {
    const first_global = self.first_global orelse return false;
    var has_dupes = false;
    for (self.getGlobals(), 0..) |index, i| {
        const sym_idx = @as(Symbol.Index, @intCast(first_global + i));
        const this_sym = self.symtab.items[sym_idx];
        const global = elf_file.getSymbol(index);
        const global_file = global.getFile(elf_file) orelse continue;

        if (self.index == global_file.getIndex() or
            this_sym.st_shndx == elf.SHN_UNDEF or
            this_sym.st_bind() == elf.STB_WEAK or
            this_sym.st_shndx == elf.SHN_COMMON) continue;

        if (this_sym.st_shndx != elf.SHN_ABS) {
            const atom_index = self.atoms.items[this_sym.st_shndx];
            const atom = elf_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
        }

        elf_file.base.fatal("multiple definition: {}: {}: {s}", .{
            self.fmtPath(),
            global_file.fmtPath(),
            global.getName(elf_file),
        });
        has_dupes = true;
    }
    return has_dupes;
}

pub fn initMergeSections(self: *Object, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = elf_file.base.allocator;

    try self.merge_sections.resize(gpa, self.shdrs.items.len);
    @memset(self.merge_sections.items, 0);

    for (self.shdrs.items, 0..) |shdr, shndx| {
        if (shdr.sh_flags & elf.SHF_MERGE == 0) continue;

        const atom_index = self.atoms.items[shndx];
        const atom = elf_file.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        if (atom.getRelocs(elf_file).len > 0) continue;

        const imsec_idx = try elf_file.addInputMergeSection();
        const imsec = elf_file.getInputMergeSection(imsec_idx).?;
        self.merge_sections.items[shndx] = imsec_idx;

        imsec.merge_section = try elf_file.getOrCreateMergeSection(atom.getName(elf_file), shdr.sh_flags, shdr.sh_type);
        imsec.atom = atom_index;

        const data = try atom.getCodeUncompressAlloc(elf_file);
        defer gpa.free(data);
        const sh_entsize: u32 = @intCast(shdr.sh_entsize);

        if (shdr.sh_flags & elf.SHF_STRINGS != 0) {
            var pos: u32 = 0;
            while (pos < data.len) switch (sh_entsize) {
                0, 1 => {
                    // According to mold's source code, GHC emits MS sections with sh_entsize = 0.
                    // This actually can also happen for output created with `-r` mode.
                    const string = mem.sliceTo(@as([*:0]const u8, @ptrCast(data.ptr + pos)), 0);
                    if (pos + string.len == data.len) {
                        elf_file.base.fatal("{}:{s}: string not null terminated", .{
                            self.fmtPath(),
                            atom.getName(elf_file),
                        });
                        return error.ParseFailed;
                    }
                    try imsec.insertZ(gpa, string);
                    try imsec.offsets.append(gpa, pos);
                    pos += @as(u32, @intCast(string.len)) + 1; // account for null
                },
                else => |entsize| {
                    const string = data.ptr[pos..][0..entsize];
                    if (string[string.len - 1] != 0) {
                        elf_file.base.fatal("{}:{s}: string not null terminated", .{
                            self.fmtPath(),
                            atom.getName(elf_file),
                        });
                        return error.ParseFailed;
                    }
                    try imsec.insert(gpa, string);
                    try imsec.offsets.append(gpa, pos);
                    pos += @as(u32, @intCast(string.len));
                },
            };
        } else {
            if (sh_entsize == 0) continue; // Malformed, don't split but don't error out
            if (shdr.sh_size % sh_entsize != 0) {
                elf_file.base.fatal("{}:{s}: size not multiple of sh_entsize", .{
                    self.fmtPath(),
                    atom.getName(elf_file),
                });
                return error.ParseFailed;
            }

            var pos: u32 = 0;
            while (pos < data.len) : (pos += sh_entsize) {
                const string = data.ptr[pos..][0..sh_entsize];
                try imsec.insert(gpa, string);
                try imsec.offsets.append(gpa, pos);
            }
        }

        atom.flags.alive = false;
    }
}

pub fn resolveMergeSubsections(self: *Object, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    for (self.merge_sections.items) |index| {
        const imsec = elf_file.getInputMergeSection(index) orelse continue;
        const msec = elf_file.getMergeSection(imsec.merge_section);
        const atom = elf_file.getAtom(imsec.atom).?;
        const isec = atom.getInputShdr(elf_file);

        try imsec.subsections.resize(gpa, imsec.strings.items.len);

        for (imsec.strings.items, imsec.subsections.items) |str, *imsec_msub| {
            const string = imsec.bytes.items[str.pos..][0..str.len];
            const res = try msec.insert(gpa, string);
            if (!res.found_existing) {
                const msub_index = try elf_file.addMergeSubsection();
                const msub = elf_file.getMergeSubsection(msub_index);
                msub.merge_section = imsec.merge_section;
                msub.string_index = res.key.pos;
                msub.alignment = atom.alignment;
                msub.size = res.key.len;
                msub.alive = !elf_file.options.gc_sections or isec.sh_flags & elf.SHF_ALLOC == 0;
                res.sub.* = msub_index;
            }
            imsec_msub.* = res.sub.*;
        }

        imsec.clearAndFree(gpa);
    }

    for (self.symtab.items, 0..) |*esym, idx| {
        const sym_index = self.symbols.items[idx];
        const sym = elf_file.getSymbol(sym_index);

        if (esym.st_shndx == elf.SHN_COMMON or esym.st_shndx == elf.SHN_UNDEF or esym.st_shndx == elf.SHN_ABS) continue;

        const imsec_index = self.merge_sections.items[esym.st_shndx];
        const imsec = elf_file.getInputMergeSection(imsec_index) orelse continue;
        const msub_index, const offset = imsec.findSubsection(@intCast(esym.st_value)) orelse {
            elf_file.base.fatal("{}: invalid symbol value: {s}:{x}", .{
                self.fmtPath(),
                sym.getName(elf_file),
                esym.st_value,
            });
            return error.ParseFailed;
        };

        try sym.addExtra(.{ .subsection = msub_index }, elf_file);
        sym.flags.merge_subsection = true;
        sym.value = offset;
    }

    for (self.atoms.items) |atom_index| {
        const atom = elf_file.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        const extra = atom.getExtra(elf_file) orelse continue;
        if (extra.rel_count == 0) continue;
        const relocs = self.relocs.items[extra.rel_index..][0..extra.rel_count];
        for (relocs) |*rel| {
            const esym = self.symtab.items[rel.r_sym()];
            if (esym.st_type() != elf.STT_SECTION) continue;

            const imsec_index = self.merge_sections.items[esym.st_shndx];
            const imsec = elf_file.getInputMergeSection(imsec_index) orelse continue;
            const msub_index, const offset = imsec.findSubsection(@intCast(@as(i64, @intCast(esym.st_value)) + rel.r_addend)) orelse {
                elf_file.base.fatal("{}: {s}: invalid relocation at offset 0x{x}", .{
                    self.fmtPath(),
                    atom.getName(elf_file),
                    rel.r_offset,
                });
                return error.ParseFailed;
            };
            const msub = elf_file.getMergeSubsection(msub_index);
            const msec = msub.getMergeSection(elf_file);

            const out_sym_idx: u64 = @intCast(self.symbols.items.len);
            try self.symbols.ensureUnusedCapacity(gpa, 1);
            const name = try std.fmt.allocPrint(gpa, "{s}$subsection{d}", .{
                msec.getName(elf_file),
                msub_index,
            });
            defer gpa.free(name);
            const sym_index = try elf_file.addSymbol();
            const sym = elf_file.getSymbol(sym_index);
            sym.* = .{
                .value = @bitCast(@as(i64, @intCast(offset)) - rel.r_addend),
                .name = try elf_file.string_intern.insert(gpa, name),
                .sym_idx = rel.r_sym(),
                .file = self.index,
            };
            try sym.addExtra(.{ .subsection = msub_index }, elf_file);
            sym.flags.merge_subsection = true;
            self.symbols.addOneAssumeCapacity().* = sym_index;
            rel.r_info = (out_sym_idx << 32) | rel.r_type();
        }
    }
}

/// We will create dummy shdrs per each resolved common symbols to make it
/// play nicely with the rest of the system.
pub fn convertCommonSymbols(self: *Object, elf_file: *Elf) !void {
    const first_global = self.first_global orelse return;
    for (self.getGlobals(), 0..) |index, i| {
        const sym_idx = @as(Symbol.Index, @intCast(first_global + i));
        const this_sym = self.symtab.items[sym_idx];
        if (this_sym.st_shndx != elf.SHN_COMMON) continue;

        const global = elf_file.getSymbol(index);
        const global_file = global.getFile(elf_file).?;
        if (global_file.getIndex() != self.index) {
            if (elf_file.options.warn_common) {
                elf_file.base.warn("{}: multiple common symbols: {s}", .{
                    self.fmtPath(),
                    global.getName(elf_file),
                });
            }
            continue;
        }

        const gpa = elf_file.base.allocator;

        const atom_index = try elf_file.addAtom();
        try self.atoms.append(gpa, atom_index);

        const is_tls = global.getType(elf_file) == elf.STT_TLS;
        const name = if (is_tls) ".tls_common" else ".common";

        const atom = elf_file.getAtom(atom_index).?;
        atom.atom_index = atom_index;
        atom.name = try elf_file.string_intern.insert(gpa, name);
        atom.file = self.index;
        atom.size = this_sym.st_size;
        const alignment = this_sym.st_value;
        atom.alignment = math.log2_int(u64, alignment);

        var sh_flags: u32 = elf.SHF_ALLOC | elf.SHF_WRITE;
        if (is_tls) sh_flags |= elf.SHF_TLS;
        const shndx = @as(u32, @intCast(self.shdrs.items.len));
        const shdr = try self.shdrs.addOne(gpa);
        shdr.* = .{
            .sh_name = try self.shstrtab.insert(gpa, name),
            .sh_type = elf.SHT_NOBITS,
            .sh_flags = sh_flags,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = this_sym.st_size,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = alignment,
            .sh_entsize = 0,
        };
        atom.shndx = shndx;

        global.value = 0;
        global.atom = atom_index;
        global.flags.weak = false;
    }
}

pub fn calcSymtabSize(self: *Object, elf_file: *Elf) !void {
    if (elf_file.options.strip_all) return;

    const isAlive = struct {
        fn isAlive(sym: *const Symbol, ctx: *Elf) bool {
            if (sym.getMergeSubsection(ctx)) |msub| return msub.alive;
            if (sym.getAtom(ctx)) |atom| return atom.flags.alive;
            return true;
        }
    }.isAlive;

    if (!elf_file.options.discard_all_locals) {
        // TODO: discard temp locals
        for (self.getLocals()) |local_index| {
            const local = elf_file.getSymbol(local_index);
            if (!isAlive(local, elf_file)) continue;
            const s_sym = local.getSourceSymbol(elf_file);
            switch (s_sym.st_type()) {
                elf.STT_SECTION => continue,
                elf.STT_NOTYPE => if (s_sym.st_shndx == elf.SHN_UNDEF) continue,
                else => {},
            }
            local.flags.output_symtab = true;
            try local.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, elf_file);
            self.output_symtab_ctx.nlocals += 1;
            self.output_symtab_ctx.strsize += @as(u32, @intCast(local.getName(elf_file).len + 1));
        }
    }

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        const file_ptr = global.getFile(elf_file) orelse continue;
        if (file_ptr.getIndex() != self.index) continue;
        if (!isAlive(global, elf_file)) continue;
        global.flags.output_symtab = true;
        if (global.isLocal(elf_file)) {
            try global.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, elf_file);
            self.output_symtab_ctx.nlocals += 1;
        } else {
            try global.addExtra(.{ .symtab = self.output_symtab_ctx.nglobals }, elf_file);
            self.output_symtab_ctx.nglobals += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(global.getName(elf_file).len + 1));
    }
}

pub fn writeSymtab(self: Object, elf_file: *Elf) void {
    if (elf_file.options.strip_all) return;

    for (self.getLocals()) |local_index| {
        const local = elf_file.getSymbol(local_index);
        const idx = local.getOutputSymtabIndex(elf_file) orelse continue;
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = @intCast(elf_file.strtab.items.len);
        elf_file.strtab.appendSliceAssumeCapacity(local.getName(elf_file));
        elf_file.strtab.appendAssumeCapacity(0);
        local.setOutputSym(elf_file, out_sym);
    }

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        const file_ptr = global.getFile(elf_file) orelse continue;
        if (file_ptr.getIndex() != self.index) continue;
        const idx = global.getOutputSymtabIndex(elf_file) orelse continue;
        const st_name = @as(u32, @intCast(elf_file.strtab.items.len));
        elf_file.strtab.appendSliceAssumeCapacity(global.getName(elf_file));
        elf_file.strtab.appendAssumeCapacity(0);
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = st_name;
        global.setOutputSym(elf_file, out_sym);
    }
}

pub fn getLocals(self: Object) []const Symbol.Index {
    const end = self.first_global orelse self.symtab.items.len;
    return self.symbols.items[0..end];
}

pub fn getGlobals(self: Object) []const Symbol.Index {
    const start = self.first_global orelse return &[0]Symbol.Index{};
    return self.symbols.items[start..self.symtab.items.len];
}

pub inline fn getSymbol(self: Object, index: Symbol.Index, elf_file: *Elf) *Symbol {
    return elf_file.getSymbol(self.symbols.items[index]);
}

pub inline fn getShdrs(self: Object) []const elf.Elf64_Shdr {
    return self.shdrs.items;
}

/// Caller owns the memory.
pub fn preadShdrContentsAlloc(self: Object, allocator: Allocator, file: std.fs.File, index: u32) ![]u8 {
    assert(index < self.shdrs.items.len);
    const offset = if (self.archive) |ar| ar.offset else 0;
    const shdr = self.shdrs.items[index];
    return Elf.preadAllAlloc(allocator, file, offset + shdr.sh_offset, shdr.sh_size);
}

fn preadRelocsAlloc(self: Object, allocator: Allocator, file: std.fs.File, shndx: u32) ![]align(1) const elf.Elf64_Rela {
    const raw = try self.preadShdrContentsAlloc(allocator, file, shndx);
    const num = @divExact(raw.len, @sizeOf(elf.Elf64_Rela));
    return @as([*]align(1) const elf.Elf64_Rela, @ptrCast(raw.ptr))[0..num];
}

inline fn getString(self: Object, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

inline fn getShString(self: Object, off: u32) [:0]const u8 {
    return self.shstrtab.getAssumeExists(off);
}

pub fn asFile(self: *Object) File {
    return .{ .object = self };
}

pub fn format(
    self: *Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format objects directly");
}

pub fn fmtSymtab(self: *Object, elf_file: *Elf) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    object: *Object,
    elf_file: *Elf,
};

fn formatSymtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.writeAll("  locals\n");
    for (object.getLocals()) |index| {
        const local = ctx.elf_file.getSymbol(index);
        try writer.print("    {}\n", .{local.fmt(ctx.elf_file)});
    }
    try writer.writeAll("  globals\n");
    for (object.getGlobals()) |index| {
        const global = ctx.elf_file.getSymbol(index);
        try writer.print("    {}\n", .{global.fmt(ctx.elf_file)});
    }
}

pub fn fmtAtoms(self: *Object, elf_file: *Elf) std.fmt.Formatter(formatAtoms) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
    } };
}

fn formatAtoms(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.writeAll("  atoms\n");
    for (object.atoms.items) |atom_index| {
        const atom = ctx.elf_file.getAtom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(ctx.elf_file)});
    }
}

pub fn fmtCies(self: *Object, elf_file: *Elf) std.fmt.Formatter(formatCies) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
    } };
}

fn formatCies(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.writeAll("  cies\n");
    for (object.cies.items, 0..) |cie, i| {
        try writer.print("    cie({d}) : {}\n", .{ i, cie.fmt(ctx.elf_file) });
    }
}

pub fn fmtFdes(self: *Object, elf_file: *Elf) std.fmt.Formatter(formatFdes) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
    } };
}

fn formatFdes(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.writeAll("  fdes\n");
    for (object.fdes.items, 0..) |fde, i| {
        try writer.print("    fde({d}) : {}\n", .{ i, fde.fmt(ctx.elf_file) });
    }
}

pub fn fmtComdatGroups(self: *Object, elf_file: *Elf) std.fmt.Formatter(formatComdatGroups) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
    } };
}

fn formatComdatGroups(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    const elf_file = ctx.elf_file;
    try writer.writeAll("  comdat groups\n");
    for (object.comdat_groups.items) |cg_index| {
        const cg = elf_file.getComdatGroup(cg_index);
        const cg_owner = elf_file.getComdatGroupOwner(cg.owner);
        if (cg_owner.file != object.index) continue;
        for (cg.getComdatGroupMembers(elf_file)) |shndx| {
            const atom_index = object.atoms.items[shndx];
            const atom = elf_file.getAtom(atom_index) orelse continue;
            try writer.print("    atom({d}) : {s}\n", .{ atom_index, atom.getName(elf_file) });
        }
    }
}

pub fn fmtPath(self: *Object) std.fmt.Formatter(formatPath) {
    return .{ .data = self };
}

fn formatPath(
    object: *Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    if (object.archive) |ar| {
        try writer.writeAll(ar.path);
        try writer.writeByte('(');
        try writer.writeAll(object.path);
        try writer.writeByte(')');
    } else try writer.writeAll(object.path);
}

const Archive = struct {
    path: []const u8,
    offset: u64,
};

const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Cie = eh_frame.Cie;
const Elf = @import("../Elf.zig");
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const InputMergeSection = @import("merge_section.zig").InputMergeSection;
const StringTable = @import("../StringTable.zig");
const Symbol = @import("Symbol.zig");
const Zld = @import("../Zld.zig");
