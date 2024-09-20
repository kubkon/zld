archive: ?Archive = null,
path: []const u8,
file_handle: File.HandleIndex,
index: File.Index,

header: ?elf.Elf64_Ehdr = null,
shdrs: std.ArrayListUnmanaged(elf.Elf64_Shdr) = .{},
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
first_global: ?Symbol.Index = null,

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
symbols_resolver: std.ArrayListUnmanaged(Elf.SymbolResolver.Index) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},
atoms_indexes: std.ArrayListUnmanaged(Atom.Index) = .{},
atoms_extra: std.ArrayListUnmanaged(u32) = .{},
relocs: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},

merge_sections: std.ArrayListUnmanaged(InputMergeSection) = .{},
merge_sections_indexes: std.ArrayListUnmanaged(InputMergeSection.Index) = .{},

comdat_groups: std.ArrayListUnmanaged(Elf.ComdatGroup) = .{},
comdat_group_data: std.ArrayListUnmanaged(u32) = .{},

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
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.symbols_extra.deinit(allocator);
    self.symbols_resolver.deinit(allocator);
    self.atoms.deinit(allocator);
    self.atoms_indexes.deinit(allocator);
    self.atoms_extra.deinit(allocator);
    self.comdat_groups.deinit(allocator);
    self.comdat_group_data.deinit(allocator);
    self.relocs.deinit(allocator);
    self.fdes.deinit(allocator);
    self.cies.deinit(allocator);
    for (self.merge_sections.items) |*sec| {
        sec.deinit(allocator);
    }
    self.merge_sections.deinit(allocator);
    self.merge_sections_indexes.deinit(allocator);
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
    try self.strtab.appendSlice(gpa, shstrtab);

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

        const strtab_bias = @as(u32, @intCast(self.strtab.items.len));
        const strtab = try self.preadShdrContentsAlloc(gpa, file, shdr.sh_link);
        defer gpa.free(strtab);
        try self.strtab.appendSlice(gpa, strtab);

        for (self.symtab.items) |*sym| {
            sym.st_name = if (sym.st_name == 0 and sym.st_type() == elf.STT_SECTION)
                shdrs[sym.st_shndx].sh_name
            else
                sym.st_name + strtab_bias;
        }
    }

    // Allocate atom index 0 to null atom
    try self.atoms.append(gpa, .{ .extra = try self.addAtomExtra(gpa, .{}) });
    // Append null input merge section
    try self.merge_sections.append(gpa, .{});

    try self.initAtoms(gpa, file, elf_file);
    try self.initSymbols(gpa, elf_file);

    for (self.shdrs.items, 0..) |shdr, i| {
        const atom = self.getAtom(self.atoms_indexes.items[i]) orelse continue;
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
    try self.atoms.ensureTotalCapacityPrecise(allocator, shdrs.len);
    try self.atoms_extra.ensureTotalCapacityPrecise(allocator, shdrs.len * @sizeOf(Atom.Extra));
    try self.atoms_indexes.ensureTotalCapacityPrecise(allocator, shdrs.len);
    try self.atoms_indexes.resize(allocator, shdrs.len);
    @memset(self.atoms_indexes.items, 0);

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
                        break :blk sym_shdr.sh_name;
                    }
                    break :blk group_info_sym.st_name;
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

                const comdat_group_index = try self.addComdatGroup(allocator);
                const comdat_group = self.getComdatGroup(comdat_group_index);
                comdat_group.* = .{
                    .signature_off = group_signature,
                    .file_index = self.index,
                    .shndx = @intCast(i),
                    .members_start = group_start,
                    .members_len = @intCast(group_nmembers - 1),
                };
            },

            elf.SHT_SYMTAB_SHNDX => @panic("TODO"),

            elf.SHT_NULL,
            elf.SHT_REL,
            elf.SHT_RELA,
            elf.SHT_SYMTAB,
            elf.SHT_STRTAB,
            => {},

            else => {
                const name = self.getString(shdr.sh_name);
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
                const size, const alignment = if (shdr.sh_flags & elf.SHF_COMPRESSED != 0) blk: {
                    const data = try self.preadShdrContentsAlloc(allocator, file, shndx);
                    defer allocator.free(data);
                    const chdr = @as(*align(1) const elf.Elf64_Chdr, @ptrCast(data.ptr)).*;
                    break :blk .{ chdr.ch_size, chdr.ch_addralign };
                } else .{ shdr.sh_size, shdr.sh_addralign };
                const atom_index = self.addAtomAssumeCapacity(.{
                    .name = shdr.sh_name,
                    .shndx = shndx,
                    .size = size,
                    .alignment = alignment,
                });
                self.atoms_indexes.items[shndx] = atom_index;
            },
        }
    }

    // Parse relocs sections if any.
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_REL, elf.SHT_RELA => {
            const atom_index = self.atoms_indexes.items[shdr.sh_info];
            if (self.getAtom(atom_index)) |atom| {
                const relocs = try self.preadRelocsAlloc(allocator, file, @intCast(i));
                defer allocator.free(relocs);
                atom.relocs_shndx = @intCast(i);
                const rel_index: u32 = @intCast(self.relocs.items.len);
                const rel_count: u32 = @intCast(relocs.len);
                atom.addExtra(.{ .rel_index = rel_index, .rel_count = rel_count }, elf_file);
                try self.relocs.appendUnalignedSlice(allocator, relocs);
                sortRelocs(self.relocs.items[rel_index..][0..rel_count], elf_file);
            }
        },
        else => {},
    };
}

fn skipShdr(self: *Object, index: u32, elf_file: *Elf) bool {
    const shdr = self.shdrs.items[index];
    const name = self.getString(shdr.sh_name);
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

fn initSymbols(self: *Object, allocator: Allocator, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const first_global = self.first_global orelse self.symtab.items.len;
    const nglobals = self.symtab.items.len - first_global;

    try self.symbols.ensureTotalCapacityPrecise(allocator, self.symtab.items.len);
    try self.symbols_extra.ensureTotalCapacityPrecise(allocator, self.symtab.items.len * @sizeOf(Symbol.Extra));
    try self.symbols_resolver.ensureTotalCapacityPrecise(allocator, nglobals);
    self.symbols_resolver.resize(allocator, nglobals) catch unreachable;
    @memset(self.symbols_resolver.items, 0);

    for (self.symtab.items, 0..) |sym, i| {
        const index = self.addSymbolAssumeCapacity();
        const sym_ptr = &self.symbols.items[index];
        sym_ptr.value = @intCast(sym.st_value);
        sym_ptr.name = sym.st_name;
        sym_ptr.esym_idx = @intCast(i);
        sym_ptr.extra = self.addSymbolExtraAssumeCapacity(.{});
        sym_ptr.ver_idx = if (i >= first_global) elf_file.default_sym_version else elf.VER_NDX_LOCAL;
        sym_ptr.flags.weak = sym.st_bind() == elf.STB_WEAK;
        if (sym.st_shndx != elf.SHN_ABS and sym.st_shndx != elf.SHN_COMMON) {
            sym_ptr.ref = .{ .index = self.atoms_indexes.items[sym.st_shndx], .file = self.index };
        }
    }
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

    var it = eh_frame.Iterator{ .data = raw };
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
            .fde => {
                if (rel_range.len == 0) {
                    // No relocs for an FDE means we cannot associate this FDE to an Atom
                    // so we skip it. According to mold source code
                    // (https://github.com/rui314/mold/blob/a3e69502b0eaf1126d6093e8ea5e6fdb95219811/src/input-files.cc#L525-L528)
                    // this can happen for object files built with -r flag by the linker.
                    continue;
                }
                try self.fdes.append(allocator, .{
                    .offset = data_start + rec.offset,
                    .size = rec.size,
                    .cie_index = undefined,
                    .rel_index = rel_start + @as(u32, @intCast(rel_range.start)),
                    .rel_num = @as(u32, @intCast(rel_range.len)),
                    .shndx = shndx,
                    .file = self.index,
                });
            },
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
        atom.addExtra(.{ .fde_start = start, .fde_count = i - start }, elf_file);
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

    for (self.atoms_indexes.items) |atom_index| {
        const atom = self.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        const shdr = atom.getInputShdr(elf_file);
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) continue;
        try atom.scanRelocs(elf_file);
    }

    for (self.cies.items) |cie| {
        for (cie.getRelocs(elf_file)) |rel| {
            const sym = &self.symbols.items[rel.r_sym()];
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

pub fn resolveSymbols(self: *Object, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = elf_file.base.allocator;

    const first_global = self.first_global orelse return;
    for (self.getGlobals(), first_global..) |_, i| {
        const esym = self.symtab.items[i];
        if (esym.st_shndx != elf.SHN_ABS and esym.st_shndx != elf.SHN_COMMON and esym.st_shndx != elf.SHN_UNDEF) {
            const atom_index = self.atoms_indexes.items[esym.st_shndx];
            const atom_ptr = self.getAtom(atom_index) orelse continue;
            if (!atom_ptr.flags.alive) continue;
        }

        const resolv = &self.symbols_resolver.items[i - first_global];
        const gop = try elf_file.resolver.getOrPut(gpa, .{
            .index = @intCast(i),
            .file = self.index,
        }, elf_file);
        if (!gop.found_existing) {
            gop.ref.* = .{ .index = 0, .file = 0 };
        }
        resolv.* = gop.index;

        if (esym.st_shndx == elf.SHN_UNDEF) continue;
        if (elf_file.getSymbol(gop.ref.*) == null) {
            gop.ref.* = .{ .index = @intCast(i), .file = self.index };
            continue;
        }

        if (self.asFile().getSymbolRank(esym, !self.alive) < elf_file.getSymbol(gop.ref.*).?.getSymbolRank(elf_file)) {
            gop.ref.* = .{ .index = @intCast(i), .file = self.index };
        }
    }
}

pub fn claimUnresolved(self: *Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (self.getGlobals(), 0..) |*sym, i| {
        const esym_index = @as(u32, @intCast(first_global + i));
        const esym = self.symtab.items[esym_index];
        if (esym.st_shndx != elf.SHN_UNDEF) continue;
        if (elf_file.getSymbol(self.resolveSymbol(esym_index, elf_file)) != null) continue;

        const is_import = blk: {
            if (!elf_file.options.shared) break :blk false;
            const vis = @as(elf.STV, @enumFromInt(esym.st_other));
            if (vis == .HIDDEN) break :blk false;
            break :blk true;
        };

        sym.value = 0;
        sym.ref = .{ .index = 0, .file = 0 };
        sym.esym_idx = esym_index;
        sym.file = self.index;
        sym.ver_idx = if (is_import) elf.VER_NDX_LOCAL else elf_file.default_sym_version;
        sym.flags.import = is_import;

        const idx = self.symbols_resolver.items[i];
        elf_file.resolver.values.items[idx - 1] = .{ .index = esym_index, .file = self.index };
    }
}

pub fn claimUnresolvedRelocatable(self: *Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (self.getGlobals(), 0..) |*sym, i| {
        const esym_index = @as(u32, @intCast(first_global + i));
        const esym = self.symtab.items[esym_index];
        if (esym.st_shndx != elf.SHN_UNDEF) continue;
        if (elf_file.getSymbol(self.resolveSymbol(esym_index, elf_file)) != null) continue;

        sym.value = 0;
        sym.ref = .{ .index = 0, .file = 0 };
        sym.esym_idx = esym_index;
        sym.file = self.index;

        const idx = self.symbols_resolver.items[i];
        elf_file.resolver.values.items[idx - 1] = .{ .index = esym_index, .file = self.index };
    }
}

pub fn markLive(self: *Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (0..self.getGlobals().len) |i| {
        const esym_idx = first_global + i;
        const esym = self.symtab.items[esym_idx];
        if (esym.st_bind() == elf.STB_WEAK) continue;

        const ref = self.resolveSymbol(@intCast(esym_idx), elf_file);
        const sym = elf_file.getSymbol(ref) orelse continue;
        const file = sym.getFile(elf_file).?;
        const should_keep = esym.st_shndx == elf.SHN_UNDEF or
            (esym.st_shndx == elf.SHN_COMMON and sym.getElfSym(elf_file).st_shndx != elf.SHN_COMMON);
        if (should_keep and !file.isAlive()) {
            file.setAlive();
            file.markLive(elf_file);
        }
    }
}

pub fn markImportsExports(self: *Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (0..self.getGlobals().len) |i| {
        const idx = first_global + i;
        const ref = self.resolveSymbol(@intCast(idx), elf_file);
        const sym = elf_file.getSymbol(ref) orelse continue;
        const file = sym.getFile(elf_file).?;
        if (sym.ver_idx == elf.VER_NDX_LOCAL) continue;
        const vis = @as(elf.STV, @enumFromInt(sym.getElfSym(elf_file).st_other));
        if (vis == .HIDDEN) continue;
        if (file == .shared and !sym.isAbs(elf_file)) {
            sym.flags.import = true;
            continue;
        }
        if (file.getIndex() == self.index) {
            sym.flags.@"export" = true;
            if (elf_file.options.shared and vis != .PROTECTED) {
                sym.flags.import = true;
            }
        }
    }
}

pub fn checkDuplicates(self: *Object, elf_file: *Elf) error{OutOfMemory}!void {
    const gpa = elf_file.base.allocator;
    const first_global = self.first_global orelse return;
    for (0..self.getGlobals().len) |i| {
        const esym_idx = first_global + i;
        const esym = self.symtab.items[esym_idx];
        const ref = self.resolveSymbol(@intCast(esym_idx), elf_file);
        const ref_sym = elf_file.getSymbol(ref) orelse continue;
        const ref_file = ref_sym.getFile(elf_file).?;

        if (self.index == ref_file.getIndex() or
            esym.st_shndx == elf.SHN_UNDEF or
            esym.st_bind() == elf.STB_WEAK or
            esym.st_shndx == elf.SHN_COMMON) continue;

        if (esym.st_shndx != elf.SHN_ABS) {
            const atom_index = self.atoms_indexes.items[esym.st_shndx];
            const atom_ptr = self.getAtom(atom_index) orelse continue;
            if (!atom_ptr.flags.alive) continue;
        }

        const gop = try elf_file.dupes.getOrPut(gpa, self.symbols_resolver.items[i]);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(gpa, self.index);
    }
}

pub fn initMergeSections(self: *Object, elf_file: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = elf_file.base.allocator;

    try self.merge_sections.ensureUnusedCapacity(gpa, self.shdrs.items.len);
    try self.merge_sections_indexes.resize(gpa, self.shdrs.items.len);
    @memset(self.merge_sections_indexes.items, 0);

    for (self.shdrs.items, 0..) |shdr, shndx| {
        if (shdr.sh_flags & elf.SHF_MERGE == 0) continue;

        const atom_index = self.atoms_indexes.items[shndx];
        const atom = self.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        if (atom.getRelocs(elf_file).len > 0) continue;

        const imsec_idx = try self.addInputMergeSection(gpa);
        const imsec = self.getInputMergeSection(imsec_idx).?;
        self.merge_sections_indexes.items[shndx] = imsec_idx;

        imsec.merge_section = try elf_file.getOrCreateMergeSection(atom.getName(elf_file), shdr.sh_flags, shdr.sh_type);
        imsec.atom = atom_index;

        const data = try atom.getCodeUncompressAlloc(elf_file);
        defer gpa.free(data);

        if (shdr.sh_flags & elf.SHF_STRINGS != 0) {
            const sh_entsize: u32 = switch (shdr.sh_entsize) {
                // According to mold's source code, GHC emits MS sections with sh_entsize = 0.
                // This actually can also happen for output created with `-r` mode.
                0 => 1,
                else => |x| @intCast(x),
            };

            const isNull = struct {
                fn isNull(slice: []u8) bool {
                    for (slice) |x| if (x != 0) return false;
                    return true;
                }
            }.isNull;

            var start: u32 = 0;
            while (start < data.len) {
                var end = start;
                while (end < data.len - sh_entsize and !isNull(data[end .. end + sh_entsize])) : (end += sh_entsize) {}
                if (!isNull(data[end .. end + sh_entsize])) {
                    elf_file.base.fatal("{}:{s}: string not null terminated", .{
                        self.fmtPath(),
                        atom.getName(elf_file),
                    });
                    return error.ParseFailed;
                }
                end += sh_entsize;
                const string = data[start..end];
                try imsec.insert(gpa, string);
                try imsec.offsets.append(gpa, start);
                start = end;
            }
        } else {
            const sh_entsize: u32 = @intCast(shdr.sh_entsize);
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

pub fn initOutputSections(self: *Object, elf_file: *Elf) !void {
    for (self.atoms_indexes.items) |atom_index| {
        const atom_ptr = self.getAtom(atom_index) orelse continue;
        if (!atom_ptr.flags.alive) continue;
        const shdr = atom_ptr.getInputShdr(elf_file);
        const osec = try elf_file.initOutputSection(.{
            .name = self.getString(shdr.sh_name),
            .flags = shdr.sh_flags,
            .type = shdr.sh_type,
        });
        atom_ptr.out_shndx = osec;
        const atoms = &elf_file.sections.items(.atoms)[osec];
        try atoms.append(elf_file.base.allocator, atom_ptr.getRef());
    }
}

pub fn initRelaSections(self: *Object, elf_file: *Elf) !void {
    for (self.atoms_indexes.items) |atom_index| {
        const atom_ptr = self.getAtom(atom_index) orelse continue;
        if (!atom_ptr.flags.alive) continue;
        if (atom_ptr.getRelocs(elf_file).len == 0) continue;
        const shdr = self.shdrs.items[atom_ptr.relocs_shndx];
        const out_shndx = try elf_file.initOutputSection(.{
            .name = self.getString(shdr.sh_name),
            .flags = shdr.sh_flags,
            .type = shdr.sh_type,
        });
        const out_shdr = &elf_file.sections.items(.shdr)[out_shndx];
        out_shdr.sh_type = elf.SHT_RELA;
        out_shdr.sh_addralign = @alignOf(elf.Elf64_Rela);
        out_shdr.sh_entsize = @sizeOf(elf.Elf64_Rela);
        out_shdr.sh_flags |= elf.SHF_INFO_LINK;
        elf_file.sections.items(.rela_shndx)[atom_ptr.out_shndx] = out_shndx;
    }
}

pub fn resolveMergeSubsections(self: *Object, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;

    for (self.merge_sections_indexes.items) |index| {
        const imsec = self.getInputMergeSection(index) orelse continue;
        if (imsec.offsets.items.len == 0) continue;
        const msec = elf_file.getMergeSection(imsec.merge_section);
        const atom = self.getAtom(imsec.atom).?;
        const isec = atom.getInputShdr(elf_file);

        try imsec.subsections.resize(gpa, imsec.strings.items.len);

        for (imsec.strings.items, imsec.subsections.items) |str, *imsec_msub| {
            const string = imsec.bytes.items[str.pos..][0..str.len];
            const res = try msec.insert(gpa, string);
            if (!res.found_existing) {
                const msub_index = try msec.addMergeSubsection(gpa);
                const msub = msec.getMergeSubsection(msub_index);
                msub.merge_section = imsec.merge_section;
                msub.string_index = res.key.pos;
                msub.entsize = @intCast(isec.sh_entsize);
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
        const sym = &self.symbols.items[idx];
        if (esym.st_shndx == elf.SHN_COMMON or esym.st_shndx == elf.SHN_UNDEF or esym.st_shndx == elf.SHN_ABS) continue;

        const imsec_index = self.merge_sections_indexes.items[esym.st_shndx];
        const imsec = self.getInputMergeSection(imsec_index) orelse continue;
        if (imsec.offsets.items.len == 0) continue;
        const msub_index, const offset = imsec.findSubsection(@intCast(esym.st_value)) orelse {
            elf_file.base.fatal("{}: invalid symbol value: {s}:{x}", .{
                self.fmtPath(),
                sym.getName(elf_file),
                esym.st_value,
            });
            return error.ParseFailed;
        };

        sym.ref = .{ .index = msub_index, .file = imsec.merge_section };
        sym.flags.merge_subsection = true;
        sym.value = offset;
    }

    for (self.atoms_indexes.items) |atom_index| {
        const atom = self.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        const extra = atom.getExtra(elf_file);
        if (extra.rel_count == 0) continue;
        const relocs = self.relocs.items[extra.rel_index..][0..extra.rel_count];
        for (relocs) |*rel| {
            const esym = self.symtab.items[rel.r_sym()];
            if (esym.st_type() != elf.STT_SECTION) continue;

            const imsec_index = self.merge_sections_indexes.items[esym.st_shndx];
            const imsec = self.getInputMergeSection(imsec_index) orelse continue;
            if (imsec.offsets.items.len == 0) continue;
            const msec = elf_file.getMergeSection(imsec.merge_section);
            const msub_index, const offset = imsec.findSubsection(@intCast(@as(i64, @intCast(esym.st_value)) + rel.r_addend)) orelse {
                elf_file.base.fatal("{}: {s}: invalid relocation at offset 0x{x}", .{
                    self.fmtPath(),
                    atom.getName(elf_file),
                    rel.r_offset,
                });
                return error.ParseFailed;
            };

            const sym_index = try self.addSymbol(gpa);
            const sym = &self.symbols.items[sym_index];
            const name = try std.fmt.allocPrint(gpa, "{s}$subsection{d}", .{
                msec.getName(elf_file),
                msub_index,
            });
            defer gpa.free(name);
            sym.* = .{
                .value = @bitCast(@as(i64, @intCast(offset)) - rel.r_addend),
                .name = try self.addString(gpa, name),
                .esym_idx = rel.r_sym(),
                .file = self.index,
                .extra = try self.addSymbolExtra(gpa, .{}),
            };
            sym.ref = .{ .index = msub_index, .file = imsec.merge_section };
            sym.flags.merge_subsection = true;
            rel.r_info = (@as(u64, @intCast(sym_index)) << 32) | rel.r_type();
        }
    }
}

/// We will create dummy shdrs per each resolved common symbols to make it
/// play nicely with the rest of the system.
pub fn convertCommonSymbols(self: *Object, elf_file: *Elf) !void {
    const first_global = self.first_global orelse return;
    for (self.getGlobals(), self.symbols_resolver.items, 0..) |*sym, resolv, i| {
        const esym_idx = @as(Symbol.Index, @intCast(first_global + i));
        const esym = self.symtab.items[esym_idx];
        if (esym.st_shndx != elf.SHN_COMMON) continue;

        if (elf_file.resolver.get(resolv).?.file != self.index) {
            if (elf_file.options.warn_common) {
                elf_file.base.warn("{}: multiple common symbols: {s}", .{
                    self.fmtPath(),
                    self.getString(esym.st_name),
                });
            }
            continue;
        }

        const gpa = elf_file.base.allocator;
        const is_tls = sym.getType(elf_file) == elf.STT_TLS;
        const name = if (is_tls) ".tls_common" else ".common";
        const name_offset = @as(u32, @intCast(self.strtab.items.len));
        try self.strtab.writer(gpa).print("{s}\x00", .{name});

        var sh_flags: u32 = elf.SHF_ALLOC | elf.SHF_WRITE;
        if (is_tls) sh_flags |= elf.SHF_TLS;
        const shndx = @as(u32, @intCast(self.shdrs.items.len));
        const shdr = try self.shdrs.addOne(gpa);
        const sh_size = math.cast(usize, esym.st_size) orelse return error.Overflow;
        shdr.* = .{
            .sh_name = name_offset,
            .sh_type = elf.SHT_NOBITS,
            .sh_flags = sh_flags,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = sh_size,
            .sh_link = 0,
            .sh_info = 0,
            .sh_addralign = esym.st_value,
            .sh_entsize = 0,
        };

        const atom_index = try self.addAtom(gpa, .{
            .name = name_offset,
            .shndx = shndx,
            .size = esym.st_size,
            .alignment = esym.st_value,
        });
        try self.atoms_indexes.append(gpa, atom_index);

        sym.value = 0;
        sym.ref = .{ .index = atom_index, .file = self.index };
        sym.flags.weak = false;
    }
}

pub fn resolveComdatGroups(self: *Object, elf_file: *Elf, table: anytype) !void {
    for (self.comdat_groups.items, 0..) |*cg, cgi| {
        const signature = cg.getSignature(elf_file);
        const gop = try table.getOrPut(signature);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .index = @intCast(cgi), .file = self.index };
            continue;
        }
        const current = elf_file.getComdatGroup(gop.value_ptr.*);
        cg.alive = false;
        if (self.index < current.file_index) {
            current.alive = false;
            cg.alive = true;
            gop.value_ptr.* = .{ .index = @intCast(cgi), .file = self.index };
        }
    }
}

pub fn markComdatGroupsDead(self: *Object, elf_file: *Elf) void {
    for (self.comdat_groups.items) |cg| {
        if (cg.alive) continue;
        for (cg.getComdatGroupMembers(elf_file)) |shndx| {
            const atom_index = self.atoms_indexes.items[shndx];
            if (self.getAtom(atom_index)) |atom_ptr| {
                atom_ptr.flags.alive = false;
                atom_ptr.markFdesDead(elf_file);
            }
        }
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
        for (self.getLocals()) |*local| {
            if (!isAlive(local, elf_file)) continue;
            const esym = local.getElfSym(elf_file);
            switch (esym.st_type()) {
                elf.STT_SECTION => continue,
                elf.STT_NOTYPE => if (esym.st_shndx == elf.SHN_UNDEF) continue,
                else => {},
            }
            local.flags.output_symtab = true;
            local.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, elf_file);
            self.output_symtab_ctx.nlocals += 1;
            self.output_symtab_ctx.strsize += @as(u32, @intCast(local.getName(elf_file).len + 1));
        }
    }

    for (self.getGlobals(), self.symbols_resolver.items) |*global, resolv| {
        const ref = elf_file.resolver.values.items[resolv - 1];
        const ref_sym = elf_file.getSymbol(ref) orelse continue;
        if (ref_sym.getFile(elf_file).?.getIndex() != self.index) continue;
        if (!isAlive(global, elf_file)) continue;
        global.flags.output_symtab = true;
        if (global.isLocal(elf_file)) {
            global.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, elf_file);
            self.output_symtab_ctx.nlocals += 1;
        } else {
            global.addExtra(.{ .symtab = self.output_symtab_ctx.nglobals }, elf_file);
            self.output_symtab_ctx.nglobals += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(global.getName(elf_file).len + 1));
    }
}

pub fn writeSymtab(self: Object, elf_file: *Elf) void {
    if (elf_file.options.strip_all) return;

    for (self.getLocals()) |local| {
        const idx = local.getOutputSymtabIndex(elf_file) orelse continue;
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = @intCast(elf_file.strtab.items.len);
        elf_file.strtab.appendSliceAssumeCapacity(local.getName(elf_file));
        elf_file.strtab.appendAssumeCapacity(0);
        local.setOutputSym(elf_file, out_sym);
    }

    for (self.getGlobals(), self.symbols_resolver.items) |global, resolv| {
        const ref = elf_file.resolver.values.items[resolv - 1];
        const ref_sym = elf_file.getSymbol(ref) orelse continue;
        if (ref_sym.getFile(elf_file).?.getIndex() != self.index) continue;
        const idx = global.getOutputSymtabIndex(elf_file) orelse continue;
        const st_name = @as(u32, @intCast(elf_file.strtab.items.len));
        elf_file.strtab.appendSliceAssumeCapacity(global.getName(elf_file));
        elf_file.strtab.appendAssumeCapacity(0);
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = st_name;
        global.setOutputSym(elf_file, out_sym);
    }
}

pub fn getLocals(self: Object) []Symbol {
    if (self.symbols.items.len == 0) return &[0]Symbol{};
    assert(self.symbols.items.len >= self.symtab.items.len);
    const end = self.first_global orelse self.symtab.items.len;
    return self.symbols.items[0..end];
}

pub fn getGlobals(self: Object) []Symbol {
    if (self.symbols.items.len == 0) return &[0]Symbol{};
    assert(self.symbols.items.len >= self.symtab.items.len);
    const start = self.first_global orelse self.symtab.items.len;
    return self.symbols.items[start..self.symtab.items.len];
}

pub fn resolveSymbol(self: Object, index: Symbol.Index, elf_file: *Elf) Elf.Ref {
    const start = self.first_global orelse self.symtab.items.len;
    const end = self.symtab.items.len;
    if (index < start or index >= end) return .{ .index = index, .file = self.index };
    const resolv = self.symbols_resolver.items[index - start];
    return elf_file.resolver.get(resolv).?;
}

fn addSymbol(self: *Object, allocator: Allocator) !Symbol.Index {
    try self.symbols.ensureUnusedCapacity(allocator, 1);
    return self.addSymbolAssumeCapacity();
}

fn addSymbolAssumeCapacity(self: *Object) Symbol.Index {
    const index: Symbol.Index = @intCast(self.symbols.items.len);
    self.symbols.appendAssumeCapacity(.{ .file = self.index });
    return index;
}

pub fn addSymbolExtra(self: *Object, allocator: Allocator, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).@"struct".fields;
    try self.symbols_extra.ensureUnusedCapacity(allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

pub fn addSymbolExtraAssumeCapacity(self: *Object, extra: Symbol.Extra) u32 {
    const index = @as(u32, @intCast(self.symbols_extra.items.len));
    const fields = @typeInfo(Symbol.Extra).@"struct".fields;
    inline for (fields) |field| {
        self.symbols_extra.appendAssumeCapacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        });
    }
    return index;
}

pub fn getSymbolExtra(self: *Object, index: u32) Symbol.Extra {
    const fields = @typeInfo(Symbol.Extra).@"struct".fields;
    var i: usize = index;
    var result: Symbol.Extra = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => self.symbols_extra.items[i],
            else => @compileError("bad field type"),
        };
        i += 1;
    }
    return result;
}

pub fn setSymbolExtra(self: *Object, index: u32, extra: Symbol.Extra) void {
    const fields = @typeInfo(Symbol.Extra).@"struct".fields;
    inline for (fields, 0..) |field, i| {
        self.symbols_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
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

fn addString(self: *Object, allocator: Allocator, str: []const u8) !u32 {
    const off: u32 = @intCast(self.strtab.items.len);
    try self.strtab.ensureUnusedCapacity(allocator, str.len + 1);
    self.strtab.appendSliceAssumeCapacity(str);
    self.strtab.appendAssumeCapacity(0);
    return off;
}

pub fn getString(self: Object, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

pub fn asFile(self: *Object) File {
    return .{ .object = self };
}

const AddAtomArgs = struct {
    name: u32,
    shndx: u32,
    size: u64,
    alignment: u64,
};

fn addAtom(self: *Object, allocator: Allocator, args: AddAtomArgs) !Atom.Index {
    try self.atoms.ensureUnusedCapacity(allocator, 1);
    try self.atoms_extra.ensureUnusedCapacity(allocator, @sizeOf(Atom.Extra));
    return self.addAtomAssumeCapacity(args);
}

fn addAtomAssumeCapacity(self: *Object, args: AddAtomArgs) Atom.Index {
    const atom_index: Atom.Index = @intCast(self.atoms.items.len);
    const atom_ptr = self.atoms.addOneAssumeCapacity();
    atom_ptr.* = .{
        .atom_index = atom_index,
        .name = args.name,
        .file = self.index,
        .shndx = args.shndx,
        .extra = self.addAtomExtraAssumeCapacity(.{}),
        .size = args.size,
        .alignment = math.log2_int(u64, args.alignment),
    };
    return atom_index;
}

pub fn getAtom(self: *Object, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn addAtomExtra(self: *Object, allocator: Allocator, extra: Atom.Extra) !u32 {
    const fields = @typeInfo(Atom.Extra).@"struct".fields;
    try self.atoms_extra.ensureUnusedCapacity(allocator, fields.len);
    return self.addAtomExtraAssumeCapacity(extra);
}

pub fn addAtomExtraAssumeCapacity(self: *Object, extra: Atom.Extra) u32 {
    const index = @as(u32, @intCast(self.atoms_extra.items.len));
    const fields = @typeInfo(Atom.Extra).@"struct".fields;
    inline for (fields) |field| {
        self.atoms_extra.appendAssumeCapacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        });
    }
    return index;
}

pub fn getAtomExtra(self: *Object, index: u32) Atom.Extra {
    const fields = @typeInfo(Atom.Extra).@"struct".fields;
    var i: usize = index;
    var result: Atom.Extra = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => self.atoms_extra.items[i],
            else => @compileError("bad field type"),
        };
        i += 1;
    }
    return result;
}

pub fn setAtomExtra(self: *Object, index: u32, extra: Atom.Extra) void {
    const fields = @typeInfo(Atom.Extra).@"struct".fields;
    inline for (fields, 0..) |field, i| {
        self.atoms_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
}

fn addInputMergeSection(self: *Object, allocator: Allocator) !InputMergeSection.Index {
    const index: InputMergeSection.Index = @intCast(self.merge_sections.items.len);
    const msec = try self.merge_sections.addOne(allocator);
    msec.* = .{};
    return index;
}

fn getInputMergeSection(self: *Object, index: InputMergeSection.Index) ?*InputMergeSection {
    if (index == 0) return null;
    return &self.merge_sections.items[index];
}

fn addComdatGroup(self: *Object, allocator: Allocator) !Elf.ComdatGroup.Index {
    const index = @as(Elf.ComdatGroup.Index, @intCast(self.comdat_groups.items.len));
    _ = try self.comdat_groups.addOne(allocator);
    return index;
}

pub fn getComdatGroup(self: *Object, index: Elf.ComdatGroup.Index) *Elf.ComdatGroup {
    assert(index < self.comdat_groups.items.len);
    return &self.comdat_groups.items[index];
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
    const elf_file = ctx.elf_file;
    try writer.writeAll("  locals\n");
    for (object.getLocals()) |local| {
        try writer.print("    {}\n", .{local.fmt(elf_file)});
    }
    try writer.writeAll("  globals\n");
    for (object.getGlobals(), 0..) |global, i| {
        const first_global = object.first_global.?;
        const ref = object.resolveSymbol(@intCast(i + first_global), elf_file);
        if (elf_file.getSymbol(ref)) |ref_sym| {
            try writer.print("    {}\n", .{ref_sym.fmt(elf_file)});
        } else {
            try writer.print("    {s} : unclaimed\n", .{global.getName(elf_file)});
        }
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
    for (object.atoms_indexes.items) |atom_index| {
        const atom = object.getAtom(atom_index) orelse continue;
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
    try writer.writeAll("  COMDAT groups\n");
    for (object.comdat_groups.items, 0..) |cg, cg_index| {
        try writer.print("    COMDAT({d})", .{cg_index});
        if (!cg.alive) try writer.writeAll(" : [*]");
        try writer.writeByte('\n');
        const cg_members = cg.getComdatGroupMembers(elf_file);
        for (cg_members) |shndx| {
            const atom_index = object.atoms_indexes.items[shndx];
            const atom = object.getAtom(atom_index) orelse continue;
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
