archive: ?[]const u8 = null,
path: []const u8,
mtime: u64,
data: []const u8,
index: File.Index,

header: ?macho.mach_header_64 = null,
sections: std.MultiArrayList(Section) = .{},
symtab: std.MultiArrayList(Nlist) = .{},
strtab: []const u8 = &[0]u8{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

platform: ?MachO.Options.Platform = null,
dwarf_info: ?DwarfInfo = null,

eh_frame_sect_index: ?u8 = null,
compact_unwind_sect_index: ?u8 = null,

cies: std.ArrayListUnmanaged(Cie) = .{},
fdes: std.ArrayListUnmanaged(Fde) = .{},
unwind_records: std.ArrayListUnmanaged(UnwindInfo.Record.Index) = .{},

has_unwind: bool = false,
has_eh_frame: bool = false,
alive: bool = true,
num_rebase_relocs: u32 = 0,
num_bind_relocs: u32 = 0,

output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn deinit(self: *Object, gpa: Allocator) void {
    self.symtab.deinit(gpa);
    self.symbols.deinit(gpa);
    self.atoms.deinit(gpa);
    self.cies.deinit(gpa);
    self.fdes.deinit(gpa);
    self.unwind_records.deinit(gpa);
    if (self.dwarf_info) |*dw| dw.deinit(gpa);
}

pub fn parse(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(macho.mach_header_64);

    if (self.getLoadCommand(.SEGMENT_64)) |lc| {
        const sections = lc.getSections();
        try self.sections.ensureUnusedCapacity(gpa, sections.len);
        for (sections) |sect| {
            const index = try self.sections.addOne(gpa);
            self.sections.set(index, .{ .header = sect });

            if (mem.eql(u8, sect.sectName(), "__eh_frame")) {
                self.eh_frame_sect_index = @intCast(index);
            } else if (mem.eql(u8, sect.sectName(), "__compact_unwind")) {
                self.compact_unwind_sect_index = @intCast(index);
            }
        }
    }
    if (self.getLoadCommand(.SYMTAB)) |lc| {
        const cmd = lc.cast(macho.symtab_command).?;
        self.strtab = self.data[cmd.stroff..][0..cmd.strsize];

        const symtab = @as([*]align(1) const macho.nlist_64, @ptrCast(self.data.ptr + cmd.symoff))[0..cmd.nsyms];
        try self.symtab.ensureUnusedCapacity(gpa, symtab.len);
        for (symtab) |nlist| {
            self.symtab.appendAssumeCapacity(.{
                .nlist = nlist,
                .atom = 0,
                .size = 0,
            });
        }
    }

    const NlistIdx = struct {
        nlist: macho.nlist_64,
        idx: usize,

        fn lessThan(ctx: void, lhs: @This(), rhs: @This()) bool {
            _ = ctx;
            if (lhs.nlist.n_sect == rhs.nlist.n_sect) {
                return lhs.nlist.n_value < rhs.nlist.n_value;
            }
            return lhs.nlist.n_sect < rhs.nlist.n_sect;
        }
    };

    var nlists = try std.ArrayList(NlistIdx).initCapacity(gpa, self.symtab.items(.nlist).len);
    defer nlists.deinit();
    for (self.symtab.items(.nlist), 0..) |nlist, i| {
        if (nlist.stab() or !nlist.sect()) continue;
        nlists.appendAssumeCapacity(.{ .nlist = nlist, .idx = i });
    }
    mem.sort(NlistIdx, nlists.items, {}, NlistIdx.lessThan);

    if (self.header.?.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0) {
        try self.initSubsections(nlists.items, macho_file);
    } else {
        try self.initSections(nlists.items, macho_file);
    }

    try self.initLiteralSections(macho_file);
    self.linkNlistToAtom();

    try self.sortAtoms(macho_file);
    try self.initSymbols(macho_file);
    try self.initRelocs(macho_file);

    if (self.eh_frame_sect_index) |index| {
        try self.initEhFrameRecords(index, macho_file);
    }

    if (self.compact_unwind_sect_index) |index| {
        try self.initUnwindRecords(index, macho_file);
    }

    self.initPlatform();
    try self.initDwarfInfo(gpa);
}

inline fn isLiteral(sect: macho.section_64) bool {
    return switch (sect.type()) {
        macho.S_CSTRING_LITERALS,
        macho.S_4BYTE_LITERALS,
        macho.S_8BYTE_LITERALS,
        macho.S_16BYTE_LITERALS,
        macho.S_LITERAL_POINTERS,
        => true,
        else => false,
    };
}

fn initSubsections(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |sect, *subsections, n_sect| {
        if (sect.attrs() & macho.S_ATTR_DEBUG != 0) continue;
        if (self.eh_frame_sect_index) |index| if (index == n_sect) continue;
        if (self.compact_unwind_sect_index) |index| if (index == n_sect) continue;
        if (isLiteral(sect)) continue;

        const nlist_start = for (nlists, 0..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 == n_sect) break i;
        } else nlists.len;
        const nlist_end = for (nlists[nlist_start..], nlist_start..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 != n_sect) break i;
        } else nlists.len;

        if (nlist_start == nlist_end or nlists[nlist_start].nlist.n_value > sect.addr) {
            const name = try std.fmt.allocPrintZ(gpa, "{s}${s}", .{ sect.segName(), sect.sectName() });
            defer gpa.free(name);
            const size = if (nlist_start == nlist_end) sect.size else nlists[nlist_start].nlist.n_value - sect.addr;
            const atom_index = try self.addAtom(.{
                .name = name,
                .n_sect = @intCast(n_sect),
                .off = 0,
                .size = size,
                .alignment = sect.@"align",
            }, macho_file);
            try subsections.append(gpa, .{
                .atom = atom_index,
                .off = 0,
            });
        }

        var idx: usize = nlist_start;
        while (idx < nlist_end) {
            const nlist = nlists[idx];

            while (idx < nlist_end and
                nlists[idx].nlist.n_value == nlist.nlist.n_value) : (idx += 1)
            {}

            const size = if (idx < nlist_end)
                nlists[idx].nlist.n_value - nlist.nlist.n_value
            else
                sect.addr + sect.size - nlist.nlist.n_value;
            const alignment = if (nlist.nlist.n_value > 0)
                @min(@ctz(nlist.nlist.n_value), sect.@"align")
            else
                sect.@"align";
            const atom_index = try self.addAtom(.{
                .name = self.getString(nlist.nlist.n_strx),
                .n_sect = @intCast(n_sect),
                .off = nlist.nlist.n_value - sect.addr,
                .size = size,
                .alignment = alignment,
            }, macho_file);
            try subsections.append(gpa, .{
                .atom = atom_index,
                .off = nlist.nlist.n_value - sect.addr,
            });

            for (nlist_start..idx) |i| {
                self.symtab.items(.size)[nlists[i].idx] = size;
            }
        }
    }
}

fn initSections(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    try self.atoms.ensureUnusedCapacity(gpa, self.sections.items(.header).len);

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (sect.attrs() & macho.S_ATTR_DEBUG != 0) continue;
        if (self.eh_frame_sect_index) |index| if (index == n_sect) continue;
        if (self.compact_unwind_sect_index) |index| if (index == n_sect) continue;
        if (isLiteral(sect)) continue;

        const name = try std.fmt.allocPrintZ(gpa, "{s}${s}", .{ sect.segName(), sect.sectName() });
        defer gpa.free(name);

        const atom_index = try self.addAtom(.{
            .name = name,
            .n_sect = @intCast(n_sect),
            .off = 0,
            .size = sect.size,
            .alignment = sect.@"align",
        }, macho_file);
        try slice.items(.subsections)[n_sect].append(gpa, .{ .atom = atom_index, .off = 0 });

        const nlist_start = for (nlists, 0..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 == n_sect) break i;
        } else nlists.len;
        const nlist_end = for (nlists[nlist_start..], nlist_start..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 != n_sect) break i;
        } else nlists.len;

        var idx: usize = nlist_start;
        while (idx < nlist_end) {
            const nlist = nlists[idx];

            while (idx < nlist_end and
                nlists[idx].nlist.n_value == nlist.nlist.n_value) : (idx += 1)
            {}

            const size = if (idx < nlist_end)
                nlists[idx].nlist.n_value - nlist.nlist.n_value
            else
                sect.addr + sect.size - nlist.nlist.n_value;

            for (nlist_start..idx) |i| {
                self.symtab.items(.size)[nlists[i].idx] = size;
            }
        }
    }
}

const AddAtomArgs = struct {
    name: [:0]const u8,
    n_sect: u8,
    off: u64,
    size: u64,
    alignment: u32,
};

fn addAtom(self: *Object, args: AddAtomArgs, macho_file: *MachO) !Atom.Index {
    const gpa = macho_file.base.allocator;
    const atom_index = try macho_file.addAtom();
    const atom = macho_file.getAtom(atom_index).?;
    atom.file = self.index;
    atom.atom_index = atom_index;
    atom.name = try macho_file.string_intern.insert(gpa, args.name);
    atom.n_sect = args.n_sect;
    atom.size = args.size;
    atom.alignment = args.alignment;
    atom.off = args.off;
    try self.atoms.append(gpa, atom_index);
    return atom_index;
}

fn initLiteralSections(self: *Object, macho_file: *MachO) !void {
    // TODO here we should split into equal-sized records, hash the contents, and then
    // deduplicate - ICF.
    // For now, we simply cover each literal section with one large atom.
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    try self.atoms.ensureUnusedCapacity(gpa, self.sections.items(.header).len);

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (sect.attrs() & macho.S_ATTR_DEBUG != 0) continue;
        if (self.eh_frame_sect_index) |index| if (index == n_sect) continue;
        if (self.compact_unwind_sect_index) |index| if (index == n_sect) continue;
        if (!isLiteral(sect)) continue;

        const name = try std.fmt.allocPrintZ(gpa, "{s}${s}", .{ sect.segName(), sect.sectName() });
        defer gpa.free(name);

        const atom_index = try self.addAtom(.{
            .name = name,
            .n_sect = @intCast(n_sect),
            .off = 0,
            .size = sect.size,
            .alignment = sect.@"align",
        }, macho_file);
        try slice.items(.subsections)[n_sect].append(gpa, .{ .atom = atom_index, .off = 0 });
    }
}

pub fn findAtom(self: Object, addr: u64) Atom.Index {
    for (self.sections.items(.header), 0..) |sect, n_sect| {
        if (sect.addr <= addr and addr < sect.addr + sect.size) {
            return self.findAtomInSection(addr, @intCast(n_sect));
        }
    }
    unreachable;
}

fn findAtomInSection(self: Object, addr: u64, n_sect: u8) Atom.Index {
    const slice = self.sections.slice();
    const sect = slice.items(.header)[n_sect];
    const subsections = slice.items(.subsections)[n_sect];
    var idx: usize = 0;
    while (idx < subsections.items.len) : (idx += 1) {
        const sub = subsections.items[idx];
        const sub_addr = sect.addr + sub.off;
        const sub_size = if (idx + 1 < subsections.items.len)
            subsections.items[idx + 1].off - sub.off
        else
            sect.size - sub.off;
        if (sub_addr <= addr and addr < sub_addr + sub_size) return sub.atom;
    }
    return subsections.items[subsections.items.len - 1].atom;
}

fn linkNlistToAtom(self: *Object) void {
    for (self.symtab.items(.nlist), self.symtab.items(.atom)) |nlist, *atom| {
        if (!nlist.stab() and nlist.sect()) {
            atom.* = self.findAtomInSection(nlist.n_value, nlist.n_sect - 1);
        }
    }
}

fn initSymbols(self: *Object, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const slice = self.symtab.slice();

    try self.symbols.ensureUnusedCapacity(gpa, slice.items(.nlist).len);

    for (slice.items(.nlist), slice.items(.atom), 0..) |nlist, atom_index, i| {
        if (nlist.ext()) {
            const name = self.getString(nlist.n_strx);
            const off = try macho_file.string_intern.insert(gpa, name);
            const gop = try macho_file.getOrCreateGlobal(off);
            self.symbols.addOneAssumeCapacity().* = gop.index;
            continue;
        }

        const atom = macho_file.getAtom(atom_index).?;
        const index = try macho_file.addSymbol();
        self.symbols.appendAssumeCapacity(index);
        const symbol = macho_file.getSymbol(index);
        const name = self.getString(nlist.n_strx);
        const value = if (nlist.abs())
            nlist.n_value
        else
            nlist.n_value - atom.getInputAddress(macho_file);
        symbol.* = .{
            .value = value,
            .name = try macho_file.string_intern.insert(gpa, name),
            .nlist_idx = @intCast(i),
            .atom = if (nlist.abs()) 0 else atom_index,
            .file = self.index,
        };

        symbol.flags.no_dead_strip = symbol.flags.no_dead_strip or nlist.noDeadStrip();

        if (nlist.sect() and
            self.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
        {
            symbol.flags.tlv = true;
        }
    }
}

fn sortAtoms(self: *Object, macho_file: *MachO) !void {
    const lessThanAtom = struct {
        fn lessThanAtom(ctx: *MachO, lhs: Atom.Index, rhs: Atom.Index) bool {
            return ctx.getAtom(lhs).?.getInputAddress(ctx) < ctx.getAtom(rhs).?.getInputAddress(ctx);
        }
    }.lessThanAtom;
    mem.sort(Atom.Index, self.atoms.items, macho_file, lessThanAtom);
}

fn initRelocs(self: *Object, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.header), slice.items(.relocs), 0..) |sect, *out, n_sect| {
        if (sect.nreloc == 0) continue;

        const relocs = @as([*]align(1) const macho.relocation_info, @ptrCast(self.data.ptr + sect.reloff))[0..sect.nreloc];
        const code = self.getSectionData(@intCast(n_sect));

        try out.ensureTotalCapacityPrecise(gpa, relocs.len);

        for (relocs) |rel| {
            const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.r_type);
            const rel_offset = @as(u32, @intCast(rel.r_address));
            var addend: i64 = switch (rel.r_length) {
                0 => code[rel_offset],
                1 => mem.readInt(i16, code[rel_offset..][0..2], .little),
                2 => mem.readInt(i32, code[rel_offset..][0..4], .little),
                3 => mem.readInt(i64, code[rel_offset..][0..8], .little),
            };
            addend += switch (rel_type) {
                .X86_64_RELOC_SIGNED_1 => 1,
                .X86_64_RELOC_SIGNED_2 => 2,
                .X86_64_RELOC_SIGNED_4 => 4,
                else => 0,
            };

            const target = if (rel.r_extern == 0) blk: {
                const nsect = rel.r_symbolnum - 1;
                const taddr: i64 = if (rel.r_pcrel == 1)
                    @as(i64, @intCast(sect.addr)) + rel.r_address + addend + 4
                else
                    addend;
                const target = self.findAtomInSection(@intCast(taddr), @intCast(nsect));
                addend = taddr - @as(i64, @intCast(macho_file.getAtom(target).?.getInputSection(macho_file).addr));
                break :blk target;
            } else self.symbols.items[rel.r_symbolnum];

            out.appendAssumeCapacity(.{
                .tag = if (rel.r_extern == 1) .@"extern" else .local,
                .offset = rel_offset,
                .target = target,
                .addend = addend,
                .meta = .{
                    .pcrel = rel.r_pcrel == 1,
                    .length = rel.r_length,
                    .type = rel.r_type,
                    .symbolnum = rel.r_symbolnum,
                },
            });
        }

        mem.sort(Relocation, out.items, {}, Relocation.lessThan);
    }

    for (slice.items(.header), slice.items(.relocs), slice.items(.subsections)) |sect, relocs, subsections| {
        if (sect.isZerofill()) continue;

        var next_reloc: usize = 0;
        for (subsections.items) |subsection| {
            const atom = macho_file.getAtom(subsection.atom).?;
            if (!atom.flags.alive) continue;
            if (next_reloc >= relocs.items.len) break;
            const end_addr = atom.off + atom.size;
            atom.relocs.pos = next_reloc;

            while (next_reloc < relocs.items.len and relocs.items[next_reloc].offset < end_addr) : (next_reloc += 1) {}

            atom.relocs.len = next_reloc - atom.relocs.pos;
        }
    }
}

fn initEhFrameRecords(self: *Object, sect_id: u8, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const relocs = self.sections.items(.relocs)[sect_id];

    // TODO check for non-personality relocs in FDEs and apply them

    const data = self.getSectionData(sect_id);
    var it = eh_frame.Iterator{ .data = data };
    while (try it.next()) |rec| {
        switch (rec.tag) {
            .cie => try self.cies.append(gpa, .{
                .offset = rec.offset,
                .size = rec.size,
                .file = self.index,
            }),
            .fde => try self.fdes.append(gpa, .{
                .offset = rec.offset,
                .size = rec.size,
                .cie = undefined,
                .file = self.index,
            }),
        }
    }

    for (self.cies.items) |*cie| {
        try cie.parse(macho_file);
    }

    for (self.fdes.items) |*fde| {
        try fde.parse(macho_file);
    }

    const sortFn = struct {
        fn sortFn(ctx: *MachO, lhs: Fde, rhs: Fde) bool {
            return lhs.getAtom(ctx).getInputAddress(ctx) < rhs.getAtom(ctx).getInputAddress(ctx);
        }
    }.sortFn;

    mem.sort(Fde, self.fdes.items, macho_file, sortFn);

    // Parse and attach personality pointers to CIEs if any
    for (relocs.items) |rel| {
        const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.meta.type);
        switch (rel_type) {
            .X86_64_RELOC_GOT => {
                assert(rel.meta.length == 2 and rel.tag == .@"extern"); // TODO error
                const cie = for (self.cies.items) |*cie| {
                    if (cie.offset <= rel.offset and rel.offset < cie.offset + cie.getSize()) break cie;
                } else unreachable; // TODO error
                cie.personality = .{ .index = @intCast(rel.target), .offset = rel.offset - cie.offset };
            },
            else => {},
        }
    }
}

fn initUnwindRecords(self: *Object, sect_id: u8, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const data = self.getSectionData(sect_id);
    const nrecs = @divExact(data.len, @sizeOf(macho.compact_unwind_entry));
    const recs = @as([*]align(1) const macho.compact_unwind_entry, @ptrCast(data.ptr))[0..nrecs];

    try self.unwind_records.resize(gpa, nrecs);

    const relocs = self.sections.items(.relocs)[sect_id].items;
    var reloc_idx: usize = 0;
    for (recs, self.unwind_records.items, 0..) |rec, *out_index, rec_idx| {
        const rec_start = rec_idx * @sizeOf(macho.compact_unwind_entry);
        const rec_end = rec_start + @sizeOf(macho.compact_unwind_entry);
        const reloc_start = reloc_idx;
        while (reloc_idx < relocs.len and
            relocs[reloc_idx].offset < rec_end) : (reloc_idx += 1)
        {}

        out_index.* = try macho_file.addUnwindRecord();
        const out = macho_file.getUnwindRecord(out_index.*);
        out.length = rec.rangeLength;
        out.enc = .{ .enc = rec.compactUnwindEncoding };

        for (relocs[reloc_start..reloc_idx]) |rel| {
            const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.meta.type);
            assert(rel_type == .X86_64_RELOC_UNSIGNED and rel.meta.length == 3); // TODO error
            const offset = rel.offset - rec_start;
            switch (offset) {
                0 => switch (rel.tag) { // target symbol
                    .@"extern" => {
                        out.atom = self.symtab.items(.atom)[rel.meta.symbolnum];
                        out.atom_offset = @intCast(rec.rangeStart);
                    },
                    .local => {
                        out.atom = self.findAtom(rec.rangeStart);
                        const atom = out.getAtom(macho_file);
                        out.atom_offset = @intCast(rec.rangeStart - atom.getInputAddress(macho_file));
                    },
                },
                16 => { // personality function
                    assert(rel.tag == .@"extern"); // TODO error
                    out.personality = rel.target;
                },
                24 => switch (rel.tag) { // lsda
                    .@"extern" => {
                        out.lsda = self.symtab.items(.atom)[rel.meta.symbolnum];
                        out.lsda_offset = @intCast(rec.lsda);
                    },
                    .local => {
                        out.lsda = self.findAtom(rec.lsda);
                        const atom = out.getLsdaAtom(macho_file).?;
                        out.lsda_offset = @intCast(rec.lsda - atom.getInputAddress(macho_file));
                    },
                },
                else => {},
            }
        }
    }

    // Synthesise missing unwind records.
    // The logic here is as follows:
    // 1. if an atom has unwind info record that is not DWARF, FDE is marked dead
    // 2. if an atom has unwind info record that is DWARF, FDE is tied to this unwind record
    // 3. if an atom doesn't have unwind info record but FDE is available, synthesise and tie
    // 4. if an atom doesn't have either, synthesise a null unwind info record

    const Superposition = struct { atom: Atom.Index, size: u64, cu: ?UnwindInfo.Record.Index = null, fde: ?Fde.Index = null };

    var superposition = std.AutoArrayHashMap(u64, Superposition).init(gpa);
    defer superposition.deinit();

    const slice = self.symtab.slice();
    for (slice.items(.nlist), slice.items(.atom), slice.items(.size)) |nlist, atom, size| {
        if (!nlist.sect()) continue;
        const sect = self.sections.items(.header)[nlist.n_sect - 1];
        if (sect.isCode()) {
            try superposition.ensureUnusedCapacity(1);
            const gop = superposition.getOrPutAssumeCapacity(nlist.n_value);
            if (gop.found_existing) {
                assert(gop.value_ptr.atom == atom and gop.value_ptr.size == size);
            }
            gop.value_ptr.* = .{ .atom = atom, .size = size };
        }
    }

    for (self.unwind_records.items) |rec_index| {
        const rec = macho_file.getUnwindRecord(rec_index);
        const atom = rec.getAtom(macho_file);
        const addr = atom.getInputAddress(macho_file) + rec.atom_offset;
        superposition.getPtr(addr).?.cu = rec_index;
    }

    for (self.fdes.items, 0..) |fde, fde_index| {
        const atom = fde.getAtom(macho_file);
        const addr = atom.getInputAddress(macho_file) + fde.atom_offset;
        superposition.getPtr(addr).?.fde = @intCast(fde_index);
    }

    for (superposition.keys(), superposition.values()) |addr, meta| {
        self.has_unwind = true;

        if (meta.fde) |fde_index| {
            const fde = &self.fdes.items[fde_index];

            if (meta.cu) |rec_index| {
                const rec = macho_file.getUnwindRecord(rec_index);
                if (!rec.enc.isDwarf(macho_file)) {
                    // Mark FDE dead
                    fde.alive = false;
                } else {
                    // Tie FDE to unwind record
                    rec.fde = fde_index;
                    self.has_eh_frame = true;
                }
            } else {
                // Synthesise new unwind info record
                const fde_data = fde.getData(macho_file);
                const atom_size = mem.readInt(u64, fde_data[16..][0..8], .little);
                const rec_index = try macho_file.addUnwindRecord();
                const rec = macho_file.getUnwindRecord(rec_index);
                try self.unwind_records.append(gpa, rec_index);
                rec.length = @intCast(atom_size);
                rec.atom = fde.atom;
                rec.atom_offset = fde.atom_offset;
                rec.fde = fde_index;
                rec.file = fde.file;
                rec.enc.setMode(macho.UNWIND_X86_64_MODE.DWARF);
                self.has_eh_frame = true;
            }
        } else if (meta.cu == null and meta.fde == null) {
            // Create a null record
            const rec_index = try macho_file.addUnwindRecord();
            const rec = macho_file.getUnwindRecord(rec_index);
            const atom = macho_file.getAtom(meta.atom).?;
            try self.unwind_records.append(gpa, rec_index);
            rec.length = @intCast(meta.size);
            rec.atom = meta.atom;
            rec.atom_offset = @intCast(addr - atom.getInputSection(macho_file).addr - atom.off);
            rec.file = self.index;
        }
    }

    const sortFn = struct {
        fn sortFn(ctx: *MachO, lhs_index: UnwindInfo.Record.Index, rhs_index: UnwindInfo.Record.Index) bool {
            const lhs = ctx.getUnwindRecord(lhs_index);
            const rhs = ctx.getUnwindRecord(rhs_index);
            const lhsa = lhs.getAtom(ctx);
            const rhsa = rhs.getAtom(ctx);
            return lhsa.getInputAddress(ctx) + lhs.atom_offset < rhsa.getInputAddress(ctx) + rhs.atom_offset;
        }
    }.sortFn;
    mem.sort(UnwindInfo.Record.Index, self.unwind_records.items, macho_file, sortFn);

    // Associate unwind records to atoms
    var next_cu: u32 = 0;
    while (next_cu < self.unwind_records.items.len) {
        const start = next_cu;
        const rec_index = self.unwind_records.items[start];
        const rec = macho_file.getUnwindRecord(rec_index);
        while (next_cu < self.unwind_records.items.len and
            macho_file.getUnwindRecord(self.unwind_records.items[next_cu]).atom == rec.atom) : (next_cu += 1)
        {}

        const atom = rec.getAtom(macho_file);
        atom.unwind_records = .{ .pos = start, .len = next_cu - start };
    }
}

fn initPlatform(self: *Object) void {
    var it = LoadCommandIterator{
        .ncmds = self.header.?.ncmds,
        .buffer = self.data[@sizeOf(macho.mach_header_64)..][0..self.header.?.sizeofcmds],
    };
    self.platform = while (it.next()) |cmd| {
        switch (cmd.cmd()) {
            .BUILD_VERSION,
            .VERSION_MIN_MACOSX,
            .VERSION_MIN_IPHONEOS,
            .VERSION_MIN_TVOS,
            .VERSION_MIN_WATCHOS,
            => break MachO.Options.Platform.fromLoadCommand(cmd),
            else => {},
        }
    } else null;
}

/// Currently, we only check if a compile unit for this input object file exists
/// and record that so that we can emit symbol stabs.
/// TODO in the future, we want parse debug info and debug line sections so that
/// we can provide nice error locations to the user.
fn initDwarfInfo(self: *Object, allocator: Allocator) !void {
    var debug_info_index: ?usize = null;
    var debug_abbrev_index: ?usize = null;
    var debug_str_index: ?usize = null;

    for (self.sections.items(.header), 0..) |sect, index| {
        if (sect.attrs() & macho.S_ATTR_DEBUG == 0) continue;
        if (mem.eql(u8, sect.sectName(), "__debug_info")) debug_info_index = index;
        if (mem.eql(u8, sect.sectName(), "__debug_abbrev")) debug_abbrev_index = index;
        if (mem.eql(u8, sect.sectName(), "__debug_str")) debug_str_index = index;
    }

    if (debug_info_index == null or debug_abbrev_index == null) return;

    var dwarf_info = DwarfInfo{
        .debug_info = self.getSectionData(@intCast(debug_info_index.?)),
        .debug_abbrev = self.getSectionData(@intCast(debug_abbrev_index.?)),
        .debug_str = if (debug_str_index) |index| self.getSectionData(@intCast(index)) else "",
    };
    dwarf_info.init(allocator) catch return; // TODO flag an error
    self.dwarf_info = dwarf_info;
}

pub fn resolveSymbols(self: *Object, macho_file: *MachO) void {
    for (self.symbols.items, 0..) |index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        const atom_index = self.symtab.items(.atom)[nlist_idx];

        if (!nlist.ext()) continue;
        if (nlist.undf() and !nlist.tentative()) continue;
        if (nlist.sect()) {
            const atom = macho_file.getAtom(atom_index).?;
            if (!atom.flags.alive) continue;
        }

        const symbol = macho_file.getSymbol(index);
        if (self.asFile().getSymbolRank(.{
            .archive = !self.alive,
            .weak = nlist.weakDef(),
            .tentative = nlist.tentative(),
        }) < symbol.getSymbolRank(macho_file)) {
            const value = if (nlist.sect()) blk: {
                const atom = macho_file.getAtom(atom_index).?;
                break :blk nlist.n_value - atom.getInputAddress(macho_file);
            } else nlist.n_value;
            symbol.value = value;
            symbol.atom = atom_index;
            symbol.nlist_idx = nlist_idx;
            symbol.file = self.index;
            symbol.flags.weak = nlist.weakDef();
            symbol.flags.tentative = nlist.tentative();
            symbol.flags.weak_ref = false;
            symbol.flags.dyn_ref = nlist.n_desc & macho.REFERENCED_DYNAMICALLY != 0;
            symbol.flags.no_dead_strip = symbol.flags.no_dead_strip or nlist.noDeadStrip();

            if (nlist.pext() or nlist.weakDef() and nlist.weakRef()) {
                if (symbol.visibility != .global) {
                    symbol.visibility = .linkage;
                }
            } else {
                symbol.visibility = .global;
            }

            if (nlist.sect() and
                self.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
            {
                symbol.flags.tlv = true;
            }
        }
    }
}

pub fn resetGlobals(self: *Object, macho_file: *MachO) void {
    for (self.symbols.items, 0..) |sym_index, nlist_idx| {
        if (!self.symtab.items(.nlist)[nlist_idx].ext()) continue;
        const sym = macho_file.getSymbol(sym_index);
        const name = sym.name;
        sym.* = .{};
        sym.name = name;
    }
}

pub fn markLive(self: *Object, macho_file: *MachO) void {
    for (self.symbols.items, 0..) |index, nlist_idx| {
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        if (!nlist.ext()) continue;

        const sym = macho_file.getSymbol(index);
        const file = sym.getFile(macho_file) orelse continue;
        const should_keep = nlist.undf() or (nlist.tentative() and !sym.getNlist(macho_file).tentative());
        if (should_keep and !file.isAlive()) {
            file.setAlive();
            file.markLive(macho_file);
        }
    }
}

pub fn scanRelocs(self: Object, macho_file: *MachO) !void {
    for (self.atoms.items) |atom_index| {
        const atom = macho_file.getAtom(atom_index).?;
        if (!atom.flags.alive) continue;
        const sect = atom.getInputSection(macho_file);
        if (sect.isZerofill()) continue;
        try atom.scanRelocs(macho_file);
    }

    for (self.unwind_records.items) |rec_index| {
        const rec = macho_file.getUnwindRecord(rec_index);
        if (!rec.alive) continue;
        if (rec.getFde(macho_file)) |fde| {
            if (fde.getCie(macho_file).getPersonality(macho_file)) |sym| {
                sym.flags.got = true;
            }
        } else if (rec.getPersonality(macho_file)) |sym| {
            sym.flags.got = true;
        }
    }
}

pub fn convertTentativeDefinitions(self: *Object, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    for (self.symbols.items, 0..) |index, i| {
        const sym = macho_file.getSymbol(index);
        if (!sym.flags.tentative) continue;
        const sym_file = sym.getFile(macho_file).?;
        if (sym_file.getIndex() != self.index) continue;

        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = &self.symtab.items(.nlist)[nlist_idx];
        const nlist_atom = &self.symtab.items(.atom)[nlist_idx];

        const atom_index = try macho_file.addAtom();
        try self.atoms.append(gpa, atom_index);

        const name = try std.fmt.allocPrintZ(gpa, "__DATA$__common${s}", .{sym.getName(macho_file)});
        defer gpa.free(name);
        const atom = macho_file.getAtom(atom_index).?;
        atom.atom_index = atom_index;
        atom.name = try macho_file.string_intern.insert(gpa, name);
        atom.file = self.index;
        atom.size = nlist.n_value;
        atom.alignment = (nlist.n_desc >> 8) & 0x0f;

        const n_sect = try self.addSection(gpa, "__DATA", "__common");
        const sect = &self.sections.items(.header)[n_sect];
        sect.flags = macho.S_ZEROFILL;
        sect.size = atom.size;
        sect.@"align" = atom.alignment;
        atom.n_sect = n_sect;

        sym.value = 0;
        sym.atom = atom_index;
        sym.flags.weak = false;
        sym.flags.weak_ref = false;
        sym.flags.tentative = false;
        sym.visibility = .global;

        nlist.n_value = 0;
        nlist.n_type = macho.N_EXT | macho.N_SECT;
        nlist.n_sect = n_sect + 1;
        nlist.n_desc = 0;
        nlist_atom.* = atom_index;
    }
}

fn addSection(self: *Object, allocator: Allocator, segname: []const u8, sectname: []const u8) !u8 {
    const n_sect = @as(u8, @intCast(try self.sections.addOne(allocator)));
    self.sections.set(n_sect, .{
        .header = .{
            .sectname = MachO.makeStaticString(sectname),
            .segname = MachO.makeStaticString(segname),
        },
    });
    return n_sect;
}

pub fn calcSymtabSize(self: *Object, macho_file: *MachO) !void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        const file = sym.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        if (sym.getAtom(macho_file)) |atom| if (!atom.flags.alive) continue;
        if (sym.getNlist(macho_file).stab()) continue;
        sym.flags.output_symtab = true;
        if (sym.isLocal()) {
            try sym.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, macho_file);
            self.output_symtab_ctx.nlocals += 1;
        } else if (sym.flags.@"export") {
            try sym.addExtra(.{ .symtab = self.output_symtab_ctx.nexports }, macho_file);
            self.output_symtab_ctx.nexports += 1;
        } else {
            assert(sym.flags.import);
            try sym.addExtra(.{ .symtab = self.output_symtab_ctx.nimports }, macho_file);
            self.output_symtab_ctx.nimports += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(sym.getName(macho_file).len + 1));
    }

    if (!macho_file.options.strip and self.hasDebugInfo()) self.calcStabsSize(macho_file);
}

pub fn calcStabsSize(self: *Object, macho_file: *MachO) void {
    // TODO handle multiple CUs
    const dw = self.dwarf_info.?;
    const cu = dw.compile_units.items[0];
    const comp_dir = cu.getCompileDir(dw) orelse return;
    const tu_name = cu.getSourceFile(dw) orelse return;

    self.output_symtab_ctx.nstabs += 4; // N_SO, N_SO, N_OSO, N_SO
    self.output_symtab_ctx.strsize += @as(u32, @intCast(comp_dir.len + 1)); // comp_dir
    self.output_symtab_ctx.strsize += @as(u32, @intCast(tu_name.len + 1)); // tu_name

    if (self.archive) |path| {
        self.output_symtab_ctx.strsize += @as(u32, @intCast(path.len + 1 + self.path.len + 1 + 1));
    } else {
        self.output_symtab_ctx.strsize += @as(u32, @intCast(self.path.len + 1));
    }

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        const file = sym.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        if (!sym.flags.output_symtab) continue;
        const sect = macho_file.sections.items(.header)[sym.out_n_sect];
        if (sect.isCode()) {
            self.output_symtab_ctx.nstabs += 4; // N_BNSYM, N_FUN, N_FUN, N_ENSYM
        } else if (sym.visibility == .global) {
            self.output_symtab_ctx.nstabs += 1; // N_GSYM
        } else {
            self.output_symtab_ctx.nstabs += 1; // N_STSYM
        }
    }
}

pub fn writeSymtab(self: Object, macho_file: *MachO) void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        const file = sym.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        const idx = sym.getOutputSymtabIndex(macho_file) orelse continue;
        const n_strx = @as(u32, @intCast(macho_file.strtab.items.len));
        macho_file.strtab.appendSliceAssumeCapacity(sym.getName(macho_file));
        macho_file.strtab.appendAssumeCapacity(0);
        const out_sym = &macho_file.symtab.items[idx];
        out_sym.n_strx = n_strx;
        sym.setOutputSym(macho_file, out_sym);
    }

    if (!macho_file.options.strip and self.hasDebugInfo()) self.writeStabs(macho_file);
}

pub fn writeStabs(self: Object, macho_file: *MachO) void {
    const writeFuncStab = struct {
        inline fn writeFuncStab(
            n_strx: u32,
            n_sect: u8,
            n_value: u64,
            size: u64,
            index: u32,
            ctx: *MachO,
        ) void {
            ctx.symtab.items[index] = .{
                .n_strx = 0,
                .n_type = macho.N_BNSYM,
                .n_sect = n_sect,
                .n_desc = 0,
                .n_value = n_value,
            };
            ctx.symtab.items[index + 1] = .{
                .n_strx = n_strx,
                .n_type = macho.N_FUN,
                .n_sect = n_sect,
                .n_desc = 0,
                .n_value = n_value,
            };
            ctx.symtab.items[index + 2] = .{
                .n_strx = 0,
                .n_type = macho.N_FUN,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = size,
            };
            ctx.symtab.items[index + 3] = .{
                .n_strx = 0,
                .n_type = macho.N_ENSYM,
                .n_sect = n_sect,
                .n_desc = 0,
                .n_value = size,
            };
        }
    }.writeFuncStab;

    // TODO handle multiple CUs
    const dw = self.dwarf_info.?;
    const cu = dw.compile_units.items[0];
    const comp_dir = cu.getCompileDir(dw) orelse return;
    const tu_name = cu.getSourceFile(dw) orelse return;

    var index = self.output_symtab_ctx.istab;

    // Open scope
    // N_SO comp_dir
    var n_strx = @as(u32, @intCast(macho_file.strtab.items.len));
    macho_file.strtab.appendSliceAssumeCapacity(comp_dir);
    macho_file.strtab.appendAssumeCapacity(0);
    macho_file.symtab.items[index] = .{
        .n_strx = n_strx,
        .n_type = macho.N_SO,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
    index += 1;
    // N_SO tu_name
    n_strx = @as(u32, @intCast(macho_file.strtab.items.len));
    macho_file.strtab.appendSliceAssumeCapacity(tu_name);
    macho_file.strtab.appendAssumeCapacity(0);
    macho_file.symtab.items[index] = .{
        .n_strx = n_strx,
        .n_type = macho.N_SO,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
    index += 1;
    // N_OSO path
    n_strx = @as(u32, @intCast(macho_file.strtab.items.len));
    if (self.archive) |path| {
        macho_file.strtab.appendSliceAssumeCapacity(path);
        macho_file.strtab.appendAssumeCapacity('(');
        macho_file.strtab.appendSliceAssumeCapacity(self.path);
        macho_file.strtab.appendAssumeCapacity(')');
        macho_file.strtab.appendAssumeCapacity(0);
    } else {
        macho_file.strtab.appendSliceAssumeCapacity(self.path);
        macho_file.strtab.appendAssumeCapacity(0);
    }
    macho_file.symtab.items[index] = .{
        .n_strx = n_strx,
        .n_type = macho.N_OSO,
        .n_sect = 0,
        .n_desc = 1,
        .n_value = self.mtime,
    };
    index += 1;

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        const file = sym.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        if (!sym.flags.output_symtab) continue;
        const sect = macho_file.sections.items(.header)[sym.out_n_sect];
        const sym_n_strx = n_strx: {
            const symtab_index = sym.getOutputSymtabIndex(macho_file).?;
            const osym = macho_file.symtab.items[symtab_index];
            break :n_strx osym.n_strx;
        };
        const sym_n_sect: u8 = if (!sym.isAbs(macho_file)) @intCast(sym.out_n_sect + 1) else 0;
        const sym_n_value = sym.getAddress(.{}, macho_file);
        const sym_size = sym.getSize(macho_file);
        if (sect.isCode()) {
            writeFuncStab(sym_n_strx, sym_n_sect, sym_n_value, sym_size, index, macho_file);
            index += 4;
        } else if (sym.visibility == .global) {
            macho_file.symtab.items[index] = .{
                .n_strx = sym_n_strx,
                .n_type = macho.N_GSYM,
                .n_sect = sym_n_sect,
                .n_desc = 0,
                .n_value = 0,
            };
            index += 1;
        } else {
            macho_file.symtab.items[index] = .{
                .n_strx = sym_n_strx,
                .n_type = macho.N_STSYM,
                .n_sect = sym_n_sect,
                .n_desc = 0,
                .n_value = sym_n_value,
            };
            index += 1;
        }
    }

    // Close scope
    // N_SO
    macho_file.symtab.items[index] = .{
        .n_strx = 0,
        .n_type = macho.N_SO,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
}

pub fn claimUnresolved(self: Object, macho_file: *MachO) void {
    for (self.symbols.items, 0..) |sym_index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        if (!nlist.ext()) continue;
        if (!nlist.undf()) continue;

        const sym = macho_file.getSymbol(sym_index);
        if (sym.getFile(macho_file) != null) continue;

        const is_import = switch (macho_file.options.undefined_treatment) {
            .@"error" => false,
            .warn, .suppress => nlist.weakRef(),
            .dynamic_lookup => true,
        };

        sym.value = 0;
        sym.atom = 0;
        sym.nlist_idx = nlist_idx;
        sym.file = self.index;
        sym.flags.weak = false;
        sym.flags.weak_ref = nlist.weakRef();
        sym.flags.import = is_import;
        sym.visibility = .global;
    }
}

fn getLoadCommand(self: Object, lc: macho.LC) ?LoadCommandIterator.LoadCommand {
    var it = LoadCommandIterator{
        .ncmds = self.header.?.ncmds,
        .buffer = self.data[@sizeOf(macho.mach_header_64)..][0..self.header.?.sizeofcmds],
    };
    while (it.next()) |cmd| {
        if (cmd.cmd() == lc) return cmd;
    } else return null;
}

pub fn getSectionData(self: Object, index: u8) []const u8 {
    assert(index < self.sections.items(.header).len);
    const sect = self.sections.items(.header)[index];
    return self.data[sect.offset..][0..sect.size];
}

fn getString(self: Object, off: u32) [:0]const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.ptr + off)), 0);
}

/// TODO handle multiple CUs
pub fn hasDebugInfo(self: Object) bool {
    const dw = self.dwarf_info orelse return false;
    return dw.compile_units.items.len > 0;
}

pub fn getDataInCode(self: Object) []align(1) const macho.data_in_code_entry {
    const lc = self.getLoadCommand(.DATA_IN_CODE) orelse return &[0]macho.data_in_code_entry{};
    const cmd = lc.cast(macho.linkedit_data_command).?;
    const ndice = @divExact(cmd.datasize, @sizeOf(macho.data_in_code_entry));
    const dice = @as(
        [*]align(1) const macho.data_in_code_entry,
        @ptrCast(self.data.ptr + cmd.dataoff),
    )[0..ndice];
    return dice;
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

const FormatContext = struct {
    object: *Object,
    macho_file: *MachO,
};

pub fn fmtAtoms(self: *Object, macho_file: *MachO) std.fmt.Formatter(formatAtoms) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
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
        const atom = ctx.macho_file.getAtom(atom_index).?;
        try writer.print("    {}\n", .{atom.fmt(ctx.macho_file)});
    }
}

pub fn fmtCies(self: *Object, macho_file: *MachO) std.fmt.Formatter(formatCies) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
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
        try writer.print("    cie({d}) : {}\n", .{ i, cie.fmt(ctx.macho_file) });
    }
}

pub fn fmtFdes(self: *Object, macho_file: *MachO) std.fmt.Formatter(formatFdes) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
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
        try writer.print("    fde({d}) : {}\n", .{ i, fde.fmt(ctx.macho_file) });
    }
}

pub fn fmtUnwindRecords(self: *Object, macho_file: *MachO) std.fmt.Formatter(formatUnwindRecords) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
    } };
}

fn formatUnwindRecords(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    const macho_file = ctx.macho_file;
    try writer.writeAll("  unwind records\n");
    for (object.unwind_records.items) |rec| {
        try writer.print("    rec({d}) : {}\n", .{ rec, macho_file.getUnwindRecord(rec).fmt(macho_file) });
    }
}

pub fn fmtSymtab(self: *Object, macho_file: *MachO) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
    } };
}

fn formatSymtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.writeAll("  symbols\n");
    for (object.symbols.items) |index| {
        const sym = ctx.macho_file.getSymbol(index);
        try writer.print("    {}\n", .{sym.fmt(ctx.macho_file)});
    }
}

pub fn fmtPath(self: Object) std.fmt.Formatter(formatPath) {
    return .{ .data = self };
}

fn formatPath(
    object: Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    if (object.archive) |path| {
        try writer.writeAll(path);
        try writer.writeByte('(');
        try writer.writeAll(object.path);
        try writer.writeByte(')');
    } else try writer.writeAll(object.path);
}

const Section = struct {
    header: macho.section_64,
    subsections: std.ArrayListUnmanaged(Subsection) = .{},
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
};

const Subsection = struct {
    atom: Atom.Index,
    off: u64,
};

pub const Relocation = struct {
    tag: enum { @"extern", local },
    offset: u32,
    target: u32,
    addend: i64,
    meta: packed struct {
        pcrel: bool,
        length: u2,
        type: u4,
        symbolnum: u24,
    },

    pub fn getTargetSymbol(rel: Relocation, macho_file: *MachO) *Symbol {
        assert(rel.tag == .@"extern");
        return macho_file.getSymbol(rel.target);
    }

    pub fn getTargetAtom(rel: Relocation, macho_file: *MachO) *Atom {
        assert(rel.tag == .local);
        return macho_file.getAtom(rel.target).?;
    }

    pub fn lessThan(ctx: void, lhs: Relocation, rhs: Relocation) bool {
        _ = ctx;
        return lhs.offset < rhs.offset;
    }
};

const Nlist = struct {
    nlist: macho.nlist_64,
    size: u64,
    atom: Atom.Index,
};

const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Cie = eh_frame.Cie;
const DwarfInfo = @import("DwarfInfo.zig");
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const LoadCommandIterator = macho.LoadCommandIterator;
const MachO = @import("../MachO.zig");
const Object = @This();
const StringTable = @import("../strtab.zig").StringTable;
const Symbol = @import("Symbol.zig");
const UnwindInfo = @import("UnwindInfo.zig");
