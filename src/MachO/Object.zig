archive: ?[]const u8 = null,
path: []const u8,
mtime: u64,
data: []const u8,
index: File.Index,

header: ?macho.mach_header_64 = null,
sections: std.MultiArrayList(Section) = .{},
symtab: std.MultiArrayList(Nlist) = .{},
strtab: []const u8 = &[0]u8{},

sorted_symtab: std.ArrayListUnmanaged(Symbol.Index) = .{},
symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

data_in_code: std.ArrayListUnmanaged(macho.data_in_code_entry) = .{},
platform: ?MachO.Options.Platform = null,
dwarf_info: ?DwarfInfo = null,

alive: bool = true,
num_rebase_relocs: u32 = 0,
num_bind_relocs: u32 = 0,

output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn deinit(self: *Object, gpa: Allocator) void {
    self.symtab.deinit(gpa);
    self.symbols.deinit(gpa);
    self.sorted_symtab.deinit(gpa);
    self.atoms.deinit(gpa);
    self.data_in_code.deinit(gpa);
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

    // TODO
    // if (self.header.?.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0) {
    //     try self.initSubsections(macho_file);
    // } else {
    try self.initSections(macho_file);
    // }

    try self.initSymbols(macho_file);

    try self.sortAtoms(macho_file);
    try self.initRelocs(macho_file);

    // // TODO ICF
    // // TODO __eh_frame records

    self.initPlatform();
    try self.initDwarfInfo(gpa);
}

fn initSections(self: *Object, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    try self.atoms.ensureUnusedCapacity(gpa, self.sections.items(.header).len);

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (sect.attrs() & macho.S_ATTR_DEBUG != 0) continue;
        if (sect.type() == macho.S_COALESCED and mem.eql(u8, "__eh_frame", sect.sectName())) continue;

        const name = try std.fmt.allocPrintZ(gpa, "{s}${s}", .{ sect.segName(), sect.sectName() });
        defer gpa.free(name);
        const atom_index = try macho_file.addAtom();
        const atom = macho_file.getAtom(atom_index).?;
        atom.file = self.index;
        atom.atom_index = atom_index;
        atom.name = try macho_file.string_intern.insert(gpa, name);
        atom.n_sect = @intCast(n_sect);
        atom.size = sect.size;
        atom.alignment = sect.@"align";
        self.atoms.appendAssumeCapacity(atom_index);
        try slice.items(.subsections)[n_sect].putNoClobber(gpa, 0, atom_index);
    }

    for (self.symtab.items(.nlist), self.symtab.items(.atom)) |nlist, *atom| {
        if (!nlist.stab() and nlist.sect()) {
            atom.* = slice.items(.subsections)[nlist.n_sect - 1].get(0).?;
        }
    }
}

// fn initSubsections(self: *Object, macho_file: *MachO) !void {
//     const gpa = macho_file.base.allocator;
//     const symbols = try gpa.alloc(SortedSymbolIndex, self.iundefsym);
//     defer gpa.free(symbols);
//     for (0..self.iundefsym, symbols) |idx, *out| {
//         out.index = @intCast(idx);
//     }

//     mem.sort(SortedSymbolIndex, symbols, self, SortedSymbolIndex.lessThan);

//     const subsections = try gpa.alloc(struct { usize, usize }, self.sections.items(.header).len);
//     defer gpa.free(subsections);

//     var idx: usize = 0;
//     while (idx < symbols.len) {
//         const curr = idx;
//         const sym = symbols[curr].getSymbol(self);

//         while (idx < symbols.len) : (idx += 1) {
//             const next = symbols[idx].getSymbol(self);
//             if (next.n_sect != sym.n_sect) break;
//         }

//         subsections[sym.n_sect - 1] = .{ curr, idx };
//     }

//     for (self.sections.items(.header), 0..) |sect, n_sect| {
//         if (sect.attrs() & macho.S_ATTR_DEBUG != 0) continue;

//         switch (sect.type()) {
//             macho.S_CSTRING_LITERALS,
//             macho.S_4BYTE_LITERALS,
//             macho.S_8BYTE_LITERALS,
//             macho.S_16BYTE_LITERALS,
//             macho.S_COALESCED,
//             => continue,

//             else => {},
//         }

//         const indexes = subsections[n_sect];
//         const sect_symbols = symbols[indexes[0]..indexes[1]];
//         var i: usize = 0;
//         while (i < sect_symbols.len) {
//             var curr = i;
//             const sym = sect_symbols[curr].getSymbol(self);

//             while (i < sect_symbols.len) : (i += 1) {
//                 const next = sect_symbols[i + 1].getSymbol(self);
//                 if (next.n_value != sym.n_value) break;
//             }

//             const size = sect_symbols[curr].getSize(self);
//             const alignment = if (sym.n_value > 0)
//                 @min(@ctz(sym.n_value), sect.@"align")
//             else
//                 sect.@"align";
//             const atom_index = try macho_file.addAtom();
//             const atom = macho_file.getAtom(atom_index).?;
//             atom.file = self.index;
//             atom.atom_index = atom_index;
//             atom.name = try macho_file.string_intern.insert(gpa, self.getString(sym.n_strx));
//             atom.n_sect = @intCast(n_sect);
//             atom.size = size;
//             atom.alignment = alignment;
//             atom.off = sym.n_value - sect.addr;
//             try self.atoms.append(gpa, atom_index);

//             macho_file.getAtom(self.atoms.items[n_sect]).?.flags.alive = false;

//             while (curr < i) : (curr += 1) {
//                 const osym_index = self.symbols.items[sect_symbols[curr].index];
//                 const osym = macho_file.getSymbol(osym_index);
//                 if (osym.getFile(macho_file)) |file| {
//                     if (file.getIndex() == self.index) {
//                         osym.value = 0;
//                         osym.atom = atom_index;
//                     }
//                 }
//             }
//         }
//     }
// }

// fn defSymLessThan(ctx: *const Object, lhs: u32, rhs: u32) bool {
//     const lhss = ctx.symtab.items(.nlist)[lhs];
//     const rhss = ctx.symtab.items(.nlist)[rhs];
//     if (lhss.n_value == rhss.n_value) {
//         if (lhss.n_sect == rhss.n_sect) {
//             return lhss.n_strx < rhss.n_strx;
//         } else return lhss.n_sect < rhss.n_sect;
//     } else return lhss.n_value < rhss.n_value;
// }

// fn initSymtab(self: *Object, cmd: macho.symtab_command, macho_file: *MachO) !void {
//     const gpa = macho_file.base.allocator;

//     self.strtab = self.data[cmd.stroff..][0..cmd.strsize];

//     const symtab = @as([*]align(1) const macho.nlist_64, @ptrCast(self.data.ptr + cmd.symoff))[0..cmd.nsyms];
//     try self.symtab.ensureUnusedCapacity(gpa, symtab.len);
//     for (symtab) |nlist| {
//         self.symtab.appendAssumeCapacity(.{
//             .nlist = nlist,
//             .atom = 0,
//             .size = 0,
//         });
//     }

//     if (self.getLoadCommand(.DYSYMTAB)) |lc| {
//         const dysym_cmd = lc.cast(macho.dysymtab_command).?;
//         self.iextdefsym = dysym_cmd.iextdefsym;
//         self.iundefsym = dysym_cmd.iundefsym;
//     } else @panic("TODO no DYSYMTAB, work out iextdefsym and iundefsym");

//     // TODO handle absolute symbols
//     try self.sorted_symtab.resize(gpa, self.iundefsym);
//     for (0..self.iundefsym, self.sorted_symtab.items) |idx, *out| {
//         out.* = @intCast(idx);
//     }

//     mem.sort(Symbol.Index, self.sorted_symtab.items, self, defSymLessThan);

//     var idx: usize = 0;
//     while (idx < self.sorted_symtab.items.len) {
//         var curr = idx;
//         const sym = self.symtab.items(.nlist)[self.sorted_symtab.items[curr]];
//         const sect = self.sections.items(.header)[sym.n_sect - 1];

//         while (idx < self.sorted_symtab.items.len) : (idx += 1) {
//             const next = self.symtab.items(.nlist)[self.sorted_symtab.items[idx]];
//             if (next.n_value != sym.n_value or next.n_sect != sym.n_sect) break;
//         }

//         self.sections.items(.nlists)[sym.n_sect - 1] = .{
//             .pos = curr,
//             .len = idx - curr,
//         };

//         const next = if (idx < self.sorted_symtab.items.len)
//             self.symtab.items(.nlist)[self.sorted_symtab.items[idx]]
//         else
//             null;
//         const size = size: {
//             if (next) |nn| {
//                 if (nn.n_sect == sym.n_sect) break :size nn.n_value - sym.n_value;
//             }
//             break :size sect.addr + sect.size - sym.n_value;
//         };

//         while (curr < idx) : (curr += 1) {
//             self.symtab.items(.size)[self.sorted_symtab.items[curr]] = size;
//         }
//     }
// }

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
            nlist.n_value - atom.off - atom.getInputSection(macho_file).addr;
        symbol.* = .{
            .value = value,
            .name = try macho_file.string_intern.insert(gpa, name),
            .nlist_idx = @intCast(i),
            .atom = if (nlist.abs()) 0 else atom_index,
            .file = self.index,
        };
    }
}

fn sortAtoms(self: *Object, macho_file: *MachO) !void {
    const lessThanAtom = struct {
        fn lessThanAtom(ctx: *MachO, lhs: Atom.Index, rhs: Atom.Index) bool {
            const lhsa = ctx.getAtom(lhs).?;
            const rhsa = ctx.getAtom(rhs).?;
            return lhsa.getInputSection(ctx).addr < rhsa.getInputSection(ctx).addr;
        }
    }.lessThanAtom;
    mem.sort(Atom.Index, self.atoms.items, macho_file, lessThanAtom);
}

fn initRelocs(self: *Object, macho_file: *MachO) !void {
    // std.debug.print("{}\n", .{self.fmtPath()});

    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.header), slice.items(.relocs)) |sect, *out| {
        if (sect.nreloc == 0) continue;

        const relocs = @as([*]align(1) const macho.relocation_info, @ptrCast(self.data.ptr + sect.reloff))[0..sect.nreloc];

        try out.ensureTotalCapacityPrecise(gpa, relocs.len);

        for (relocs) |rel| {
            var addend: i64 = 0;
            var target: u32 = 0;
            if (rel.r_extern == 0) {
                const nsect = rel.r_symbolnum - 1;
                const subsections = slice.items(.subsections)[nsect];
                // TODO find by offset
                target = subsections.get(0).?;
                const taddr: i64 = @intCast(slice.items(.header)[nsect].addr);
                addend = if (rel.r_pcrel == 1) blk: {
                    // off + taddr  == saddr + 4 + A
                    const saddr: i64 = @as(i64, @intCast(sect.addr)) + rel.r_address;
                    break :blk saddr + 4 - taddr;
                } else blk: {
                    // off + taddr == A
                    break :blk (-1) * taddr;
                };
            } else {
                target = self.symbols.items[rel.r_symbolnum];
            }
            out.appendAssumeCapacity(.{
                .tag = if (rel.r_extern == 1) .@"extern" else .local,
                .offset = @intCast(rel.r_address),
                .target = target,
                .s_target = rel.r_symbolnum,
                .addend = addend,
                .meta = .{
                    .pcrel = rel.r_pcrel == 1,
                    .length = rel.r_length,
                    .type = rel.r_type,
                },
            });
            // const last = out.items[out.items.len - 1];
            // std.debug.print("  {x}: {s}({d})\n", .{
            //     last.offset,
            //     switch (last.tag) {
            //         .@"extern" => "sym",
            //         .local => "atom",
            //     },
            //     last.target,
            // });
        }

        mem.sort(Relocation, out.items, {}, Relocation.lessThan);
    }

    for (slice.items(.header), slice.items(.relocs), slice.items(.subsections)) |sect, relocs, subsections| {
        if (sect.isZerofill()) continue;

        var next_reloc: usize = 0;
        for (subsections.values()) |atom_index| {
            const atom = macho_file.getAtom(atom_index).?;
            if (!atom.flags.alive) continue;
            if (next_reloc >= relocs.items.len) break;
            const end_addr = atom.off + atom.size;
            atom.relocs.pos = next_reloc;

            while (next_reloc < relocs.items.len and relocs.items[next_reloc].offset <= end_addr) : (next_reloc += 1) {}

            atom.relocs.len = next_reloc - atom.relocs.pos;
        }
    }
}

fn initDataInCode(self: *Object, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    try self.parseDataInCode(gpa);

    if (self.data_in_code.items.len == 0) return;

    var next_dice: usize = 0;
    for (self.atoms.items) |atom_index| {
        const atom = macho_file.getAtom(atom_index).?;
        if (!atom.flags.alive) continue;
        if (next_dice >= self.data_in_code.items.len) break;
        const end_off = atom.getInputSection(macho_file).addr + atom.off + atom.size;
        atom.dice.pos = next_dice;

        while (next_dice < self.data_in_code.items.len and
            self.data_in_code.items[next_dice].offset < end_off) : (next_dice += 1)
        {}

        atom.dice.len = next_dice - atom.dice.pos;
    }
}

fn parseDataInCode(self: *Object, allocator: Allocator) !void {
    const diceLessThan = struct {
        fn diceLessThan(ctx: void, lhs: macho.data_in_code_entry, rhs: macho.data_in_code_entry) bool {
            _ = ctx;
            return lhs.offset < rhs.offset;
        }
    }.diceLessThan;

    const lc = self.getLoadCommand(.DATA_IN_CODE) orelse return;
    const cmd = lc.cast(macho.linkedit_data_command).?;
    const ndice = @divExact(cmd.datasize, @sizeOf(macho.data_in_code_entry));
    const dice = @as(
        [*]align(1) const macho.data_in_code_entry,
        @ptrCast(self.data.ptr + cmd.dataoff),
    )[0..ndice];
    try self.data_in_code.ensureTotalCapacityPrecise(allocator, dice.len);
    self.data_in_code.appendUnalignedSliceAssumeCapacity(dice);
    mem.sort(macho.data_in_code_entry, self.data_in_code.items, {}, diceLessThan);
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
        if (!nlist.tentative() and !nlist.abs()) {
            const atom = macho_file.getAtom(atom_index).?;
            if (!atom.flags.alive) continue;
        }

        const symbol = macho_file.getSymbol(index);
        if (self.asFile().getSymbolRank(nlist, !self.alive) < symbol.getSymbolRank(macho_file)) {
            const value = if (!nlist.tentative() and !nlist.abs()) blk: {
                const atom = macho_file.getAtom(atom_index).?;
                break :blk nlist.n_value - atom.off - atom.getInputSection(macho_file).addr;
            } else nlist.n_value;
            symbol.value = value;
            symbol.atom = atom_index;
            symbol.nlist_idx = nlist_idx;
            symbol.file = self.index;
            symbol.flags.weak = nlist.weakDef() or nlist.pext();
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
        if (nlist.weakRef()) continue;

        const sym = macho_file.getSymbol(index);
        const file = sym.getFile(macho_file) orelse continue;
        const should_keep = nlist.undf() or (nlist.tentative() and sym.getNlist(macho_file).tentative());
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

    // TODO scan __eh_frame relocs
}

pub fn convertBoundarySymbols(self: *Object, macho_file: *MachO) !void {
    const parseBoundarySymbol = struct {
        fn parseBoundarySymbol(name: []const u8) ?struct {
            segment: bool,
            start: bool,
            segname: []const u8,
            sectname: []const u8,
        } {
            invalid: {
                var segment: ?bool = null;
                var start: ?bool = null;
                var segname: []const u8 = "";
                var sectname: []const u8 = "";

                var it = std.mem.splitScalar(u8, name, '$');
                var next = it.next() orelse break :invalid;

                if (std.mem.eql(u8, next, "segment")) {
                    segment = true;
                } else if (std.mem.eql(u8, next, "section")) {
                    segment = false;
                }

                if (segment == null) break :invalid;

                next = it.next() orelse break :invalid;

                if (std.mem.eql(u8, next, "start")) {
                    start = true;
                } else if (std.mem.eql(u8, next, "stop")) {
                    start = false;
                }

                if (start == null) break :invalid;

                segname = it.next() orelse break :invalid;
                if (!segment.?) sectname = it.next() orelse break :invalid;

                return .{
                    .segment = segment.?,
                    .start = start.?,
                    .segname = segname,
                    .sectname = sectname,
                };
            }
            return null;
        }
    }.parseBoundarySymbol;

    const gpa = macho_file.base.allocator;

    for (self.symbols.items, 0..) |index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = &self.symtab.items(.nlist)[nlist_idx];
        const nlist_atom = &self.symtab.items(.atom)[nlist_idx];
        if (!nlist.ext()) continue;
        if (!nlist.undf()) continue;

        const sym = macho_file.getSymbol(index);
        if (sym.getFile(macho_file)) |file| {
            if (file.getIndex() != self.index) continue;
        }

        const name = sym.getName(macho_file);
        const parsed = parseBoundarySymbol(name) orelse continue;

        const info: Symbol.BoundaryInfo = .{
            .segment = parsed.segment,
            .start = parsed.start,
        };
        sym.flags.boundary = true;
        try sym.addExtra(.{ .boundary = @bitCast(info) }, macho_file);

        const atom_index = try macho_file.addAtom();
        try self.atoms.append(gpa, atom_index);

        const atom = macho_file.getAtom(atom_index).?;
        atom.atom_index = atom_index;
        atom.name = try macho_file.string_intern.insert(gpa, name);
        atom.file = self.index;

        const n_sect = try self.addSection(gpa, parsed.segname, parsed.sectname);
        const sect = &self.sections.items(.header)[n_sect];
        sect.flags = macho.S_REGULAR;
        atom.n_sect = n_sect;

        sym.value = 0;
        sym.atom = atom_index;
        sym.file = self.index;
        sym.flags.weak = false;
        sym.nlist_idx = nlist_idx;

        nlist.n_value = 0;
        nlist.n_type = macho.N_PEXT | macho.N_EXT | macho.N_SECT;
        nlist.n_sect = n_sect + 1;
        nlist_atom.* = atom_index;
    }
}

pub fn convertTentativeDefinitions(self: *Object, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    for (self.symbols.items, 0..) |index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = &self.symtab.items(.nlist)[nlist_idx];
        const nlist_atom = &self.symtab.items(.atom)[nlist_idx];
        if (!nlist.tentative()) continue;

        const sym = macho_file.getSymbol(index);
        const sym_file = sym.getFile(macho_file).?;
        if (sym_file.getIndex() != self.index) {
            //     if (elf_file.options.warn_common) {
            //         elf_file.base.warn("{}: multiple common symbols: {s}", .{
            //             self.fmtPath(),
            //             global.getName(elf_file),
            //         });
            //     }
            continue;
        }

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
        } else if (sym.getNlist(macho_file).ext()) {
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
        } else if (sym.getNlist(macho_file).ext()) {
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
        if (sym.getFile(macho_file)) |_| {
            if (!sym.getNlist(macho_file).undf()) continue;
        }

        const is_import = switch (macho_file.options.undefined_treatment) {
            .@"error" => false,
            .warn, .suppress => nlist.weakRef(),
            .dynamic_lookup => true,
        };

        sym.value = 0;
        sym.atom = 0;
        sym.nlist_idx = nlist_idx;
        sym.file = self.index;
        sym.flags.import = is_import;
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

fn getSectionData(self: Object, index: u8) []const u8 {
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
    subsections: std.AutoArrayHashMapUnmanaged(u64, Atom.Index) = .{},
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
};

pub const Relocation = struct {
    tag: enum { @"extern", local },
    offset: u32,
    target: u32,
    s_target: u32,
    addend: i64,
    meta: packed struct {
        pcrel: bool,
        length: u2,
        type: u4,
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
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const DwarfInfo = @import("DwarfInfo.zig");
const File = @import("file.zig").File;
const LoadCommandIterator = macho.LoadCommandIterator;
const MachO = @import("../MachO.zig");
const Object = @This();
const StringTable = @import("../strtab.zig").StringTable;
const Symbol = @import("Symbol.zig");
