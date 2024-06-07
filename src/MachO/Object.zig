/// Non-zero for fat object files or archives
offset: u64,
path: []const u8,
file_handle: File.HandleIndex,
mtime: u64,
index: File.Index,
ar_name: ?[]const u8 = null,

header: ?macho.mach_header_64 = null,
sections: std.MultiArrayList(Section) = .{},
symtab: std.MultiArrayList(Nlist) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom) = .{},
atoms_indexes: std.ArrayListUnmanaged(Atom.Index) = .{},
atoms_extra: std.ArrayListUnmanaged(u32) = .{},

compile_unit: ?CompileUnit = null,
stab_files: std.ArrayListUnmanaged(StabFile) = .{},

eh_frame_sect_index: ?u8 = null,
compact_unwind_sect_index: ?u8 = null,
cies: std.ArrayListUnmanaged(Cie) = .{},
fdes: std.ArrayListUnmanaged(Fde) = .{},
eh_frame_data: std.ArrayListUnmanaged(u8) = .{},
unwind_records: std.ArrayListUnmanaged(UnwindInfo.Record) = .{},
unwind_records_indexes: std.ArrayListUnmanaged(UnwindInfo.Record.Index) = .{},
data_in_code: std.ArrayListUnmanaged(macho.data_in_code_entry) = .{},

alive: bool = true,
hidden: bool = false,

output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn deinit(self: *Object, allocator: Allocator) void {
    allocator.free(self.path);
    if (self.ar_name) |path| allocator.free(path);
    for (self.sections.items(.relocs), self.sections.items(.subsections)) |*relocs, *sub| {
        relocs.deinit(allocator);
        sub.deinit(allocator);
    }
    self.sections.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.atoms.deinit(allocator);
    self.atoms_indexes.deinit(allocator);
    self.atoms_extra.deinit(allocator);
    self.cies.deinit(allocator);
    self.fdes.deinit(allocator);
    self.eh_frame_data.deinit(allocator);
    self.unwind_records.deinit(allocator);
    self.unwind_records_indexes.deinit(allocator);
    for (self.stab_files.items) |*sf| {
        sf.stabs.deinit(allocator);
    }
    self.stab_files.deinit(allocator);
    self.data_in_code.deinit(allocator);
}

pub fn init(self: *Object, allocator: Allocator) !void {
    // Atom at index 0 is reserved as null atom
    try self.atoms.append(allocator, .{});
    try self.atoms_extra.append(allocator, 0);
}

pub fn parse(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    log.debug("parsing input object file {}", .{self.fmtPath()});

    const gpa = macho_file.base.allocator;
    const file = macho_file.getFileHandle(self.file_handle);

    var header_buffer: [@sizeOf(macho.mach_header_64)]u8 = undefined;
    {
        const amt = try file.preadAll(&header_buffer, self.offset);
        if (amt != @sizeOf(macho.mach_header_64)) return error.InputOutput;
    }
    self.header = @as(*align(1) const macho.mach_header_64, @ptrCast(&header_buffer)).*;

    const cpu_arch: std.Target.Cpu.Arch = switch (self.header.?.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => unreachable,
    };
    if (macho_file.options.cpu_arch.? != cpu_arch) {
        macho_file.base.fatal("{}: invalid architecture '{s}', expected '{s}'", .{
            self.fmtPath(),
            @tagName(cpu_arch),
            @tagName(macho_file.options.cpu_arch.?),
        });
        return error.ParseFailed;
    }

    const lc_buffer = try gpa.alloc(u8, self.header.?.sizeofcmds);
    defer gpa.free(lc_buffer);
    {
        const amt = try file.preadAll(lc_buffer, self.offset + @sizeOf(macho.mach_header_64));
        if (amt != self.header.?.sizeofcmds) return error.InputOutput;
    }

    var platforms = std.ArrayList(MachO.Options.Platform).init(gpa);
    defer platforms.deinit();

    var it = LoadCommandIterator{
        .ncmds = self.header.?.ncmds,
        .buffer = lc_buffer,
    };
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
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
        },
        .SYMTAB => {
            const cmd = lc.cast(macho.symtab_command).?;
            try self.strtab.resize(gpa, cmd.strsize);
            {
                const amt = try file.preadAll(self.strtab.items, cmd.stroff + self.offset);
                if (amt != self.strtab.items.len) return error.InputOutput;
            }

            const symtab_buffer = try gpa.alloc(u8, cmd.nsyms * @sizeOf(macho.nlist_64));
            defer gpa.free(symtab_buffer);
            {
                const amt = try file.preadAll(symtab_buffer, cmd.symoff + self.offset);
                if (amt != symtab_buffer.len) return error.InputOutput;
            }
            const symtab = @as([*]align(1) const macho.nlist_64, @ptrCast(symtab_buffer.ptr))[0..cmd.nsyms];
            try self.symtab.ensureUnusedCapacity(gpa, symtab.len);
            for (symtab) |nlist| {
                self.symtab.appendAssumeCapacity(.{
                    .nlist = nlist,
                    .atom = 0,
                    .size = 0,
                });
            }
        },
        .DATA_IN_CODE => {
            const cmd = lc.cast(macho.linkedit_data_command).?;
            const buffer = try gpa.alloc(u8, cmd.datasize);
            defer gpa.free(buffer);
            {
                const amt = try file.preadAll(buffer, self.offset + cmd.dataoff);
                if (amt != buffer.len) return error.InputOutput;
            }
            const ndice = @divExact(cmd.datasize, @sizeOf(macho.data_in_code_entry));
            const dice = @as([*]align(1) const macho.data_in_code_entry, @ptrCast(buffer.ptr))[0..ndice];
            try self.data_in_code.appendUnalignedSlice(gpa, dice);
        },
        .BUILD_VERSION,
        .VERSION_MIN_MACOSX,
        .VERSION_MIN_IPHONEOS,
        .VERSION_MIN_TVOS,
        .VERSION_MIN_WATCHOS,
        => try platforms.append(MachO.Options.Platform.fromLoadCommand(lc)),
        else => {},
    };

    if (macho_file.options.platform) |plat| {
        const match = for (platforms.items) |this_plat| {
            if (this_plat.platform == plat.platform) break this_plat;
        } else null;
        if (match) |this_plat| {
            if (this_plat.version.value > plat.version.value) {
                macho_file.base.warn(
                    "{}: object file was built for newer platform version: expected {}, got {}",
                    .{
                        self.fmtPath(),
                        plat.version,
                        this_plat.version,
                    },
                );
            }
        } else {
            const err = try macho_file.base.addErrorWithNotes(1 + platforms.items.len);
            try err.addMsg("{}: object file was built for different platforms than required {s}", .{
                self.fmtPath(),
                @tagName(plat.platform),
            });
            for (platforms.items) |this_plat| {
                try err.addNote("object file built for {s}", .{@tagName(this_plat.platform)});
            }
            return error.ParseFailed;
        }
    }

    const NlistIdx = struct {
        nlist: macho.nlist_64,
        idx: usize,

        fn rank(ctx: *const Object, nl: macho.nlist_64) u8 {
            if (!nl.ext()) {
                const name = ctx.getString(nl.n_strx);
                if (name.len == 0) return 5;
                if (name[0] == 'l' or name[0] == 'L') return 4;
                return 3;
            }
            return if (nl.weakDef()) 2 else 1;
        }

        fn lessThan(ctx: *const Object, lhs: @This(), rhs: @This()) bool {
            if (lhs.nlist.n_sect == rhs.nlist.n_sect) {
                if (lhs.nlist.n_value == rhs.nlist.n_value) {
                    return rank(ctx, lhs.nlist) < rank(ctx, rhs.nlist);
                }
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
    mem.sort(NlistIdx, nlists.items, self, NlistIdx.lessThan);

    if (self.hasSubsections()) {
        try self.initSubsections(nlists.items, macho_file);
    } else {
        try self.initSections(nlists.items, macho_file);
    }

    try self.initCstringLiterals(macho_file);
    try self.initFixedSizeLiterals(macho_file);
    try self.initPointerLiterals(macho_file);
    try self.linkNlistToAtom(macho_file);

    try self.sortAtoms(macho_file);
    try self.initSymbols(macho_file);
    try self.initSymbolStabs(nlists.items, macho_file);
    try self.initRelocs(macho_file);

    if (self.eh_frame_sect_index) |index| {
        try self.initEhFrameRecords(index, macho_file);
    }

    if (self.compact_unwind_sect_index) |index| {
        try self.initUnwindRecords(index, macho_file);
    }

    if (self.hasUnwindRecords() or self.hasEhFrameRecords()) {
        try self.parseUnwindRecords(macho_file);
    }

    for (self.getAtoms()) |atom_index| {
        const atom = self.getAtom(atom_index) orelse continue;
        const isec = atom.getInputSection(macho_file);
        if (mem.eql(u8, isec.sectName(), "__eh_frame") or
            mem.eql(u8, isec.sectName(), "__compact_unwind") or
            isec.attrs() & macho.S_ATTR_DEBUG != 0)
        {
            _ = atom.alive.swap(false, .seq_cst);
        }
    }
}

pub fn isCstringLiteral(sect: macho.section_64) bool {
    return sect.type() == macho.S_CSTRING_LITERALS;
}

pub fn isFixedSizeLiteral(sect: macho.section_64) bool {
    return switch (sect.type()) {
        macho.S_4BYTE_LITERALS,
        macho.S_8BYTE_LITERALS,
        macho.S_16BYTE_LITERALS,
        => true,
        else => false,
    };
}

pub fn isPtrLiteral(sect: macho.section_64) bool {
    return sect.type() == macho.S_LITERAL_POINTERS;
}

fn initSubsections(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |sect, *subsections, n_sect| {
        if (isCstringLiteral(sect)) continue;
        if (isFixedSizeLiteral(sect)) continue;
        if (isPtrLiteral(sect)) continue;

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
            const atom_index = try self.addAtom(gpa, .{
                .name = try self.addString(gpa, name),
                .n_sect = @intCast(n_sect),
                .off = 0,
                .size = size,
                .alignment = sect.@"align",
            });
            try self.atoms_indexes.append(gpa, atom_index);
            try subsections.append(gpa, .{
                .atom = atom_index,
                .off = 0,
            });
        }

        var idx: usize = nlist_start;
        while (idx < nlist_end) {
            const alias_start = idx;
            const nlist = nlists[alias_start];

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
            const atom_index = try self.addAtom(gpa, .{
                .name = nlist.nlist.n_strx,
                .n_sect = @intCast(n_sect),
                .off = nlist.nlist.n_value - sect.addr,
                .size = size,
                .alignment = alignment,
            });
            try self.atoms_indexes.append(gpa, atom_index);
            try subsections.append(gpa, .{
                .atom = atom_index,
                .off = nlist.nlist.n_value - sect.addr,
            });

            for (alias_start..idx) |i| {
                self.symtab.items(.size)[nlists[i].idx] = size;
            }
        }
    }
}

fn initSections(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    try self.atoms.ensureUnusedCapacity(gpa, self.sections.items(.header).len);
    try self.atoms_indexes.ensureUnusedCapacity(gpa, self.sections.items(.header).len);

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (isCstringLiteral(sect)) continue;
        if (isFixedSizeLiteral(sect)) continue;
        if (isPtrLiteral(sect)) continue;

        const name = try std.fmt.allocPrintZ(gpa, "{s}${s}", .{ sect.segName(), sect.sectName() });
        defer gpa.free(name);

        const atom_index = try self.addAtom(gpa, .{
            .name = try self.addString(gpa, name),
            .n_sect = @intCast(n_sect),
            .off = 0,
            .size = sect.size,
            .alignment = sect.@"align",
        });
        try self.atoms_indexes.append(gpa, atom_index);
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

fn initCstringLiterals(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (!isCstringLiteral(sect)) continue;

        const data = try self.getSectionData(@intCast(n_sect), macho_file);
        defer gpa.free(data);

        var start: u32 = 0;
        while (start < data.len) {
            var end = start;
            while (end < data.len - 1 and data[end] != 0) : (end += 1) {}
            if (data[end] != 0) {
                macho_file.base.fatal("{}:{s},{s}: string not null terminated", .{
                    self.fmtPath(),
                    sect.segName(),
                    sect.sectName(),
                });
                return error.ParseFailed;
            }
            end += 1;

            const atom_index = try self.addAtom(gpa, .{
                .name = 0,
                .n_sect = @intCast(n_sect),
                .off = start,
                .size = end - start,
                .alignment = sect.@"align",
            });
            try self.atoms_indexes.append(gpa, atom_index);
            try slice.items(.subsections)[n_sect].append(gpa, .{
                .atom = atom_index,
                .off = start,
            });

            start = end;
        }
    }
}

fn initFixedSizeLiterals(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (!isFixedSizeLiteral(sect)) continue;

        const rec_size: u8 = switch (sect.type()) {
            macho.S_4BYTE_LITERALS => 4,
            macho.S_8BYTE_LITERALS => 8,
            macho.S_16BYTE_LITERALS => 16,
            else => unreachable,
        };
        if (sect.size % rec_size != 0) {
            macho_file.base.fatal("{}:{s},{s}: size not multiple of record size", .{
                self.fmtPath(),
                sect.segName(),
                sect.sectName(),
            });
            return error.ParseFailed;
        }

        var pos: u32 = 0;
        while (pos < sect.size) : (pos += rec_size) {
            const atom_index = try self.addAtom(gpa, .{
                .name = 0,
                .n_sect = @intCast(n_sect),
                .off = pos,
                .size = rec_size,
                .alignment = sect.@"align",
            });
            try self.atoms_indexes.append(gpa, atom_index);
            try slice.items(.subsections)[n_sect].append(gpa, .{
                .atom = atom_index,
                .off = pos,
            });
        }
    }
}

fn initPointerLiterals(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (!isPtrLiteral(sect)) continue;

        const rec_size: u8 = 8;
        if (sect.size % rec_size != 0) {
            macho_file.base.fatal("{}:{s},{s}: size not multiple of record size", .{
                self.fmtPath(),
                sect.segName(),
                sect.sectName(),
            });
            return error.ParseFailed;
        }
        const num_ptrs = @divExact(sect.size, rec_size);

        for (0..num_ptrs) |i| {
            const pos: u32 = @as(u32, @intCast(i)) * rec_size;
            const atom_index = try self.addAtom(gpa, .{
                .name = 0,
                .n_sect = @intCast(n_sect),
                .off = pos,
                .size = rec_size,
                .alignment = sect.@"align",
            });
            try self.atoms_indexes.append(gpa, atom_index);
            try slice.items(.subsections)[n_sect].append(gpa, .{
                .atom = atom_index,
                .off = pos,
            });
        }
    }
}

pub fn resolveLiterals(self: *Object, lp: *MachO.LiteralPool, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |header, subs, n_sect| {
        if (isCstringLiteral(header) or isFixedSizeLiteral(header)) {
            const data = try self.getSectionData(@intCast(n_sect), macho_file);
            defer gpa.free(data);

            for (subs.items) |sub| {
                const atom = self.getAtom(sub.atom).?;
                const atom_data = data[atom.off..][0..atom.size];
                const res = try lp.insert(gpa, header.type(), atom_data);
                if (!res.found_existing) {
                    const nlist_index: u32 = @intCast(try self.symtab.addOne(gpa));
                    self.symtab.set(nlist_index, .{
                        .nlist = .{
                            .n_strx = 0,
                            .n_type = macho.N_SECT,
                            .n_sect = @intCast(atom.n_sect + 1),
                            .n_desc = 0,
                            .n_value = atom.getInputAddress(macho_file),
                        },
                        .size = atom.size,
                        .atom = sub.atom,
                    });
                    const sym_index = try macho_file.addSymbol();
                    try self.symbols.append(gpa, sym_index);
                    const sym = macho_file.getSymbol(sym_index);
                    sym.* = .{
                        .atom_ref = .{ .atom = sub.atom, .file = self.index },
                        .file = self.index,
                        .nlist_idx = nlist_index,
                        .extra = try macho_file.addSymbolExtra(.{}),
                    };
                    res.symbol.* = sym_index;
                }
                atom.flags.literal_pool = true;
                try atom.addExtra(.{ .literal_index = res.index }, macho_file);
            }
        } else if (isPtrLiteral(header)) {
            for (subs.items) |sub| {
                const atom = self.getAtom(sub.atom).?;
                const relocs = atom.getRelocs(macho_file);
                assert(relocs.len == 1);
                const rel = relocs[0];
                const target = switch (rel.tag) {
                    .local => rel.getTargetAtom(atom.*, macho_file),
                    .@"extern" => rel.getTargetSymbol(macho_file).getAtom(macho_file).?,
                };
                const addend = math.cast(u32, rel.addend) orelse return error.Overflow;
                try buffer.ensureUnusedCapacity(target.size);
                buffer.resize(target.size) catch unreachable;
                try target.getCode(macho_file, buffer.items);
                const res = try lp.insert(gpa, header.type(), buffer.items[addend..]);
                buffer.clearRetainingCapacity();
                if (!res.found_existing) {
                    const nlist_index: u32 = @intCast(try self.symtab.addOne(gpa));
                    self.symtab.set(nlist_index, .{
                        .nlist = .{
                            .n_strx = 0,
                            .n_type = macho.N_SECT,
                            .n_sect = @intCast(atom.n_sect + 1),
                            .n_desc = 0,
                            .n_value = atom.getInputAddress(macho_file),
                        },
                        .size = atom.size,
                        .atom = sub.atom,
                    });
                    const sym_index = try macho_file.addSymbol();
                    try self.symbols.append(gpa, sym_index);
                    const sym = macho_file.getSymbol(sym_index);
                    sym.* = .{
                        .atom_ref = .{ .atom = sub.atom, .file = self.index },
                        .file = self.index,
                        .nlist_idx = nlist_index,
                        .extra = try macho_file.addSymbolExtra(.{}),
                    };
                    res.symbol.* = sym_index;
                }
                atom.flags.literal_pool = true;
                try atom.addExtra(.{ .literal_index = res.index }, macho_file);
            }
        }
    }
}

pub fn dedupLiterals(self: *Object, lp: MachO.LiteralPool, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.getAtoms()) |atom_index| {
        const atom = self.getAtom(atom_index) orelse continue;
        if (!atom.alive.load(.seq_cst)) continue;
        if (!atom.flags.relocs) continue;

        const relocs = blk: {
            const extra = atom.getExtra(macho_file).?;
            const relocs = self.sections.items(.relocs)[atom.n_sect].items;
            break :blk relocs[extra.rel_index..][0..extra.rel_count];
        };
        for (relocs) |*rel| switch (rel.tag) {
            .local => {
                const target = rel.getTargetAtom(atom.*, macho_file);
                if (target.getLiteralPoolIndex(macho_file)) |lp_index| {
                    const lp_sym = lp.getSymbol(lp_index, macho_file);
                    const lp_atom_ref = lp_sym.atom_ref;
                    if (target.atom_index != lp_atom_ref.atom or self.index != lp_atom_ref.file) {
                        const lp_atom = lp_sym.getAtom(macho_file).?;
                        _ = lp_atom.alignment.fetchMax(target.alignment.load(.seq_cst), .seq_cst);
                        _ = target.alive.swap(false, .seq_cst);
                        rel.mutex.lock();
                        defer rel.mutex.unlock();
                        rel.target = lp.getSymbolIndex(lp_index);
                        rel.tag = .@"extern";
                    }
                }
            },
            .@"extern" => {
                const target_sym = rel.getTargetSymbol(macho_file);
                if (target_sym.getAtom(macho_file)) |target_atom| {
                    if (target_atom.getLiteralPoolIndex(macho_file)) |lp_index| {
                        const lp_sym = lp.getSymbol(lp_index, macho_file);
                        const lp_atom_ref = lp_sym.atom_ref;
                        if (target_atom.atom_index != lp_atom_ref.atom or target_atom.file != lp_atom_ref.file) {
                            const lp_atom = lp_sym.getAtom(macho_file).?;
                            _ = lp_atom.alignment.fetchMax(target_atom.alignment.load(.seq_cst), .seq_cst);
                            _ = target_atom.alive.swap(false, .seq_cst);
                            target_sym.mutex.lock();
                            defer target_sym.mutex.unlock();
                            target_sym.atom_ref = lp_atom_ref;
                        }
                    }
                }
            },
        };
    }
}

pub fn findAtom(self: Object, addr: u64) ?Atom.Index {
    const tracy = trace(@src());
    defer tracy.end();
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |sect, subs, n_sect| {
        if (subs.items.len == 0) continue;
        if (sect.addr == addr) return subs.items[0].atom;
        if (sect.addr < addr and addr < sect.addr + sect.size) {
            return self.findAtomInSection(addr, @intCast(n_sect));
        }
    }
    return null;
}

fn findAtomInSection(self: Object, addr: u64, n_sect: u8) ?Atom.Index {
    const tracy = trace(@src());
    defer tracy.end();
    const slice = self.sections.slice();
    const sect = slice.items(.header)[n_sect];
    const subsections = slice.items(.subsections)[n_sect];

    var min: usize = 0;
    var max: usize = subsections.items.len;
    while (min < max) {
        const idx = (min + max) / 2;
        const sub = subsections.items[idx];
        const sub_addr = sect.addr + sub.off;
        const sub_size = if (idx + 1 < subsections.items.len)
            subsections.items[idx + 1].off - sub.off
        else
            sect.size - sub.off;
        if (sub_addr == addr or (sub_addr < addr and addr < sub_addr + sub_size)) return sub.atom;
        if (sub_addr < addr) {
            min = idx + 1;
        } else {
            max = idx;
        }
    }

    if (min < subsections.items.len) {
        const sub = subsections.items[min];
        const sub_addr = sect.addr + sub.off;
        const sub_size = if (min + 1 < subsections.items.len)
            subsections.items[min + 1].off - sub.off
        else
            sect.size - sub.off;
        if (sub_addr == addr or (sub_addr < addr and addr < sub_addr + sub_size)) return sub.atom;
    }

    return null;
}

fn linkNlistToAtom(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    for (self.symtab.items(.nlist), self.symtab.items(.atom)) |nlist, *atom| {
        if (!nlist.stab() and nlist.sect()) {
            if (self.findAtomInSection(nlist.n_value, nlist.n_sect - 1)) |atom_index| {
                atom.* = atom_index;
            } else {
                macho_file.base.fatal("{}: symbol {s} not attached to any (sub)section", .{
                    self.fmtPath(), self.getString(nlist.n_strx),
                });
                return error.ParseFailed;
            }
        }
    }
}

fn initSymbols(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.allocator;
    const slice = self.symtab.slice();

    try self.symbols.ensureUnusedCapacity(gpa, slice.items(.nlist).len);

    for (slice.items(.nlist), slice.items(.atom), 0..) |nlist, atom_index, i| {
        if (nlist.ext()) {
            const name = self.getString(nlist.n_strx);
            const off = try macho_file.string_intern.insert(gpa, name);
            const gop = try macho_file.getOrCreateGlobal(off);
            self.symbols.addOneAssumeCapacity().* = gop.index;
            if (nlist.undf() and nlist.weakRef()) {
                macho_file.getSymbol(gop.index).flags.weak_ref = true;
            }
            continue;
        }

        const index = try macho_file.addSymbol();
        self.symbols.appendAssumeCapacity(index);
        const symbol = macho_file.getSymbol(index);
        symbol.* = .{
            .value = nlist.n_value,
            .name = nlist.n_strx,
            .nlist_idx = @intCast(i),
            .file = self.index,
        };

        if (self.getAtom(atom_index)) |atom| {
            assert(!nlist.abs());
            symbol.value -= atom.getInputAddress(macho_file);
            symbol.atom_ref = .{ .atom = atom_index, .file = self.index };
        }

        symbol.flags.abs = nlist.abs();
        symbol.flags.no_dead_strip = symbol.flags.no_dead_strip or nlist.noDeadStrip();

        if (nlist.sect() and
            self.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
        {
            symbol.flags.tlv = true;
        }
    }
}

fn initSymbolStabs(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const SymbolLookup = struct {
        ctx: *const Object,
        entries: @TypeOf(nlists),

        fn find(fs: @This(), addr: u64) ?Symbol.Index {
            // TODO binary search since we have the list sorted
            for (fs.entries) |nlist| {
                if (nlist.nlist.n_value == addr) return fs.ctx.symbols.items[nlist.idx];
            }
            return null;
        }
    };

    const start: u32 = for (self.symtab.items(.nlist), 0..) |nlist, i| {
        if (nlist.stab()) break @intCast(i);
    } else @intCast(self.symtab.items(.nlist).len);
    const end: u32 = for (self.symtab.items(.nlist)[start..], start..) |nlist, i| {
        if (!nlist.stab()) break @intCast(i);
    } else @intCast(self.symtab.items(.nlist).len);

    if (start == end) return;

    const gpa = macho_file.base.allocator;
    const syms = self.symtab.items(.nlist);
    const sym_lookup = SymbolLookup{ .ctx = self, .entries = nlists };

    // We need to cache nlists by name so that we can properly resolve local N_GSYM stabs.
    // What happens is `ld -r` will emit an N_GSYM stab for a symbol that may be either an
    // external or private external.
    var addr_lookup = std.StringHashMap(u64).init(gpa);
    defer addr_lookup.deinit();
    for (syms) |sym| {
        if (sym.sect() and (sym.ext() or sym.pext())) {
            try addr_lookup.putNoClobber(self.getString(sym.n_strx), sym.n_value);
        }
    }

    var i: u32 = start;
    while (i < end) : (i += 1) {
        const open = syms[i];
        if (open.n_type != macho.N_SO) {
            macho_file.base.fatal("{}: unexpected symbol stab type 0x{x} as the first entry", .{
                self.fmtPath(),
                open.n_type,
            });
            return error.ParseFailed;
        }

        while (i < end and syms[i].n_type == macho.N_SO and syms[i].n_sect != 0) : (i += 1) {}

        var sf: StabFile = .{ .comp_dir = i };
        // TODO validate
        i += 3;

        while (i < end and syms[i].n_type != macho.N_SO) : (i += 1) {
            const nlist = syms[i];
            var stab: StabFile.Stab = .{};
            switch (nlist.n_type) {
                macho.N_BNSYM => {
                    stab.is_func = true;
                    stab.symbol = sym_lookup.find(nlist.n_value);
                    // TODO validate
                    i += 3;
                },
                macho.N_GSYM => {
                    stab.is_func = false;
                    stab.symbol = sym_lookup.find(addr_lookup.get(self.getString(nlist.n_strx)).?);
                },
                macho.N_STSYM => {
                    stab.is_func = false;
                    stab.symbol = sym_lookup.find(nlist.n_value);
                },
                else => {
                    macho_file.base.fatal("{}: unhandled symbol stab type 0x{x}", .{
                        self.fmtPath(),
                        nlist.n_type,
                    });
                    return error.ParseFailed;
                },
            }
            try sf.stabs.append(gpa, stab);
        }

        try self.stab_files.append(gpa, sf);
    }
}

fn sortAtoms(self: *Object, macho_file: *MachO) !void {
    const Ctx = struct {
        object: *Object,
        m_file: *MachO,

        fn lessThanAtom(ctx: @This(), lhs: Atom.Index, rhs: Atom.Index) bool {
            return ctx.object.getAtom(lhs).?.getInputAddress(ctx.m_file) <
                ctx.object.getAtom(rhs).?.getInputAddress(ctx.m_file);
        }
    };
    mem.sort(Atom.Index, self.atoms_indexes.items, Ctx{
        .object = self,
        .m_file = macho_file,
    }, Ctx.lessThanAtom);
}

fn initRelocs(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const cpu_arch = macho_file.options.cpu_arch.?;
    const slice = self.sections.slice();

    for (slice.items(.header), slice.items(.relocs), 0..) |sect, *out, n_sect| {
        if (sect.nreloc == 0) continue;
        // We skip relocs for __DWARF since even in -r mode, the linker is expected to emit
        // debug symbol stabs in the relocatable. This made me curious why that is. For now,
        // I shall comply, but I wanna compare with dsymutil.
        if (sect.attrs() & macho.S_ATTR_DEBUG != 0 and
            !mem.eql(u8, sect.sectName(), "__compact_unwind")) continue;

        switch (cpu_arch) {
            .x86_64 => try x86_64.parseRelocs(self, @intCast(n_sect), sect, out, macho_file),
            .aarch64 => try aarch64.parseRelocs(self, @intCast(n_sect), sect, out, macho_file),
            else => unreachable,
        }

        mem.sort(Relocation, out.items, {}, Relocation.lessThan);
    }

    for (slice.items(.header), slice.items(.relocs), slice.items(.subsections)) |sect, relocs, subsections| {
        if (sect.isZerofill()) continue;

        var next_reloc: usize = 0;
        for (subsections.items) |subsection| {
            const atom = self.getAtom(subsection.atom).?;
            if (!atom.alive.load(.seq_cst)) continue;
            if (next_reloc >= relocs.items.len) break;
            const end_addr = atom.off + atom.size;
            const rel_index = next_reloc;

            while (next_reloc < relocs.items.len and relocs.items[next_reloc].offset < end_addr) : (next_reloc += 1) {}

            const rel_count = next_reloc - rel_index;
            try atom.addExtra(.{ .rel_index = @intCast(rel_index), .rel_count = @intCast(rel_count) }, macho_file);
            atom.flags.relocs = true;
        }
    }
}

fn initEhFrameRecords(self: *Object, sect_id: u8, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.allocator;
    const nlists = self.symtab.items(.nlist);
    const slice = self.sections.slice();
    const sect = slice.items(.header)[sect_id];
    const relocs = slice.items(.relocs)[sect_id];

    // TODO: read into buffer directly
    const data = try self.getSectionData(sect_id, macho_file);
    defer gpa.free(data);

    try self.eh_frame_data.ensureTotalCapacityPrecise(gpa, data.len);
    self.eh_frame_data.appendSliceAssumeCapacity(data);

    // Check for non-personality relocs in FDEs and apply them
    for (relocs.items, 0..) |rel, i| {
        switch (rel.type) {
            .unsigned => {
                assert((rel.meta.length == 2 or rel.meta.length == 3) and rel.meta.has_subtractor); // TODO error
                const S: i64 = switch (rel.tag) {
                    .local => rel.meta.symbolnum,
                    .@"extern" => @intCast(nlists[rel.meta.symbolnum].n_value),
                };
                const A = rel.addend;
                const SUB: i64 = blk: {
                    const sub_rel = relocs.items[i - 1];
                    break :blk switch (sub_rel.tag) {
                        .local => sub_rel.meta.symbolnum,
                        .@"extern" => @intCast(nlists[sub_rel.meta.symbolnum].n_value),
                    };
                };
                switch (rel.meta.length) {
                    0, 1 => unreachable,
                    2 => mem.writeInt(u32, self.eh_frame_data.items[rel.offset..][0..4], @bitCast(@as(i32, @truncate(S + A - SUB))), .little),
                    3 => mem.writeInt(u64, self.eh_frame_data.items[rel.offset..][0..8], @bitCast(S + A - SUB), .little),
                }
            },
            else => {},
        }
    }

    var it = eh_frame.Iterator{ .data = self.eh_frame_data.items };
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
        switch (rel.type) {
            .got => {
                assert(rel.meta.length == 2 and rel.tag == .@"extern");
                const cie = for (self.cies.items) |*cie| {
                    if (cie.offset <= rel.offset and rel.offset < cie.offset + cie.getSize()) break cie;
                } else {
                    macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                        self.fmtPath(), sect.segName(), sect.sectName(), rel.offset,
                    });
                    return error.ParseFailed;
                };
                cie.personality = .{ .index = @intCast(rel.target), .offset = rel.offset - cie.offset };
            },
            else => {},
        }
    }
}

fn initUnwindRecords(self: *Object, sect_id: u8, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const SymbolLookup = struct {
        ctx: *const Object,

        fn find(fs: @This(), addr: u64) ?Symbol.Index {
            for (fs.ctx.symbols.items, 0..) |sym_index, i| {
                const nlist = fs.ctx.symtab.items(.nlist)[i];
                if (nlist.ext() and nlist.n_value == addr) return sym_index;
            }
            return null;
        }
    };

    const gpa = macho_file.base.allocator;
    const data = try self.getSectionData(sect_id, macho_file);
    defer gpa.free(data);
    const nrecs = @divExact(data.len, @sizeOf(macho.compact_unwind_entry));
    const recs = @as([*]align(1) const macho.compact_unwind_entry, @ptrCast(data.ptr))[0..nrecs];
    const sym_lookup = SymbolLookup{ .ctx = self };

    try self.unwind_records.ensureTotalCapacityPrecise(gpa, nrecs);
    try self.unwind_records_indexes.ensureTotalCapacityPrecise(gpa, nrecs);

    const header = self.sections.items(.header)[sect_id];
    const relocs = self.sections.items(.relocs)[sect_id].items;
    var reloc_idx: usize = 0;
    for (recs, 0..) |rec, rec_idx| {
        const rec_start = rec_idx * @sizeOf(macho.compact_unwind_entry);
        const rec_end = rec_start + @sizeOf(macho.compact_unwind_entry);
        const reloc_start = reloc_idx;
        while (reloc_idx < relocs.len and
            relocs[reloc_idx].offset < rec_end) : (reloc_idx += 1)
        {}

        const out_index = self.addUnwindRecordAssumeCapacity();
        self.unwind_records_indexes.appendAssumeCapacity(out_index);
        const out = self.getUnwindRecord(out_index);
        out.length = rec.rangeLength;
        out.enc = .{ .enc = rec.compactUnwindEncoding };

        for (relocs[reloc_start..reloc_idx]) |rel| {
            if (rel.type != .unsigned or rel.meta.length != 3) {
                macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                    self.fmtPath(), header.segName(), header.sectName(), rel.offset,
                });
                return error.ParseFailed;
            }
            assert(rel.type == .unsigned and rel.meta.length == 3); // TODO error
            const offset = rel.offset - rec_start;
            switch (offset) {
                0 => switch (rel.tag) { // target symbol
                    .@"extern" => {
                        out.atom = self.symtab.items(.atom)[rel.meta.symbolnum];
                        out.atom_offset = @intCast(rec.rangeStart);
                    },
                    .local => if (self.findAtom(rec.rangeStart)) |atom_index| {
                        out.atom = atom_index;
                        const atom = out.getAtom(macho_file);
                        out.atom_offset = @intCast(rec.rangeStart - atom.getInputAddress(macho_file));
                    } else {
                        macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                            self.fmtPath(), header.segName(), header.sectName(), rel.offset,
                        });
                        return error.ParseFailed;
                    },
                },
                16 => switch (rel.tag) { // personality function
                    .@"extern" => {
                        out.personality = rel.target;
                    },
                    .local => if (sym_lookup.find(rec.personalityFunction)) |sym_index| {
                        out.personality = sym_index;
                    } else {
                        macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                            self.fmtPath(), header.segName(), header.sectName(), rel.offset,
                        });
                        return error.ParseFailed;
                    },
                },
                24 => switch (rel.tag) { // lsda
                    .@"extern" => {
                        out.lsda = self.symtab.items(.atom)[rel.meta.symbolnum];
                        out.lsda_offset = @intCast(rec.lsda);
                    },
                    .local => if (self.findAtom(rec.lsda)) |atom_index| {
                        out.lsda = atom_index;
                        const atom = out.getLsdaAtom(macho_file).?;
                        out.lsda_offset = @intCast(rec.lsda - atom.getInputAddress(macho_file));
                    } else {
                        macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                            self.fmtPath(), header.segName(), header.sectName(), rel.offset,
                        });
                        return error.ParseFailed;
                    },
                },
                else => {},
            }
        }
    }
}

fn parseUnwindRecords(self: *Object, macho_file: *MachO) !void {
    // Synthesise missing unwind records.
    // The logic here is as follows:
    // 1. if an atom has unwind info record that is not DWARF, FDE is marked dead
    // 2. if an atom has unwind info record that is DWARF, FDE is tied to this unwind record
    // 3. if an atom doesn't have unwind info record but FDE is available, synthesise and tie
    // 4. if an atom doesn't have either, synthesise a null unwind info record

    const Superposition = struct { atom: Atom.Index, size: u64, cu: ?UnwindInfo.Record.Index = null, fde: ?Fde.Index = null };

    const gpa = macho_file.base.allocator;
    var superposition = std.AutoArrayHashMap(u64, Superposition).init(gpa);
    defer superposition.deinit();

    const slice = self.symtab.slice();
    for (slice.items(.nlist), slice.items(.atom), slice.items(.size)) |nlist, atom, size| {
        if (nlist.stab()) continue;
        if (!nlist.sect()) continue;
        const sect = self.sections.items(.header)[nlist.n_sect - 1];
        if (sect.isCode() and sect.size > 0) {
            try superposition.ensureUnusedCapacity(1);
            const gop = superposition.getOrPutAssumeCapacity(nlist.n_value);
            if (gop.found_existing) {
                assert(gop.value_ptr.atom == atom and gop.value_ptr.size == size);
            }
            gop.value_ptr.* = .{ .atom = atom, .size = size };
        }
    }

    for (self.unwind_records_indexes.items) |rec_index| {
        const rec = self.getUnwindRecord(rec_index);
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
        if (meta.fde) |fde_index| {
            const fde = &self.fdes.items[fde_index];

            if (meta.cu) |rec_index| {
                const rec = self.getUnwindRecord(rec_index);
                if (!rec.enc.isDwarf(macho_file)) {
                    // Mark FDE dead
                    fde.alive = false;
                } else {
                    // Tie FDE to unwind record
                    rec.fde = fde_index;
                }
            } else {
                // Synthesise new unwind info record
                const rec_index = try self.addUnwindRecord(gpa);
                const rec = self.getUnwindRecord(rec_index);
                try self.unwind_records_indexes.append(gpa, rec_index);
                rec.length = @intCast(meta.size);
                rec.atom = fde.atom;
                rec.atom_offset = fde.atom_offset;
                rec.fde = fde_index;
                switch (macho_file.options.cpu_arch.?) {
                    .x86_64 => rec.enc.setMode(macho.UNWIND_X86_64_MODE.DWARF),
                    .aarch64 => rec.enc.setMode(macho.UNWIND_ARM64_MODE.DWARF),
                    else => unreachable,
                }
            }
        } else if (meta.cu == null and meta.fde == null) {
            // Create a null record
            const rec_index = try self.addUnwindRecord(gpa);
            const rec = self.getUnwindRecord(rec_index);
            const atom = self.getAtom(meta.atom).?;
            try self.unwind_records_indexes.append(gpa, rec_index);
            rec.length = @intCast(meta.size);
            rec.atom = meta.atom;
            rec.atom_offset = @intCast(addr - atom.getInputAddress(macho_file));
        }
    }

    const SortCtx = struct {
        object: *Object,
        mfile: *MachO,

        fn sort(ctx: @This(), lhs_index: UnwindInfo.Record.Index, rhs_index: UnwindInfo.Record.Index) bool {
            const lhs = ctx.object.getUnwindRecord(lhs_index);
            const rhs = ctx.object.getUnwindRecord(rhs_index);
            const lhsa = lhs.getAtom(ctx.mfile);
            const rhsa = rhs.getAtom(ctx.mfile);
            return lhsa.getInputAddress(ctx.mfile) + lhs.atom_offset < rhsa.getInputAddress(ctx.mfile) + rhs.atom_offset;
        }
    };
    mem.sort(UnwindInfo.Record.Index, self.unwind_records_indexes.items, SortCtx{
        .object = self,
        .mfile = macho_file,
    }, SortCtx.sort);

    // Associate unwind records to atoms
    var next_cu: u32 = 0;
    while (next_cu < self.unwind_records_indexes.items.len) {
        const start = next_cu;
        const rec_index = self.unwind_records_indexes.items[start];
        const rec = self.getUnwindRecord(rec_index);
        while (next_cu < self.unwind_records_indexes.items.len and
            self.getUnwindRecord(self.unwind_records_indexes.items[next_cu]).atom == rec.atom) : (next_cu += 1)
        {}

        const atom = rec.getAtom(macho_file);
        try atom.addExtra(.{ .unwind_index = start, .unwind_count = next_cu - start }, macho_file);
        atom.flags.unwind = true;
    }
}

/// Currently, we only check if a compile unit for this input object file exists
/// and record that so that we can emit symbol stabs.
/// TODO in the future, we want parse debug info and debug line sections so that
/// we can provide nice error locations to the user.
pub fn parseDebugInfo(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;

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

    const debug_info = try self.getSectionData(@intCast(debug_info_index.?), macho_file);
    defer gpa.free(debug_info);
    const debug_abbrev = try self.getSectionData(@intCast(debug_abbrev_index.?), macho_file);
    defer gpa.free(debug_abbrev);
    const debug_str = if (debug_str_index) |index| try self.getSectionData(@intCast(index), macho_file) else &[0]u8{};
    defer gpa.free(debug_str);

    self.compile_unit = self.findCompileUnit(.{
        .gpa = gpa,
        .debug_info = debug_info,
        .debug_abbrev = debug_abbrev,
        .debug_str = debug_str,
    }) catch null; // TODO figure out what errors are fatal, and when we silently fail
}

fn findCompileUnit(self: *Object, args: struct {
    gpa: Allocator,
    debug_info: []const u8,
    debug_abbrev: []const u8,
    debug_str: []const u8,
}) !CompileUnit {
    var cu_wip: struct {
        comp_dir: ?[:0]const u8 = null,
        tu_name: ?[:0]const u8 = null,
    } = .{};

    const gpa = args.gpa;
    var info_reader = dwarf.InfoReader{ .bytes = args.debug_info, .strtab = args.debug_str };
    var abbrev_reader = dwarf.AbbrevReader{ .bytes = args.debug_abbrev };

    const cuh = try info_reader.readCompileUnitHeader();
    try abbrev_reader.seekTo(cuh.debug_abbrev_offset);

    const cu_decl = (try abbrev_reader.readDecl()) orelse return error.Eof;
    if (cu_decl.tag != dwarf.TAG.compile_unit) return error.UnexpectedTag;

    try info_reader.seekToDie(cu_decl.code, cuh, &abbrev_reader);

    while (try abbrev_reader.readAttr()) |attr| switch (attr.at) {
        dwarf.AT.name => {
            cu_wip.tu_name = try info_reader.readString(attr.form, cuh);
        },
        dwarf.AT.comp_dir => {
            cu_wip.comp_dir = try info_reader.readString(attr.form, cuh);
        },
        else => switch (attr.form) {
            dwarf.FORM.sec_offset,
            dwarf.FORM.ref_addr,
            => {
                _ = try info_reader.readOffset(cuh.format);
            },

            dwarf.FORM.addr => {
                _ = try info_reader.readNBytes(cuh.address_size);
            },

            dwarf.FORM.block1,
            dwarf.FORM.block2,
            dwarf.FORM.block4,
            dwarf.FORM.block,
            => {
                _ = try info_reader.readBlock(attr.form);
            },

            dwarf.FORM.exprloc => {
                _ = try info_reader.readExprLoc();
            },

            dwarf.FORM.flag_present => {},

            dwarf.FORM.data1,
            dwarf.FORM.ref1,
            dwarf.FORM.flag,
            dwarf.FORM.data2,
            dwarf.FORM.ref2,
            dwarf.FORM.data4,
            dwarf.FORM.ref4,
            dwarf.FORM.data8,
            dwarf.FORM.ref8,
            dwarf.FORM.ref_sig8,
            dwarf.FORM.udata,
            dwarf.FORM.ref_udata,
            dwarf.FORM.sdata,
            => {
                _ = try info_reader.readConstant(attr.form);
            },

            dwarf.FORM.strp,
            dwarf.FORM.string,
            => {
                _ = try info_reader.readString(attr.form, cuh);
            },

            else => {
                // TODO actual errors?
                log.err("unhandled DW_FORM_* value with identifier {x}", .{attr.form});
                return error.UnhandledForm;
            },
        },
    };

    if (cu_wip.comp_dir == null) return error.MissingCompDir;
    if (cu_wip.tu_name == null) return error.MissingTuName;

    return .{
        .comp_dir = try self.addString(gpa, cu_wip.comp_dir.?),
        .tu_name = try self.addString(gpa, cu_wip.tu_name.?),
    };
}

pub fn resolveSymbols(self: *Object, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items, 0..) |index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        const atom_index = self.symtab.items(.atom)[nlist_idx];

        if (!nlist.ext()) continue;
        if (nlist.undf() and !nlist.tentative()) continue;
        if (nlist.sect()) {
            const atom = self.getAtom(atom_index).?;
            if (!atom.alive.load(.seq_cst)) continue;
        }

        const symbol = macho_file.getSymbol(index);
        if (self.asFile().getSymbolRank(.{
            .archive = !self.alive,
            .weak = nlist.weakDef(),
            .tentative = nlist.tentative(),
        }) < symbol.getSymbolRank(macho_file)) {
            const value = if (nlist.sect()) blk: {
                const atom = self.getAtom(atom_index).?;
                break :blk nlist.n_value - atom.getInputAddress(macho_file);
            } else nlist.n_value;
            symbol.value = value;
            symbol.atom_ref = .{ .atom = atom_index, .file = self.index };
            symbol.nlist_idx = nlist_idx;
            symbol.file = self.index;
            symbol.flags.weak = nlist.weakDef();
            symbol.flags.abs = nlist.abs();
            symbol.flags.tentative = nlist.tentative();
            symbol.flags.weak_ref = false;
            symbol.flags.dyn_ref = nlist.n_desc & macho.REFERENCED_DYNAMICALLY != 0;
            symbol.flags.no_dead_strip = symbol.flags.no_dead_strip or nlist.noDeadStrip();
            symbol.flags.interposable = macho_file.options.dylib and macho_file.options.namespace == .flat and !nlist.pext();

            if (nlist.sect() and
                self.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
            {
                symbol.flags.tlv = true;
            }
        }

        // Regardless of who the winner is, we still merge symbol visibility here.
        if (nlist.pext() or (nlist.weakDef() and nlist.weakRef()) or self.hidden) {
            if (symbol.visibility != .global) {
                symbol.visibility = .hidden;
            }
        } else {
            symbol.visibility = .global;
        }
    }
}

pub fn resetGlobals(self: *Object, macho_file: *MachO) void {
    for (self.symbols.items, 0..) |sym_index, nlist_idx| {
        if (!self.symtab.items(.nlist)[nlist_idx].ext()) continue;
        const sym = macho_file.getSymbol(sym_index);
        const name = sym.name;
        const global = sym.flags.global;
        const weak_ref = sym.flags.weak_ref;
        sym.* = .{};
        sym.name = name;
        sym.flags.global = global;
        sym.flags.weak_ref = weak_ref;
    }
}

pub fn markLive(self: *Object, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items, 0..) |index, nlist_idx| {
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        if (!nlist.ext()) continue;

        const sym = macho_file.getSymbol(index);
        const file = sym.getFile(macho_file) orelse continue;
        const should_keep = nlist.undf() or (nlist.tentative() and !sym.flags.tentative);
        if (should_keep and file == .object and !file.object.alive) {
            file.object.alive = true;
            file.object.markLive(macho_file);
        }
    }
}

pub fn scanRelocs(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.getAtoms()) |atom_index| {
        const atom = self.getAtom(atom_index) orelse continue;
        if (!atom.alive.load(.seq_cst)) continue;
        const sect = atom.getInputSection(macho_file);
        if (sect.isZerofill()) continue;
        try atom.scanRelocs(macho_file);
    }

    for (self.unwind_records_indexes.items) |rec_index| {
        const rec = self.getUnwindRecord(rec_index);
        if (!rec.alive) continue;
        if (rec.getFde(macho_file)) |fde| {
            if (fde.getCie(macho_file).getPersonality(macho_file)) |sym| {
                sym.setSectionFlags(.{ .got = true });
            }
        } else if (rec.getPersonality(macho_file)) |sym| {
            sym.setSectionFlags(.{ .got = true });
        }
    }
}

pub fn convertTentativeDefinitions(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.allocator;

    for (self.symbols.items, 0..) |index, i| {
        const sym = macho_file.getSymbol(index);
        if (!sym.flags.tentative) continue;
        const sym_file = sym.getFile(macho_file).?;
        if (sym_file.getIndex() != self.index) continue;

        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = &self.symtab.items(.nlist)[nlist_idx];
        const nlist_atom = &self.symtab.items(.atom)[nlist_idx];

        const name = try std.fmt.allocPrintZ(gpa, "__DATA$__common${s}", .{sym.getName(macho_file)});
        defer gpa.free(name);

        const alignment = (nlist.n_desc >> 8) & 0x0f;
        const n_sect = try self.addSection(gpa, "__DATA", "__common");
        const atom_index = try self.addAtom(gpa, .{
            .name = try self.addString(gpa, name),
            .n_sect = n_sect,
            .off = 0,
            .size = nlist.n_value,
            .alignment = alignment,
        });
        try self.atoms_indexes.append(gpa, atom_index);

        const sect = &self.sections.items(.header)[n_sect];
        sect.flags = macho.S_ZEROFILL;
        sect.size = nlist.n_value;
        sect.@"align" = alignment;

        sym.value = 0;
        sym.atom_ref = .{ .atom = atom_index, .file = self.index };
        sym.flags.global = true;
        sym.flags.weak = false;
        sym.flags.weak_ref = false;
        sym.flags.tentative = false;
        sym.visibility = .global;

        nlist.n_value = 0;
        nlist.n_type = macho.N_EXT | macho.N_SECT;
        nlist.n_sect = 0;
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

pub fn calcSymtabSize(self: *Object, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    const is_relocatable = macho_file.options.relocatable;

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        const file = sym.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        if (sym.getAtom(macho_file)) |atom| if (!atom.alive.load(.seq_cst)) continue;
        if (sym.isSymbolStab(macho_file)) continue;
        const name = sym.getName(macho_file);
        // TODO in -r mode, we actually want to merge symbol names and emit only one
        // work it out when emitting relocs
        if (name.len > 0 and
            (name[0] == 'L' or name[0] == 'l' or
            mem.startsWith(u8, name, "_OBJC_SELECTOR_REFERENCES_")) and
            !is_relocatable)
            continue;
        sym.flags.output_symtab = true;
        if (sym.isLocal()) {
            sym.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, macho_file);
            self.output_symtab_ctx.nlocals += 1;
        } else if (sym.flags.@"export") {
            sym.addExtra(.{ .symtab = self.output_symtab_ctx.nexports }, macho_file);
            self.output_symtab_ctx.nexports += 1;
        } else {
            assert(sym.flags.import);
            sym.addExtra(.{ .symtab = self.output_symtab_ctx.nimports }, macho_file);
            self.output_symtab_ctx.nimports += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(sym.getName(macho_file).len + 1));
    }

    if (!macho_file.options.strip and self.hasDebugInfo()) self.calcStabsSize(macho_file);
}

pub fn calcStabsSize(self: *Object, macho_file: *MachO) void {
    if (self.compile_unit) |cu| {
        // TODO handle multiple CUs
        const comp_dir = cu.getCompDir(self);
        const tu_name = cu.getTuName(self);

        self.output_symtab_ctx.nstabs += 4; // N_SO, N_SO, N_OSO, N_SO
        self.output_symtab_ctx.strsize += @as(u32, @intCast(comp_dir.len + 1)); // comp_dir
        self.output_symtab_ctx.strsize += @as(u32, @intCast(tu_name.len + 1)); // tu_name

        if (self.ar_name) |path| {
            self.output_symtab_ctx.strsize += @as(u32, @intCast(path.len + 1 + self.path.len + 1 + 1));
        } else {
            self.output_symtab_ctx.strsize += @as(u32, @intCast(self.path.len + 1));
        }

        for (self.symbols.items) |sym_index| {
            const sym = macho_file.getSymbol(sym_index);
            const file = sym.getFile(macho_file) orelse continue;
            if (file.getIndex() != self.index) continue;
            if (!sym.flags.output_symtab) continue;
            if (macho_file.options.relocatable) {
                const name = sym.getName(macho_file);
                if (name.len > 0 and (name[0] == 'L' or name[0] == 'l')) continue;
            }
            const sect = macho_file.sections.items(.header)[sym.getOutputSectionIndex(macho_file)];
            if (sect.isCode()) {
                self.output_symtab_ctx.nstabs += 4; // N_BNSYM, N_FUN, N_FUN, N_ENSYM
            } else if (sym.visibility == .global) {
                self.output_symtab_ctx.nstabs += 1; // N_GSYM
            } else {
                self.output_symtab_ctx.nstabs += 1; // N_STSYM
            }
        }
    } else {
        assert(self.hasSymbolStabs());

        for (self.stab_files.items) |sf| {
            self.output_symtab_ctx.nstabs += 4; // N_SO, N_SO, N_OSO, N_SO
            self.output_symtab_ctx.strsize += @as(u32, @intCast(sf.getCompDir(self).len + 1)); // comp_dir
            self.output_symtab_ctx.strsize += @as(u32, @intCast(sf.getTuName(self).len + 1)); // tu_name
            self.output_symtab_ctx.strsize += @as(u32, @intCast(sf.getOsoPath(self).len + 1)); // path

            for (sf.stabs.items) |stab| {
                const sym = stab.getSymbol(macho_file) orelse continue;
                const file = sym.getFile(macho_file).?;
                if (file.getIndex() != self.index) continue;
                if (!sym.flags.output_symtab) continue;
                const nstabs: u32 = if (stab.is_func) 4 else 1;
                self.output_symtab_ctx.nstabs += nstabs;
            }
        }
    }
}

pub fn writeSymtab(self: Object, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    var n_strx = self.output_symtab_ctx.stroff;
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        const file = sym.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        const idx = sym.getOutputSymtabIndex(macho_file) orelse continue;
        const out_sym = &macho_file.symtab.items[idx];
        out_sym.n_strx = n_strx;
        sym.setOutputSym(macho_file, out_sym);
        const name = sym.getName(macho_file);
        @memcpy(macho_file.strtab.items[n_strx..][0..name.len], name);
        n_strx += @intCast(name.len);
        macho_file.strtab.items[n_strx] = 0;
        n_strx += 1;
    }

    if (!macho_file.options.strip and self.hasDebugInfo()) self.writeStabs(n_strx, macho_file);
}

pub fn writeStabs(self: *const Object, stroff: u32, macho_file: *MachO) void {
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

    var index = self.output_symtab_ctx.istab;
    var n_strx = stroff;

    if (self.compile_unit) |cu| {
        // TODO handle multiple CUs
        const comp_dir = cu.getCompDir(self);
        const tu_name = cu.getTuName(self);

        // Open scope
        // N_SO comp_dir
        macho_file.symtab.items[index] = .{
            .n_strx = n_strx,
            .n_type = macho.N_SO,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
        index += 1;
        @memcpy(macho_file.strtab.items[n_strx..][0..comp_dir.len], comp_dir);
        n_strx += @intCast(comp_dir.len);
        macho_file.strtab.items[n_strx] = 0;
        n_strx += 1;
        // N_SO tu_name
        macho_file.symtab.items[index] = .{
            .n_strx = n_strx,
            .n_type = macho.N_SO,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
        index += 1;
        @memcpy(macho_file.strtab.items[n_strx..][0..tu_name.len], tu_name);
        n_strx += @intCast(tu_name.len);
        macho_file.strtab.items[n_strx] = 0;
        n_strx += 1;
        // N_OSO path
        macho_file.symtab.items[index] = .{
            .n_strx = n_strx,
            .n_type = macho.N_OSO,
            .n_sect = 0,
            .n_desc = 1,
            .n_value = self.mtime,
        };
        index += 1;
        if (self.ar_name) |path| {
            @memcpy(macho_file.strtab.items[n_strx..][0..path.len], path);
            n_strx += @intCast(path.len);
            macho_file.strtab.items[n_strx] = '(';
            n_strx += 1;
            @memcpy(macho_file.strtab.items[n_strx..][0..self.path.len], self.path);
            n_strx += @intCast(self.path.len);
            macho_file.strtab.items[n_strx] = ')';
            n_strx += 1;
            macho_file.strtab.items[n_strx] = 0;
            n_strx += 1;
        } else {
            @memcpy(macho_file.strtab.items[n_strx..][0..self.path.len], self.path);
            n_strx += @intCast(self.path.len);
            macho_file.strtab.items[n_strx] = 0;
            n_strx += 1;
        }

        for (self.symbols.items) |sym_index| {
            const sym = macho_file.getSymbol(sym_index);
            const file = sym.getFile(macho_file) orelse continue;
            if (file.getIndex() != self.index) continue;
            if (!sym.flags.output_symtab) continue;
            if (macho_file.options.relocatable) {
                const name = sym.getName(macho_file);
                if (name.len > 0 and (name[0] == 'L' or name[0] == 'l')) continue;
            }
            const sect = macho_file.sections.items(.header)[sym.getOutputSectionIndex(macho_file)];
            const sym_n_strx = n_strx: {
                const symtab_index = sym.getOutputSymtabIndex(macho_file).?;
                const osym = macho_file.symtab.items[symtab_index];
                break :n_strx osym.n_strx;
            };
            const sym_n_sect: u8 = if (!sym.flags.abs) @intCast(sym.getOutputSectionIndex(macho_file) + 1) else 0;
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
    } else {
        assert(self.hasSymbolStabs());

        for (self.stab_files.items) |sf| {
            const comp_dir = sf.getCompDir(self);
            const tu_name = sf.getTuName(self);
            const oso_path = sf.getOsoPath(self);

            // Open scope
            // N_SO comp_dir
            macho_file.symtab.items[index] = .{
                .n_strx = n_strx,
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            index += 1;
            @memcpy(macho_file.strtab.items[n_strx..][0..comp_dir.len], comp_dir);
            n_strx += @intCast(comp_dir.len);
            macho_file.strtab.items[n_strx] = 0;
            n_strx += 1;
            // N_SO tu_name
            macho_file.symtab.items[index] = .{
                .n_strx = n_strx,
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            index += 1;
            @memcpy(macho_file.strtab.items[n_strx..][0..tu_name.len], tu_name);
            n_strx += @intCast(tu_name.len);
            macho_file.strtab.items[n_strx] = 0;
            n_strx += 1;
            // N_OSO path
            macho_file.symtab.items[index] = .{
                .n_strx = n_strx,
                .n_type = macho.N_OSO,
                .n_sect = 0,
                .n_desc = 1,
                .n_value = sf.getOsoModTime(self),
            };
            index += 1;
            @memcpy(macho_file.strtab.items[n_strx..][0..oso_path.len], oso_path);
            n_strx += @intCast(oso_path.len);
            macho_file.strtab.items[n_strx] = 0;
            n_strx += 1;

            for (sf.stabs.items) |stab| {
                const sym = stab.getSymbol(macho_file) orelse continue;
                const file = sym.getFile(macho_file).?;
                if (file.getIndex() != self.index) continue;
                if (!sym.flags.output_symtab) continue;
                const sym_n_strx = n_strx: {
                    const symtab_index = sym.getOutputSymtabIndex(macho_file).?;
                    const osym = macho_file.symtab.items[symtab_index];
                    break :n_strx osym.n_strx;
                };
                const sym_n_sect: u8 = if (!sym.flags.abs) @intCast(sym.getOutputSectionIndex(macho_file) + 1) else 0;
                const sym_n_value = sym.getAddress(.{}, macho_file);
                const sym_size = sym.getSize(macho_file);
                if (stab.is_func) {
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
            index += 1;
        }
    }
}

pub fn getSectionData(self: *const Object, index: u32, macho_file: *MachO) ![]u8 {
    const gpa = macho_file.base.allocator;
    const slice = self.sections.slice();
    assert(index < slice.items(.header).len);
    const sect = slice.items(.header)[index];
    const file = macho_file.getFileHandle(self.file_handle);
    const buffer = try gpa.alloc(u8, sect.size);
    errdefer gpa.free(buffer);
    const amt = try file.preadAll(buffer, sect.offset + self.offset);
    if (amt != buffer.len) return error.InputOutput;
    return buffer;
}

fn addString(self: *Object, allocator: Allocator, name: [:0]const u8) error{OutOfMemory}!u32 {
    const off: u32 = @intCast(self.strtab.items.len);
    try self.strtab.ensureUnusedCapacity(allocator, name.len + 1);
    self.strtab.appendSliceAssumeCapacity(name);
    self.strtab.appendAssumeCapacity(0);
    return off;
}

pub fn getString(self: Object, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

/// TODO handle multiple CUs
pub fn hasDebugInfo(self: Object) bool {
    return self.compile_unit != null or self.hasSymbolStabs();
}

fn hasSymbolStabs(self: Object) bool {
    return self.stab_files.items.len > 0;
}

pub fn hasObjc(self: Object) bool {
    for (self.symtab.items(.nlist)) |nlist| {
        const name = self.getString(nlist.n_strx);
        if (mem.startsWith(u8, name, "_OBJC_CLASS_$_")) return true;
    }
    for (self.sections.items(.header)) |sect| {
        if (mem.eql(u8, sect.segName(), "__DATA") and mem.eql(u8, sect.sectName(), "__objc_catlist")) return true;
        if (mem.eql(u8, sect.segName(), "__TEXT") and mem.eql(u8, sect.sectName(), "__swift")) return true;
    }
    return false;
}

pub fn getDataInCode(self: Object) []const macho.data_in_code_entry {
    return self.data_in_code.items;
}

pub inline fn hasSubsections(self: Object) bool {
    return self.header.?.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0;
}

pub fn hasUnwindRecords(self: Object) bool {
    return self.unwind_records.items.len > 0;
}

pub fn hasEhFrameRecords(self: Object) bool {
    return self.cies.items.len > 0;
}

pub fn asFile(self: *Object) File {
    return .{ .object = self };
}

const AddAtomArgs = struct {
    name: u32,
    n_sect: u8,
    off: u64,
    size: u64,
    alignment: u32,
};

fn addAtom(self: *Object, allocator: Allocator, args: AddAtomArgs) !Atom.Index {
    const atom_index: Atom.Index = @intCast(self.atoms.items.len);
    const atom = try self.atoms.addOne(allocator);
    atom.* = .{
        .file = self.index,
        .atom_index = atom_index,
        .name = args.name,
        .n_sect = args.n_sect,
        .size = args.size,
        .off = args.off,
    };
    atom.alignment.store(args.alignment, .seq_cst);
    return atom_index;
}

pub fn getAtom(self: *Object, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn getAtoms(self: *Object) []const Atom.Index {
    return self.atoms_indexes.items;
}

pub fn addAtomExtra(self: *Object, allocator: Allocator, extra: Atom.Extra) !u32 {
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    try self.atoms_extra.ensureUnusedCapacity(allocator, fields.len);
    return self.addAtomExtraAssumeCapacity(extra);
}

pub fn addAtomExtraAssumeCapacity(self: *Object, extra: Atom.Extra) u32 {
    const index = @as(u32, @intCast(self.atoms_extra.items.len));
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    inline for (fields) |field| {
        self.atoms_extra.appendAssumeCapacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        });
    }
    return index;
}

pub fn getAtomExtra(self: Object, index: u32) ?Atom.Extra {
    if (index == 0) return null;
    const fields = @typeInfo(Atom.Extra).Struct.fields;
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
    assert(index > 0);
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    inline for (fields, 0..) |field, i| {
        self.atoms_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
}

fn addUnwindRecord(self: *Object, allocator: Allocator) !UnwindInfo.Record.Index {
    try self.unwind_records.ensureUnusedCapacity(allocator, 1);
    return self.addUnwindRecordAssumeCapacity();
}

fn addUnwindRecordAssumeCapacity(self: *Object) UnwindInfo.Record.Index {
    const index = @as(UnwindInfo.Record.Index, @intCast(self.unwind_records.items.len));
    const rec = self.unwind_records.addOneAssumeCapacity();
    rec.* = .{ .file = self.index };
    return index;
}

pub fn getUnwindRecord(self: *Object, index: UnwindInfo.Record.Index) *UnwindInfo.Record {
    assert(index < self.unwind_records.items.len);
    return &self.unwind_records.items[index];
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
    const macho_file = ctx.macho_file;
    try writer.writeAll("  atoms\n");
    for (object.getAtoms()) |atom_index| {
        const atom = object.getAtom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(macho_file)});
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
    for (object.unwind_records_indexes.items) |rec| {
        try writer.print("    rec({d}) : {}\n", .{ rec, object.getUnwindRecord(rec).fmt(macho_file) });
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
    for (object.stab_files.items) |sf| {
        try writer.print("  stabs({s},{s},{s})\n", .{
            sf.getCompDir(object),
            sf.getTuName(object),
            sf.getOsoPath(object),
        });
        for (sf.stabs.items) |stab| {
            try writer.print("    {}", .{stab.fmt(ctx.macho_file)});
        }
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
    if (object.ar_name) |path| {
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

const Nlist = struct {
    nlist: macho.nlist_64,
    size: u64,
    atom: Atom.Index,
};

const StabFile = struct {
    comp_dir: u32,
    stabs: std.ArrayListUnmanaged(Stab) = .{},

    fn getCompDir(sf: StabFile, object: *const Object) [:0]const u8 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir];
        return object.getString(nlist.n_strx);
    }

    fn getTuName(sf: StabFile, object: *const Object) [:0]const u8 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir + 1];
        return object.getString(nlist.n_strx);
    }

    fn getOsoPath(sf: StabFile, object: *const Object) [:0]const u8 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir + 2];
        return object.getString(nlist.n_strx);
    }

    fn getOsoModTime(sf: StabFile, object: *const Object) u64 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir + 2];
        return nlist.n_value;
    }

    const Stab = struct {
        is_func: bool = true,
        symbol: ?Symbol.Index = null,

        fn getSymbol(stab: Stab, macho_file: *MachO) ?*Symbol {
            return if (stab.symbol) |s| macho_file.getSymbol(s) else null;
        }

        pub fn format(
            stab: Stab,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = stab;
            _ = unused_fmt_string;
            _ = options;
            _ = writer;
            @compileError("do not format stabs directly");
        }

        const StabFormatContext = struct { Stab, *MachO };

        pub fn fmt(stab: Stab, macho_file: *MachO) std.fmt.Formatter(format2) {
            return .{ .data = .{ stab, macho_file } };
        }

        fn format2(
            ctx: StabFormatContext,
            comptime unused_fmt_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = unused_fmt_string;
            _ = options;
            const stab, const macho_file = ctx;
            const sym = stab.getSymbol(macho_file).?;
            if (stab.is_func) {
                try writer.print("func(%{d})", .{stab.symbol.?});
            } else if (sym.visibility == .global) {
                try writer.print("gsym(%{d})", .{stab.symbol.?});
            } else {
                try writer.print("stsym(%{d})", .{stab.symbol.?});
            }
        }
    };
};

const CompileUnit = struct {
    comp_dir: u32,
    tu_name: u32,

    fn getCompDir(cu: CompileUnit, object: *const Object) [:0]const u8 {
        return object.getString(cu.comp_dir);
    }

    fn getTuName(cu: CompileUnit, object: *const Object) [:0]const u8 {
        return object.getString(cu.tu_name);
    }
};

const x86_64 = struct {
    fn parseRelocs(
        self: *Object,
        n_sect: u8,
        sect: macho.section_64,
        out: *std.ArrayListUnmanaged(Relocation),
        macho_file: *MachO,
    ) !void {
        const gpa = macho_file.base.allocator;

        const file = macho_file.getFileHandle(self.file_handle);
        const relocs_buffer = try gpa.alloc(u8, sect.nreloc * @sizeOf(macho.relocation_info));
        defer gpa.free(relocs_buffer);
        {
            const amt = try file.preadAll(relocs_buffer, sect.reloff + self.offset);
            if (amt != relocs_buffer.len) return error.InputOutput;
        }
        const relocs = @as([*]align(1) const macho.relocation_info, @ptrCast(relocs_buffer.ptr))[0..sect.nreloc];

        const code = try self.getSectionData(@intCast(n_sect), macho_file);
        defer gpa.free(code);

        try out.ensureTotalCapacityPrecise(gpa, relocs.len);

        var i: usize = 0;
        while (i < relocs.len) : (i += 1) {
            const rel = relocs[i];
            const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.r_type);
            const rel_offset = @as(u32, @intCast(rel.r_address));

            var addend = switch (rel.r_length) {
                0 => code[rel_offset],
                1 => mem.readInt(i16, code[rel_offset..][0..2], .little),
                2 => mem.readInt(i32, code[rel_offset..][0..4], .little),
                3 => mem.readInt(i64, code[rel_offset..][0..8], .little),
            };
            addend += switch (@as(macho.reloc_type_x86_64, @enumFromInt(rel.r_type))) {
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
                const target = self.findAtomInSection(@intCast(taddr), @intCast(nsect)) orelse {
                    macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                        self.fmtPath(), sect.segName(), sect.sectName(), rel.r_address,
                    });
                    return error.ParseFailed;
                };
                addend = taddr - @as(i64, @intCast(self.getAtom(target).?.getInputAddress(macho_file)));
                break :blk target;
            } else self.symbols.items[rel.r_symbolnum];

            const has_subtractor = if (i > 0 and
                @as(macho.reloc_type_x86_64, @enumFromInt(relocs[i - 1].r_type)) == .X86_64_RELOC_SUBTRACTOR)
            blk: {
                if (rel_type != .X86_64_RELOC_UNSIGNED) {
                    macho_file.base.fatal("{}: {s},{s}: 0x{x}: X86_64_RELOC_SUBTRACTOR followed by {s}", .{
                        self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type),
                    });
                    return error.ParseFailed;
                }
                break :blk true;
            } else false;

            const @"type": Relocation.Type = validateRelocType(rel, rel_type) catch |err| {
                switch (err) {
                    error.Pcrel => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: PC-relative {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type) },
                    ),
                    error.NonPcrel => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: non-PC-relative {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type) },
                    ),
                    error.InvalidLength => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: invalid length of {d} in {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @as(u8, 1) << rel.r_length, @tagName(rel_type) },
                    ),
                    error.NonExtern => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: non-extern target in {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type) },
                    ),
                }
                return error.ParseFailed;
            };

            out.appendAssumeCapacity(.{
                .tag = if (rel.r_extern == 1) .@"extern" else .local,
                .offset = @as(u32, @intCast(rel.r_address)),
                .target = target,
                .addend = addend,
                .type = @"type",
                .meta = .{
                    .pcrel = rel.r_pcrel == 1,
                    .has_subtractor = has_subtractor,
                    .length = rel.r_length,
                    .symbolnum = rel.r_symbolnum,
                },
            });
        }
    }

    fn validateRelocType(rel: macho.relocation_info, rel_type: macho.reloc_type_x86_64) !Relocation.Type {
        switch (rel_type) {
            .X86_64_RELOC_UNSIGNED => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                if (rel.r_length != 2 and rel.r_length != 3) return error.InvalidLength;
                return .unsigned;
            },

            .X86_64_RELOC_SUBTRACTOR => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                return .subtractor;
            },

            .X86_64_RELOC_BRANCH,
            .X86_64_RELOC_GOT_LOAD,
            .X86_64_RELOC_GOT,
            .X86_64_RELOC_TLV,
            => {
                if (rel.r_pcrel == 0) return error.NonPcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                if (rel.r_extern == 0) return error.NonExtern;
                return switch (rel_type) {
                    .X86_64_RELOC_BRANCH => .branch,
                    .X86_64_RELOC_GOT_LOAD => .got_load,
                    .X86_64_RELOC_GOT => .got,
                    .X86_64_RELOC_TLV => .tlv,
                    else => unreachable,
                };
            },

            .X86_64_RELOC_SIGNED,
            .X86_64_RELOC_SIGNED_1,
            .X86_64_RELOC_SIGNED_2,
            .X86_64_RELOC_SIGNED_4,
            => {
                if (rel.r_pcrel == 0) return error.NonPcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                return switch (rel_type) {
                    .X86_64_RELOC_SIGNED => .signed,
                    .X86_64_RELOC_SIGNED_1 => .signed1,
                    .X86_64_RELOC_SIGNED_2 => .signed2,
                    .X86_64_RELOC_SIGNED_4 => .signed4,
                    else => unreachable,
                };
            },
        }
    }
};

const aarch64 = struct {
    fn parseRelocs(
        self: *Object,
        n_sect: u8,
        sect: macho.section_64,
        out: *std.ArrayListUnmanaged(Relocation),
        macho_file: *MachO,
    ) !void {
        const gpa = macho_file.base.allocator;

        const file = macho_file.getFileHandle(self.file_handle);
        const relocs_buffer = try gpa.alloc(u8, sect.nreloc * @sizeOf(macho.relocation_info));
        defer gpa.free(relocs_buffer);
        {
            const amt = try file.preadAll(relocs_buffer, sect.reloff + self.offset);
            if (amt != relocs_buffer.len) return error.InputOutput;
        }
        const relocs = @as([*]align(1) const macho.relocation_info, @ptrCast(relocs_buffer.ptr))[0..sect.nreloc];

        const code = try self.getSectionData(@intCast(n_sect), macho_file);
        defer gpa.free(code);

        try out.ensureTotalCapacityPrecise(gpa, relocs.len);

        var i: usize = 0;
        while (i < relocs.len) : (i += 1) {
            var rel = relocs[i];
            const rel_offset = @as(u32, @intCast(rel.r_address));

            var addend: i64 = 0;

            switch (@as(macho.reloc_type_arm64, @enumFromInt(rel.r_type))) {
                .ARM64_RELOC_ADDEND => {
                    addend = rel.r_symbolnum;
                    i += 1;
                    if (i >= relocs.len) {
                        macho_file.base.fatal("{}: {s},{s}: 0x{x}: unterminated ARM64_RELOC_ADDEND", .{
                            self.fmtPath(), sect.segName(), sect.sectName(), rel_offset,
                        });
                        return error.ParseFailed;
                    }
                    rel = relocs[i];
                    switch (@as(macho.reloc_type_arm64, @enumFromInt(rel.r_type))) {
                        .ARM64_RELOC_PAGE21, .ARM64_RELOC_PAGEOFF12 => {},
                        else => |x| {
                            macho_file.base.fatal(
                                "{}: {s},{s}: 0x{x}: ARM64_RELOC_ADDEND followed by {s}",
                                .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(x) },
                            );
                            return error.ParseFailed;
                        },
                    }
                },
                .ARM64_RELOC_UNSIGNED => {
                    addend = switch (rel.r_length) {
                        0 => code[rel_offset],
                        1 => mem.readInt(i16, code[rel_offset..][0..2], .little),
                        2 => mem.readInt(i32, code[rel_offset..][0..4], .little),
                        3 => mem.readInt(i64, code[rel_offset..][0..8], .little),
                    };
                },
                else => {},
            }

            const rel_type: macho.reloc_type_arm64 = @enumFromInt(rel.r_type);

            const target = if (rel.r_extern == 0) blk: {
                const nsect = rel.r_symbolnum - 1;
                const taddr: i64 = if (rel.r_pcrel == 1)
                    @as(i64, @intCast(sect.addr)) + rel.r_address + addend
                else
                    addend;
                const target = self.findAtomInSection(@intCast(taddr), @intCast(nsect)) orelse {
                    macho_file.base.fatal("{}: {s},{s}: 0x{x}: bad relocation", .{
                        self.fmtPath(), sect.segName(), sect.sectName(), rel.r_address,
                    });
                    return error.ParseFailed;
                };
                addend = taddr - @as(i64, @intCast(self.getAtom(target).?.getInputAddress(macho_file)));
                break :blk target;
            } else self.symbols.items[rel.r_symbolnum];

            const has_subtractor = if (i > 0 and
                @as(macho.reloc_type_arm64, @enumFromInt(relocs[i - 1].r_type)) == .ARM64_RELOC_SUBTRACTOR)
            blk: {
                if (rel_type != .ARM64_RELOC_UNSIGNED) {
                    macho_file.base.fatal("{}: {s},{s}: 0x{x}: ARM64_RELOC_SUBTRACTOR followed by {s}", .{
                        self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type),
                    });
                    return error.ParseFailed;
                }
                break :blk true;
            } else false;

            const @"type": Relocation.Type = validateRelocType(rel, rel_type) catch |err| {
                switch (err) {
                    error.Pcrel => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: PC-relative {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type) },
                    ),
                    error.NonPcrel => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: non-PC-relative {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type) },
                    ),
                    error.InvalidLength => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: invalid length of {d} in {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @as(u8, 1) << rel.r_length, @tagName(rel_type) },
                    ),
                    error.NonExtern => macho_file.base.fatal(
                        "{}: {s},{s}: 0x{x}: non-extern target in {s} relocation",
                        .{ self.fmtPath(), sect.segName(), sect.sectName(), rel_offset, @tagName(rel_type) },
                    ),
                }
                return error.ParseFailed;
            };

            out.appendAssumeCapacity(.{
                .tag = if (rel.r_extern == 1) .@"extern" else .local,
                .offset = @as(u32, @intCast(rel.r_address)),
                .target = target,
                .addend = addend,
                .type = @"type",
                .meta = .{
                    .pcrel = rel.r_pcrel == 1,
                    .has_subtractor = has_subtractor,
                    .length = rel.r_length,
                    .symbolnum = rel.r_symbolnum,
                },
            });
        }
    }

    fn validateRelocType(rel: macho.relocation_info, rel_type: macho.reloc_type_arm64) !Relocation.Type {
        switch (rel_type) {
            .ARM64_RELOC_UNSIGNED => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                if (rel.r_length != 2 and rel.r_length != 3) return error.InvalidLength;
                return .unsigned;
            },

            .ARM64_RELOC_SUBTRACTOR => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                return .subtractor;
            },

            .ARM64_RELOC_BRANCH26,
            .ARM64_RELOC_PAGE21,
            .ARM64_RELOC_GOT_LOAD_PAGE21,
            .ARM64_RELOC_TLVP_LOAD_PAGE21,
            .ARM64_RELOC_POINTER_TO_GOT,
            => {
                if (rel.r_pcrel == 0) return error.NonPcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                if (rel.r_extern == 0) return error.NonExtern;
                return switch (rel_type) {
                    .ARM64_RELOC_BRANCH26 => .branch,
                    .ARM64_RELOC_PAGE21 => .page,
                    .ARM64_RELOC_GOT_LOAD_PAGE21 => .got_load_page,
                    .ARM64_RELOC_TLVP_LOAD_PAGE21 => .tlvp_page,
                    .ARM64_RELOC_POINTER_TO_GOT => .got,
                    else => unreachable,
                };
            },

            .ARM64_RELOC_PAGEOFF12,
            .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
            .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
            => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                if (rel.r_extern == 0) return error.NonExtern;
                return switch (rel_type) {
                    .ARM64_RELOC_PAGEOFF12 => .pageoff,
                    .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => .got_load_pageoff,
                    .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => .tlvp_pageoff,
                    else => unreachable,
                };
            },

            .ARM64_RELOC_ADDEND => unreachable, // We make it part of the addend field
        }
    }
};

const assert = std.debug.assert;
const dwarf = @import("dwarf.zig");
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
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const LoadCommandIterator = macho.LoadCommandIterator;
const MachO = @import("../MachO.zig");
const Object = @This();
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
const UnwindInfo = @import("UnwindInfo.zig");
