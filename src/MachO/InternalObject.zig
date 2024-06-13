index: File.Index,

sections: std.MultiArrayList(Section) = .{},
atoms: std.ArrayListUnmanaged(Atom) = .{},
atoms_indexes: std.ArrayListUnmanaged(Atom.Index) = .{},
atoms_extra: std.ArrayListUnmanaged(u32) = .{},
symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
globals: std.ArrayListUnmanaged(u32) = .{},

objc_methnames: std.ArrayListUnmanaged(u8) = .{},
objc_selrefs: [@sizeOf(u64)]u8 = [_]u8{0} ** @sizeOf(u64),

entry_index: ?Symbol.Index = null,
dyld_stub_binder_index: ?Symbol.Index = null,
dyld_private_index: ?Symbol.Index = null,
objc_msg_send_index: ?Symbol.Index = null,

num_rebase_relocs: u32 = 0,
output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    for (self.sections.items(.relocs)) |*relocs| {
        relocs.deinit(allocator);
    }
    self.sections.deinit(allocator);
    self.atoms.deinit(allocator);
    self.atoms_indexes.deinit(allocator);
    self.atoms_extra.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.symbols_extra.deinit(allocator);
    self.globals.deinit(allocator);
    self.objc_methnames.deinit(allocator);
}

pub fn init(self: *InternalObject, allocator: Allocator) !void {
    // Atom at index 0 is reserved as null atom
    try self.atoms.append(allocator, .{});
    try self.atoms_extra.append(allocator, 0);
    // Null byte in strtab
    try self.strtab.append(allocator, 0);
}

pub fn initSymbols(self: *InternalObject, macho_file: *MachO) !void {
    const createSymbol = struct {
        fn createSymbol(obj: *InternalObject, name: u32, args: struct {
            type: u8 = macho.N_UNDF,
            desc: u16 = 0,
        }) Symbol.Index {
            const index = obj.addSymbolAssumeCapacity();
            const symbol = &obj.symbols.items[index];
            symbol.name = name;
            symbol.extra = obj.addSymbolExtraAssumeCapacity(.{});
            symbol.flags.dyn_ref = args.desc & macho.REFERENCED_DYNAMICALLY != 0;
            symbol.visibility = if (args.type & macho.N_EXT != 0) blk: {
                break :blk if (args.type & macho.N_PEXT != 0) .hidden else .global;
            } else .local;

            const nlist_idx: u32 = @intCast(obj.symtab.items.len);
            const nlist = obj.symtab.addOneAssumeCapacity();
            nlist.* = .{
                .n_strx = name,
                .n_type = args.type,
                .n_sect = 0,
                .n_desc = args.desc,
                .n_value = 0,
            };
            symbol.nlist_idx = nlist_idx;
            return index;
        }
    }.createSymbol;

    const gpa = macho_file.base.allocator;
    var nsyms = macho_file.options.force_undefined_symbols.len;
    nsyms += 1; // dyld_stub_binder
    nsyms += 1; // _objc_msgSend
    if (!macho_file.options.dylib) {
        nsyms += 1; // entry
        nsyms += 1; // __mh_execute_header
    } else {
        nsyms += 1; // __mh_dylib_header
    }
    nsyms += 1; // ___dso_handle
    nsyms += 1; // dyld_private

    try self.symbols.ensureTotalCapacityPrecise(gpa, nsyms);
    try self.symbols_extra.ensureTotalCapacityPrecise(gpa, nsyms * @sizeOf(Symbol.Extra));
    try self.symtab.ensureTotalCapacityPrecise(gpa, nsyms);
    try self.globals.ensureTotalCapacityPrecise(gpa, nsyms);
    self.globals.resize(gpa, nsyms) catch unreachable;
    @memset(self.globals.items, 0);

    for (macho_file.options.force_undefined_symbols) |name| {
        _ = createSymbol(self, try self.addString(gpa, name), .{});
    }

    self.dyld_stub_binder_index = createSymbol(self, try self.addString(gpa, "dyld_stub_binder"), .{});
    self.objc_msg_send_index = createSymbol(self, try self.addString(gpa, "_objc_msgSend"), .{});

    if (!macho_file.options.dylib) {
        self.entry_index = createSymbol(self, try self.addString(gpa, macho_file.options.entry orelse "_main"), .{});
        _ = createSymbol(self, try self.addString(gpa, "__mh_execute_header"), .{
            .type = macho.N_SECT | macho.N_EXT,
            .desc = macho.REFERENCED_DYNAMICALLY,
        });
    } else {
        _ = createSymbol(self, try self.addString(gpa, "__mh_dylib_header"), .{
            .type = macho.N_SECT | macho.N_EXT,
        });
    }

    _ = createSymbol(self, try self.addString(gpa, "___dso_handle"), .{
        .type = macho.N_SECT | macho.N_EXT,
    });
    self.dyld_private_index = createSymbol(self, try self.addString(gpa, "dyld_private"), .{
        .type = macho.N_SECT,
    });
}

pub fn resolveSymbols(self: *InternalObject, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;

    for (self.symbols.items, 0..) |sym, i| {
        const nlist = self.symtab.items[i];
        const global = &self.globals.items[i];
        const name = sym.getName(macho_file);
        const gop = try macho_file.resolver.getOrPut(gpa, name);
        if (!gop.found_existing) {
            gop.ref_ptr.* = .{ .index = 0, .file = 0 };
        }
        global.* = gop.off;

        if (nlist.undf()) continue;
        if (gop.ref_ptr.getFile(macho_file) == null) {
            gop.ref_ptr.* = .{ .index = @intCast(i), .file = self.index };
            continue;
        }

        if (self.asFile().getSymbolRank(.{
            .archive = false,
            .weak = false,
            .tentative = false,
        }) < gop.ref_ptr.getSymbol(macho_file).?.getSymbolRank(macho_file)) {
            gop.ref_ptr.* = .{ .index = @intCast(i), .file = self.index };
        }
    }
}

pub fn markLive(self: *InternalObject, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (0..self.symbols.items.len) |i| {
        const nlist = self.symtab.items[i];
        if (!nlist.ext()) continue;

        const ref = self.getSymbolRef(@intCast(i), macho_file);
        const file = ref.getFile(macho_file) orelse continue;
        if (file == .object and !file.object.alive) {
            file.object.alive = true;
            file.object.markLive(macho_file);
        }
    }
}

/// Creates a fake input sections __TEXT,__objc_methname and __DATA,__objc_selrefs.
pub fn addObjcMsgsendSections(self: *InternalObject, sym_name: []const u8, macho_file: *MachO) !Symbol.Index {
    const methname_atom_index = try self.addObjcMethnameSection(sym_name, macho_file);
    return try self.addObjcSelrefsSection(methname_atom_index, macho_file);
}

fn addObjcMethnameSection(self: *InternalObject, methname: []const u8, macho_file: *MachO) !Atom.Index {
    const gpa = macho_file.base.allocator;
    const atom_index = try self.addAtom(gpa);
    try self.atoms_indexes.append(gpa, atom_index);
    const atom = self.getAtom(atom_index).?;
    atom.size = methname.len + 1;
    atom.alignment.store(0, .seq_cst);

    const n_sect = try self.addSection(gpa, "__TEXT", "__objc_methname");
    const sect = &self.sections.items(.header)[n_sect];
    sect.flags = macho.S_CSTRING_LITERALS;
    sect.size = atom.size;
    sect.@"align" = 0;
    atom.n_sect = n_sect;
    self.sections.items(.extra)[n_sect].is_objc_methname = true;

    sect.offset = @intCast(self.objc_methnames.items.len);
    try self.objc_methnames.ensureUnusedCapacity(gpa, methname.len + 1);
    self.objc_methnames.writer(gpa).print("{s}\x00", .{methname}) catch unreachable;

    return atom_index;
}

fn addObjcSelrefsSection(self: *InternalObject, methname_atom_index: Atom.Index, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.allocator;
    const atom_index = try self.addAtom(gpa);
    try self.atoms_indexes.append(gpa, atom_index);
    const atom = self.getAtom(atom_index).?;
    atom.size = @sizeOf(u64);
    atom.alignment.store(3, .seq_cst);

    const n_sect = try self.addSection(gpa, "__DATA", "__objc_selrefs");
    const sect = &self.sections.items(.header)[n_sect];
    sect.flags = macho.S_LITERAL_POINTERS | macho.S_ATTR_NO_DEAD_STRIP;
    sect.offset = 0;
    sect.size = atom.size;
    sect.@"align" = 3;
    atom.n_sect = n_sect;
    self.sections.items(.extra)[n_sect].is_objc_selref = true;

    const relocs = &self.sections.items(.relocs)[n_sect];
    try relocs.ensureUnusedCapacity(gpa, 1);
    relocs.appendAssumeCapacity(.{
        .tag = .local,
        .offset = 0,
        .target = methname_atom_index,
        .addend = 0,
        .type = .unsigned,
        .meta = .{
            .pcrel = false,
            .length = 3,
            .symbolnum = 0, // Only used when synthesising unwind records so can be anything
            .has_subtractor = false,
        },
    });
    try atom.addExtra(.{ .rel_index = 0, .rel_count = 1 }, macho_file);
    atom.flags.relocs = true;
    self.num_rebase_relocs += 1;

    const sym_index = try self.addSymbol(gpa);
    const sym = &self.symbols.items[sym_index];
    sym.atom_ref = .{ .index = atom_index, .file = self.index };
    sym.extra = try self.addSymbolExtra(gpa, .{});
    const nlist_idx: u32 = @intCast(self.symtab.items.len);
    const nlist = try self.symtab.addOne(gpa);
    nlist.* = .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = @intCast(n_sect),
        .n_desc = 0,
        .n_value = 0,
    };
    sym.nlist_idx = nlist_idx;
    return sym_index;
}

pub fn resolveLiterals(self: *InternalObject, lp: *MachO.LiteralPool, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const slice = self.sections.slice();
    for (slice.items(.header), self.getAtoms(), 0..) |header, atom_index, n_sect| {
        if (Object.isCstringLiteral(header) or Object.isFixedSizeLiteral(header)) {
            const atom = self.getAtom(atom_index).?;
            const data = self.getSectionData(@intCast(n_sect));
            const res = try lp.insert(gpa, header.type(), data);
            if (!res.found_existing) {
                const sym_index = try self.addSymbol(gpa);
                const sym = &self.symbols.items[sym_index];
                sym.atom_ref = .{ .index = atom_index, .file = self.index };
                sym.extra = try self.addSymbolExtra(gpa, .{});
                const nlist_idx: u32 = @intCast(self.symtab.items.len);
                const nlist = try self.symtab.addOne(gpa);
                nlist.* = .{
                    .n_strx = 0,
                    .n_type = macho.N_SECT,
                    .n_sect = @intCast(n_sect),
                    .n_desc = 0,
                    .n_value = 0,
                };
                sym.nlist_idx = nlist_idx;
                res.ref.* = .{ .index = sym_index, .file = self.index };
            }
            atom.flags.literal_pool = true;
            try atom.addExtra(.{ .literal_index = res.index }, macho_file);
        } else if (Object.isPtrLiteral(header)) {
            const atom = self.getAtom(atom_index).?;
            const relocs = atom.getRelocs(macho_file);
            assert(relocs.len == 1);
            const rel = relocs[0];
            assert(rel.tag == .local);
            const target = rel.getTargetAtom(atom.*, macho_file);
            const addend = std.math.cast(u32, rel.addend) orelse return error.Overflow;
            try buffer.ensureUnusedCapacity(target.size);
            buffer.resize(target.size) catch unreachable;
            try target.getCode(macho_file, buffer.items);
            const res = try lp.insert(gpa, header.type(), buffer.items[addend..]);
            buffer.clearRetainingCapacity();
            if (!res.found_existing) {
                const sym_index = try self.addSymbol(gpa);
                const sym = &self.symbols.items[sym_index];
                sym.atom_ref = .{ .index = atom_index, .file = self.index };
                sym.extra = try self.addSymbolExtra(gpa, .{});
                const nlist_idx: u32 = @intCast(self.symtab.items.len);
                const nlist = try self.symtab.addOne(gpa);
                nlist.* = .{
                    .n_strx = 0,
                    .n_type = macho.N_SECT,
                    .n_sect = @intCast(n_sect),
                    .n_desc = 0,
                    .n_value = 0,
                };
                sym.nlist_idx = nlist_idx;
                res.ref.* = .{ .index = sym_index, .file = self.index };
            }
            atom.flags.literal_pool = true;
            try atom.addExtra(.{ .literal_index = res.index }, macho_file);
        }
    }
}

pub fn dedupLiterals(self: *InternalObject, lp: MachO.LiteralPool, macho_file: *MachO) void {
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
                const target = rel.getTargetAtom(macho_file);
                if (target.getLiteralPoolIndex(macho_file)) |lp_index| {
                    const lp_sym = lp.getSymbol(lp_index, macho_file);
                    const lp_atom_ref = lp_sym.atom_ref;
                    if (target.atom_index != lp_atom_ref.index or self.index != lp_atom_ref.file) {
                        const lp_atom = lp_sym.getAtom(macho_file).?;
                        _ = lp_atom.alignment.fetchMax(target.alignment.load(.seq_cst), .seq_cst);
                        _ = target.alive.swap(false, .seq_cst);
                        rel.mutex.lock();
                        defer rel.mutex.unlock();
                        rel.target = lp.getSymbolRef(lp_index);
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
                        if (target_atom.atom_index != lp_atom_ref.index or target_atom.file != lp_atom_ref.file) {
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

    for (self.symbols.items) |*sym| {
        if (!sym.getSectionFlags().objc_stubs) continue;
        var extra = sym.getExtra(macho_file);
        const tsym_ref = MachO.Ref{ .index = extra.objc_selrefs_index, .file = extra.objc_selrefs_file };
        const tsym = tsym_ref.getSymbol(macho_file);
        if (tsym.getAtom(macho_file)) |atom| {
            if (atom.getLiteralPoolIndex(macho_file)) |lp_index| {
                const lp_sym = lp.getSymbol(lp_index, macho_file);
                const lp_atom_ref = lp_sym.atom_ref;
                if (atom.atom_index != lp_atom_ref.index or atom.file != lp_atom_ref.file) {
                    const lp_atom = lp_sym.getAtom(macho_file).?;
                    _ = lp_atom.alignment.fetchMax(atom.alignment.load(.seq_cst), .seq_cst);
                    _ = atom.alive.swap(false, .seq_cst);
                    const lp_sym_ref = lp.getSymbolRef(lp_index);
                    extra.objc_selrefs_index = lp_sym_ref.index;
                    extra.objc_selrefs_file = lp_sym_ref.file;
                    sym.mutex.lock();
                    defer sym.mutex.unlock();
                    sym.setExtra(extra, macho_file);
                }
            }
        }
    }
}

pub fn scanRelocs(self: *InternalObject, macho_file: *MachO) void {
    if (self.getEntryRef(macho_file)) |ref| {
        if (ref.getFile(macho_file) != null) {
            const sym = ref.getSymbol(macho_file).?;
            if (sym.flags.import) sym.setSectionFlags(.{ .stubs = true });
        }
    }
    if (self.getDyldStubBinderRef(macho_file)) |ref| {
        if (ref.getFile(macho_file) != null) {
            const sym = ref.getSymbol(macho_file).?;
            sym.setSectionFlags(.{ .got = true });
        }
    }
    if (self.getObjcMsgSendRef(macho_file)) |ref| {
        if (ref.getFile(macho_file) != null) {
            const sym = ref.getSymbol(macho_file).?;
            // TODO is it always needed, or only if we are synthesising fast stubs
            sym.setSectionFlags(.{ .got = true });
        }
    }
}

pub fn calcSymtabSize(self: *InternalObject, macho_file: *MachO) void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        if (sym.getFile(macho_file)) |file| if (file.getIndex() != self.index) continue;
        if (sym.getName(macho_file).len == 0) continue;
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
}

pub fn writeSymtab(self: InternalObject, macho_file: *MachO) void {
    var n_strx = self.output_symtab_ctx.stroff;
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        if (sym.getFile(macho_file)) |file| if (file.getIndex() != self.index) continue;
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
}

fn addSection(self: *InternalObject, allocator: Allocator, segname: []const u8, sectname: []const u8) !u32 {
    const n_sect = @as(u32, @intCast(try self.sections.addOne(allocator)));
    self.sections.set(n_sect, .{
        .header = .{
            .sectname = MachO.makeStaticString(sectname),
            .segname = MachO.makeStaticString(segname),
        },
    });
    return n_sect;
}

pub fn getSectionData(self: *const InternalObject, index: u32) []const u8 {
    const slice = self.sections.slice();
    assert(index < slice.items(.header).len);
    const sect = slice.items(.header)[index];
    const extra = slice.items(.extra)[index];
    if (extra.is_objc_methname) {
        return self.objc_methnames.items[sect.offset..][0..sect.size];
    } else if (extra.is_objc_selref) {
        return &self.objc_selrefs;
    } else @panic("ref to non-existent section");
}

pub fn addString(self: *InternalObject, allocator: Allocator, name: []const u8) !u32 {
    const off: u32 = @intCast(self.strtab.items.len);
    try self.strtab.ensureUnusedCapacity(allocator, name.len + 1);
    self.strtab.appendSliceAssumeCapacity(name);
    self.strtab.appendAssumeCapacity(0);
    return off;
}

pub fn getString(self: InternalObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

fn addAtom(self: *InternalObject, allocator: Allocator) !Atom.Index {
    const atom_index: Atom.Index = @intCast(self.atoms.items.len);
    const atom = try self.atoms.addOne(allocator);
    atom.* = .{ .file = self.index, .atom_index = atom_index };
    return atom_index;
}

pub fn getAtom(self: *InternalObject, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn getAtoms(self: *InternalObject) []const Atom.Index {
    return self.atoms_indexes.items;
}

pub fn addAtomExtra(self: *InternalObject, allocator: Allocator, extra: Atom.Extra) !u32 {
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    try self.atoms_extra.ensureUnusedCapacity(allocator, fields.len);
    return self.addAtomExtraAssumeCapacity(extra);
}

pub fn addAtomExtraAssumeCapacity(self: *InternalObject, extra: Atom.Extra) u32 {
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

pub fn getAtomExtra(self: InternalObject, index: u32) ?Atom.Extra {
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

pub fn setAtomExtra(self: *InternalObject, index: u32, extra: Atom.Extra) void {
    assert(index > 0);
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    inline for (fields, 0..) |field, i| {
        self.atoms_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
}

pub fn getEntryRef(self: InternalObject, macho_file: *MachO) ?MachO.Ref {
    const index = self.entry_index orelse return null;
    return self.getSymbolRef(index, macho_file);
}

pub fn getDyldStubBinderRef(self: InternalObject, macho_file: *MachO) ?MachO.Ref {
    const index = self.dyld_stub_binder_index orelse return null;
    return self.getSymbolRef(index, macho_file);
}

pub fn getDyldPrivateRef(self: InternalObject, macho_file: *MachO) ?MachO.Ref {
    const index = self.dyld_private_index orelse return null;
    return self.getSymbolRef(index, macho_file);
}

pub fn getObjcMsgSendRef(self: InternalObject, macho_file: *MachO) ?MachO.Ref {
    const index = self.objc_msg_send_index orelse return null;
    return self.getSymbolRef(index, macho_file);
}

pub fn addSymbol(self: *InternalObject, allocator: Allocator) !Symbol.Index {
    try self.symbols.ensureUnusedCapacity(allocator, 1);
    return self.addSymbolAssumeCapacity();
}

pub fn addSymbolAssumeCapacity(self: *InternalObject) Symbol.Index {
    const index: Symbol.Index = @intCast(self.symbols.items.len);
    const symbol = self.symbols.addOneAssumeCapacity();
    symbol.* = .{ .file = self.index };
    return index;
}

pub fn getSymbolRef(self: InternalObject, index: Symbol.Index, macho_file: *MachO) MachO.Ref {
    const off = self.globals.items[index];
    if (macho_file.resolver.get(off)) |ref| return ref;
    return .{ .index = index, .file = self.index };
}

pub fn addSymbolExtra(self: *InternalObject, allocator: Allocator, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    try self.symbols_extra.ensureUnusedCapacity(allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

fn addSymbolExtraAssumeCapacity(self: *InternalObject, extra: Symbol.Extra) u32 {
    const index = @as(u32, @intCast(self.symbols_extra.items.len));
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    inline for (fields) |field| {
        self.symbols_extra.appendAssumeCapacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        });
    }
    return index;
}

pub fn getSymbolExtra(self: InternalObject, index: u32) Symbol.Extra {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
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

pub fn setSymbolExtra(self: *InternalObject, index: u32, extra: Symbol.Extra) void {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    inline for (fields, 0..) |field, i| {
        self.symbols_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
}

const FormatContext = struct {
    self: *InternalObject,
    macho_file: *MachO,
};

pub fn fmtAtoms(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(formatAtoms) {
    return .{ .data = .{
        .self = self,
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
    try writer.writeAll("  atoms\n");
    for (ctx.self.getAtoms()) |atom_index| {
        const atom = ctx.self.getAtom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(ctx.macho_file)});
    }
}

pub fn fmtSymtab(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .self = self,
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
    const macho_file = ctx.macho_file;
    const self = ctx.self;
    try writer.writeAll("  symbols\n");
    for (self.symbols.items, 0..) |sym, i| {
        const ref = self.getSymbolRef(@intCast(i), macho_file);
        if (ref.getFile(macho_file) == null) {
            // TODO any better way of handling this?
            try writer.print("    {s} : unclaimed\n", .{sym.getName(macho_file)});
        } else {
            try writer.print("    {}\n", .{ref.getSymbol(macho_file).?.fmt(macho_file)});
        }
    }
}

const Section = struct {
    header: macho.section_64,
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
    extra: Extra = .{},

    const Extra = packed struct {
        is_objc_methname: bool = false,
        is_objc_selref: bool = false,
    };
};

const assert = std.debug.assert;
const macho = std.macho;
const mem = std.mem;
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const InternalObject = @This();
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
