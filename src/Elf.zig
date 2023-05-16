base: Zld,
arena: std.heap.ArenaAllocator.State,
options: Options,
shoff: u64 = 0,

objects: std.ArrayListUnmanaged(u32) = .{},
shared_objects: std.ArrayListUnmanaged(u32) = .{},
files: std.MultiArrayList(File) = .{},

sections: std.MultiArrayList(Section) = .{},
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

first_load_seg_index: u16 = 0,
phdr_seg_index: ?u16 = null,
interp_seg_index: ?u16 = null,
tls_seg_index: ?u16 = null,

text_sect_index: ?u16 = null,
got_sect_index: ?u16 = null,
symtab_sect_index: ?u16 = null,
strtab_sect_index: ?u16 = null,
shstrtab_sect_index: ?u16 = null,
interp_sect_index: ?u16 = null,
dynamic_sect_index: ?u16 = null,
dynsymtab_sect_index: ?u16 = null,
dynstrtab_sect_index: ?u16 = null,

internal_object_index: ?u32 = null,
dynamic_index: ?u32 = null,
init_array_start_index: ?u32 = null,
init_array_end_index: ?u32 = null,
fini_array_start_index: ?u32 = null,
fini_array_end_index: ?u32 = null,
got_index: ?u32 = null,

entry_index: ?u32 = null,

globals: std.ArrayListUnmanaged(Symbol) = .{},
// TODO convert to context-adapted
globals_table: std.StringHashMapUnmanaged(u32) = .{},

string_intern: StringTable(.string_intern) = .{},

shstrtab: StringTable(.shstrtab) = .{},
strtab: StringTable(.strtab) = .{},
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
dynsymtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
dynstrtab: StringTable(.dynstrtab) = .{},

got_section: SyntheticSection(u32, *Elf, .{
    .log_scope = .got_section,
    .entry_size = @sizeOf(u64),
    .baseAddrFn = Elf.getGotBaseAddress,
    .writeFn = Elf.writeGotEntry,
}) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

pub const base_tag = Zld.Tag.elf;

pub const File = union(enum) {
    null: void,
    internal: InternalObject,
    object: Object,
    shared: SharedObject,

    pub fn getIndex(file: File) Index {
        return switch (file) {
            .null => unreachable,
            inline else => |x| x.index,
        };
    }

    pub fn getPath(file: File) []const u8 {
        return switch (file) {
            .null, .internal => unreachable,
            .object => |x| x.name, // TODO wrap in archive path if extracted
            .shared => |x| x.name,
        };
    }

    fn resolveSymbols(file: File, elf_file: *Elf) void {
        switch (file) {
            .null => unreachable,
            inline else => |x| x.resolveSymbols(elf_file),
        }
    }

    fn resetGlobals(file: File, elf_file: *Elf) void {
        switch (file) {
            .null => unreachable,
            inline else => |x| x.resetGlobals(elf_file),
        }
    }

    pub fn isAlive(file: File) bool {
        return switch (file) {
            .null => unreachable,
            inline else => |x| x.alive,
        };
    }

    /// Encodes symbol rank so that the following ordering applies:
    /// * strong defined
    /// * weak defined
    /// * strong in lib (dso/archive)
    /// * weak in lib (dso/archive)
    /// * unclaimed
    pub fn getSymbolRank(file: File, sym: elf.Elf64_Sym, in_archive: bool) u32 {
        const base: u4 = blk: {
            if (file == .shared or in_archive) break :blk switch (sym.st_bind()) {
                elf.STB_GLOBAL => 3,
                else => 4,
            };
            break :blk switch (sym.st_bind()) {
                elf.STB_GLOBAL => 1,
                else => 2,
            };
        };
        return (@as(u32, base) << 24) + file.getIndex();
    }

    pub const Index = u32;
};

pub const FilePtr = union(enum) {
    internal: *InternalObject,
    object: *Object,
    shared: *SharedObject,

    pub fn deref(ptr: FilePtr) File {
        return switch (ptr) {
            .internal => |x| .{ .internal = x.* },
            .object => |x| .{ .object = x.* },
            .shared => |x| .{ .shared = x.* },
        };
    }

    pub fn setAlive(ptr: FilePtr) void {
        switch (ptr) {
            inline else => |x| x.alive = true,
        }
    }

    pub fn markLive(ptr: FilePtr, elf_file: *Elf) void {
        switch (ptr) {
            .internal => {},
            inline else => |x| x.markLive(elf_file),
        }
    }
};

const Section = struct {
    shdr: elf.Elf64_Shdr,
    first_atom: ?Atom.Index,
    last_atom: ?Atom.Index, // TODO remove this
};

const Segment = struct {
    phdr: elf.Elf64_Phdr,
    file_align: u64,
    shdrs: std.ArrayListUnmanaged(u16) = .{},
};

const default_base_addr: u64 = 0x200000;
const default_page_size: u64 = 0x1000;

pub fn openPath(allocator: Allocator, options: Options, thread_pool: *ThreadPool) !*Elf {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options, thread_pool);
    errdefer allocator.destroy(self);

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*Elf {
    const self = try gpa.create(Elf);

    self.* = .{
        .base = .{
            .tag = .elf,
            .allocator = gpa,
            .file = undefined,
            .thread_pool = thread_pool,
        },
        .arena = std.heap.ArenaAllocator.init(gpa).state,
        .options = options,
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    const gpa = self.base.allocator;
    self.string_intern.deinit(gpa);
    self.symtab.deinit(gpa);
    self.shstrtab.deinit(gpa);
    self.strtab.deinit(gpa);
    self.atoms.deinit(gpa);
    self.globals.deinit(gpa);
    self.globals_table.deinit(gpa);
    self.got_section.deinit(gpa);
    self.phdrs.deinit(gpa);
    self.sections.deinit(gpa);
    for (self.files.items(.tags), self.files.items(.data)) |tag, *data| switch (tag) {
        .null => {},
        .internal => data.internal.deinit(gpa),
        .object => data.object.deinit(gpa),
        .shared => data.shared.deinit(gpa),
    };
    self.files.deinit(gpa);
    self.objects.deinit(gpa);
    self.shared_objects.deinit(gpa);
    self.dynsymtab.deinit(gpa);
    self.dynstrtab.deinit(gpa);
    self.arena.promote(gpa).deinit();
}

fn resolveLib(
    arena: Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    opts: Zld.SystemLib,
) !?[]const u8 {
    if (fs.path.isAbsolute(name)) return try arena.dupe(u8, name);
    if (!opts.static) {
        const search_name = blk: {
            if (hasSharedLibraryExt(name)) break :blk name;
            break :blk try std.fmt.allocPrint(arena, "lib{s}.so", .{name});
        };
        if (try resolveLibPath(arena, search_dirs, search_name)) |full_path| return full_path;
    }
    const search_name = blk: {
        if (mem.endsWith(u8, name, ".a")) break :blk name;
        break :blk try std.fmt.allocPrint(arena, "lib{s}.a", .{name});
    };
    if (try resolveLibPath(arena, search_dirs, search_name)) |full_path| return full_path;
    return null;
}

fn resolveLibPath(arena: Allocator, search_dirs: []const []const u8, search_name: []const u8) !?[]const u8 {
    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, search_name });
        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();
        return full_path;
    }
    return null;
}

fn hasSharedLibraryExt(filename: []const u8) bool {
    if (mem.endsWith(u8, filename, ".so")) return true;
    // Look for .so.X, .so.X.Y, .so.X.Y.Z
    var it = mem.split(u8, filename, ".");
    _ = it.first();
    var so_txt = it.next() orelse return false;
    while (!mem.eql(u8, so_txt, "so")) {
        so_txt = it.next() orelse return false;
    }
    const n1 = it.next() orelse return false;
    const n2 = it.next();
    const n3 = it.next();

    _ = std.fmt.parseInt(u32, n1, 10) catch return false;
    if (n2) |x| _ = std.fmt.parseInt(u32, x, 10) catch return false;
    if (n3) |x| _ = std.fmt.parseInt(u32, x, 10) catch return false;
    if (it.next() != null) return false;

    return true;
}

pub fn flush(self: *Elf) !void {
    const gpa = self.base.allocator;

    // Append empty string to string tables.
    try self.string_intern.buffer.append(gpa, 0);
    try self.strtab.buffer.append(gpa, 0);
    try self.shstrtab.buffer.append(gpa, 0);
    try self.dynstrtab.buffer.append(gpa, 0);
    // Append null section.
    _ = try self.addSection(.{ .name = "" });
    // Append null atom.
    try self.atoms.append(gpa, .{});
    // Append null symbols.
    try self.symtab.append(gpa, .{
        .st_name = 0,
        .st_info = 0,
        .st_other = 0,
        .st_shndx = 0,
        .st_value = 0,
        .st_size = 0,
    });
    try self.dynsymtab.append(gpa, .{
        .st_name = 0,
        .st_info = 0,
        .st_other = 0,
        .st_shndx = 0,
        .st_value = 0,
        .st_size = 0,
    });
    // Append null file.
    try self.files.append(gpa, .null);

    var arena_allocator = self.arena.promote(gpa);
    defer self.arena = arena_allocator.state;
    const arena = arena_allocator.allocator();

    var search_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.search_dirs) |dir| {
        // Verify that search path actually exists
        var tmp = fs.cwd().openDir(dir, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                self.base.warn("{s}: library search directory not found", .{dir});
                continue;
            },
            else => |e| return e,
        };
        defer tmp.close();
        try search_dirs.append(dir);
    }

    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);

    const parse_ctx = ParseLibsCtx{
        .search_dirs = search_dirs.items,
        .libs = &libs,
    };

    for (self.options.positionals) |obj| {
        try self.parsePositional(arena, obj, parse_ctx);
    }

    self.base.reportWarningsAndErrorsAndExit();

    for (self.options.libs.keys(), self.options.libs.values()) |lib_name, lib_info| {
        try self.parseLib(arena, lib_name, lib_info, parse_ctx);
    }

    if (self.base.errors.items.len > 0) {
        self.base.fatal("library search paths:", .{});
        for (search_dirs.items) |dir| {
            self.base.fatal("  {s}", .{dir});
        }
    }
    self.base.reportWarningsAndErrorsAndExit();

    {
        const index = @intCast(File.Index, try self.files.addOne(gpa));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object_index = index;
    }

    try self.resolveSymbols();
    try self.markImportsAndExports();

    // Set the entrypoint if found
    self.entry_index = blk: {
        if (self.options.output_mode != .exe) break :blk null;
        const entry_name = self.options.entry orelse "_start";
        break :blk self.globals_table.get(entry_name) orelse null;
    };
    if (self.options.output_mode == .exe and self.entry_index == null) {
        self.base.fatal("no entrypoint found: '{s}'", .{self.options.entry orelse "_start"});
    }

    if (self.options.gc_sections) {
        try gc.gcAtoms(self);

        if (self.options.print_gc_sections) {
            try gc.dumpPrunedAtoms(self);
        }
    }

    if (!self.options.allow_multiple_definition) {
        self.checkDuplicates();
        self.base.reportWarningsAndErrorsAndExit();
    }

    try self.resolveSyntheticSymbols();

    if (self.options.execstack_if_needed) {
        for (self.objects.items) |index| {
            if (self.getFile(index).?.object.needs_exec_stack) {
                self.options.execstack = true;
                break;
            }
        }
    }

    self.claimUnresolved();
    try self.scanRelocs();
    self.checkUndefined();
    self.base.reportWarningsAndErrorsAndExit();

    try self.initSections();
    try self.sortSections();
    try self.calcSectionSizes();
    try self.setDynsymtab();
    try self.setSymtab();
    self.setShstrtab();

    try self.allocateSections();
    state_log.debug("{}", .{self.dumpState()});
    if (true) return error.Todo;
    // try self.initSegments();
    // self.calcLoadSegmentSizes();
    // self.allocateSegments();
    self.allocateAllocSections();
    self.allocateAtoms();
    self.allocateLocals();
    self.allocateGlobals();
    self.allocateSyntheticSymbols();

    self.shoff = blk: {
        const shdr = self.sections.items(.shdr)[self.sections.len - 1];
        const offset = shdr.sh_offset + shdr.sh_size;
        break :blk mem.alignForwardGeneric(u64, offset, @alignOf(elf.Elf64_Shdr));
    };

    state_log.debug("{}", .{self.dumpState()});

    try self.writeAtoms();
    try self.writeSyntheticSections();
    try self.writePhdrs();
    try self.writeShdrs();
    try self.writeHeader();

    self.base.reportWarningsAndErrorsAndExit();
}

fn initSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.is_alive) continue;
            try atom.initOutputSection(self);
        }
    }

    if (self.got_section.count() > 0) {
        self.got_sect_index = try self.addSection(.{
            .name = ".got",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .addralign = @alignOf(u64),
        });
    }

    self.shstrtab_sect_index = try self.addSection(.{
        .name = ".shstrtab",
        .type = elf.SHT_STRTAB,
        .entsize = 1,
        .addralign = 1,
    });

    if (!self.options.strip_all) {
        self.strtab_sect_index = try self.addSection(.{
            .name = ".strtab",
            .type = elf.SHT_STRTAB,
            .entsize = 1,
            .addralign = 1,
        });
        self.symtab_sect_index = try self.addSection(.{
            .name = ".symtab",
            .type = elf.SHT_SYMTAB,
            .link = self.strtab_sect_index.?,
            .addralign = @alignOf(elf.Elf64_Sym),
            .entsize = @sizeOf(elf.Elf64_Sym),
        });
    }

    if (self.options.dynamic_linker != null) {
        self.interp_sect_index = try self.addSection(.{
            .name = ".interp",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC,
            .addralign = 1,
        });
    }

    if (self.shared_objects.items.len > 0) {
        self.dynstrtab_sect_index = try self.addSection(.{
            .name = ".dynstr",
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_STRTAB,
            .entsize = 1,
            .addralign = 1,
        });
        self.dynsymtab_sect_index = try self.addSection(.{
            .name = ".dynsym",
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_DYNSYM,
            .link = self.dynstrtab_sect_index.?,
            .addralign = @alignOf(elf.Elf64_Sym),
            .entsize = @sizeOf(elf.Elf64_Sym),
        });
    }
}

fn calcSectionSizes(self: *Elf) !void {
    var slice = self.sections.slice();
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.is_alive) continue;

            var section = slice.get(atom.out_shndx);
            const alignment = try math.powi(u64, 2, atom.alignment);
            const addr = mem.alignForwardGeneric(u64, section.shdr.sh_size, alignment);
            const padding = addr - section.shdr.sh_size;
            atom.value = addr;
            section.shdr.sh_size += padding + atom.size;
            section.shdr.sh_addralign = @max(section.shdr.sh_addralign, alignment);

            if (section.last_atom) |last_atom_index| {
                const last_atom = self.getAtom(last_atom_index).?;
                last_atom.next = @intCast(u32, atom_index);
                atom.prev = last_atom_index;
            } else {
                assert(section.first_atom == null);
                section.first_atom = @intCast(u32, atom_index);
            }
            section.last_atom = @intCast(u32, atom_index);

            slice.set(atom.out_shndx, section);
        }
    }

    if (self.got_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.got_section.size();
        shdr.sh_addralign = @sizeOf(u64);
    }

    if (self.interp_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        const size = self.options.dynamic_linker.?.len + 1;
        shdr.sh_size = size;
        shdr.sh_addralign = 1;
    }
}

fn initPhdrs(self: *Elf) !void {
    // Add PHDR phdr
    self.phdr_seg_index = try self.addSegment(.{
        .type = elf.PT_PHDR,
        .flags = elf.PF_R,
        .@"align" = @alignOf(elf.Elf64_Phdr),
        .addr = default_base_addr + @sizeOf(elf.Elf64_Ehdr),
        .offset = @sizeOf(elf.Elf64_Ehdr),
    });

    // Add INTERP phdr if required
    if (self.interp_sect_index) |index| {
        const shdr = self.sections.items(.shdr)[index];
        self.interp_seg_index = try self.addSegment(.{
            .type = elf.PT_INTERP,
            .flags = elf.PF_R,
            .@"align" = 1,
            .offset = shdr.sh_offset,
            .addr = shdr.sh_addr,
            .filesz = shdr.sh_size,
            .memsz = shdr.sh_size,
        });
    }

    // Add LOAD phdrs
    var last_phdr: ?u16 = null;
    const slice = self.sections.slice();
    var shndx: usize = 0;
    while (shndx < slice.len) {
        const shdr = slice.items(.shdr)[shndx];
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) {
            shndx += 1;
            continue;
        }
        last_phdr = try self.addSegment(.{
            .type = elf.PT_LOAD,
            .flags = shdrToPhdrFlags(shdr.sh_flags),
            .@"align" = @max(default_page_size, shdr.sh_addralign),
            .offset = if (last_phdr == null) 0 else shdr.sh_offset,
            .addr = if (last_phdr == null) default_base_addr else shdr.sh_addr,
        });
        const p_flags = self.phdrs.items[last_phdr.?].p_flags;
        try self.addShdrToPhdr(last_phdr.?, shdr);
        shndx += 1;

        while (shndx < slice.len) : (shndx += 1) {
            const next = slice.items(.shdr)[shndx];
            if (p_flags == shdrToPhdrFlags(next.sh_flags) and
                next.sh_offset - shdr.sh_offset == next.sh_addr - shdr.sh_addr)
            {
                try self.addShdrToPhdr(last_phdr.?, next);
                continue;
            }
            break;
        }
    }

    // Add PT_GNU_STACK phdr that controls some stack attributes that apparently may or may not
    // be respected by the OS.
    _ = try self.addSegment(.{
        .type = elf.PT_GNU_STACK,
        .flags = if (self.options.execstack) elf.PF_W | elf.PF_R | elf.PF_X else elf.PF_W | elf.PF_R,
        .memsz = self.options.stack_size orelse 0,
    });

    // Backpatch size of the PHDR phdr
    if (self.phdr_seg_index) |index| {
        const phdr = &self.phdrs.items[index];
        const size = @sizeOf(elf.Elf64_Phdr) * self.phdrs.items.len;
        phdr.p_filesz = size;
        phdr.p_memsz = size;
    }
}

fn addShdrToPhdr(self: *Elf, phdr_index: u16, shdr: elf.Elf64_Shdr) !void {
    const phdr = &self.phdrs.items[phdr_index];
    phdr.p_align = @max(phdr.p_align, shdr.sh_addralign);
    if (shdr.sh_type != elf.SHT_NOBITS) {
        phdr.p_filesz = shdr.sh_addr + shdr.sh_size - phdr.p_vaddr;
    }
    phdr.p_memsz = shdr.sh_addr + shdr.sh_size - phdr.p_vaddr;
}

fn shdrToPhdrFlags(sh_flags: u64) u32 {
    const write = sh_flags & elf.SHF_WRITE != 0;
    const exec = sh_flags & elf.SHF_EXECINSTR != 0;
    var out_flags: u32 = elf.PF_R;
    if (write) out_flags |= elf.PF_W;
    if (exec) out_flags |= elf.PF_X;
    return out_flags;
}

fn allocateSectionsInMemory(self: *Elf, base_offset: u64) !void {
    var addr = default_base_addr + base_offset;
    for (self.sections.items(.shdr)[1..], 1..) |*shdr, i| {
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        if (i != 1) {
            const prev_shdr = self.sections.items(.shdr)[i - 1];
            if (shdrToPhdrFlags(shdr.sh_flags) != shdrToPhdrFlags(prev_shdr.sh_flags)) {
                // We need advance by page size
                addr += default_page_size;
            }
        }

        addr = mem.alignForwardGeneric(u64, addr, shdr.sh_addralign);
        shdr.sh_addr = addr;
        addr += shdr.sh_size;
    }
}

fn allocatesSectionsInFile(self: *Elf, base_offset: u64) void {
    var offset = base_offset;
    for (self.sections.items(.shdr)[1..]) |*shdr| {
        defer if (shdr.sh_type != elf.SHT_NOBITS) {
            offset = shdr.sh_offset + shdr.sh_size;
        };
        shdr.sh_offset = mem.alignForwardGeneric(u64, offset, shdr.sh_addralign);
    }
}

fn allocateSections(self: *Elf) !void {
    while (true) {
        const nphdrs = self.phdrs.items.len;
        const base_offset: u64 = @sizeOf(elf.Elf64_Ehdr) + nphdrs * @sizeOf(elf.Elf64_Phdr);
        try self.allocateSectionsInMemory(base_offset);
        self.allocatesSectionsInFile(base_offset);
        self.phdrs.clearRetainingCapacity();
        try self.initPhdrs();
        if (nphdrs == self.phdrs.items.len) break;
    }
}

fn getSectionRank(self: *Elf, shndx: u16) u8 {
    if (maybeEql(u16, self.interp_sect_index, shndx)) return 1;
    if (maybeEql(u16, self.dynsymtab_sect_index, shndx)) return 2;
    if (maybeEql(u16, self.dynstrtab_sect_index, shndx)) return 3;
    if (maybeEql(u16, self.symtab_sect_index, shndx)) return 0xf9;
    if (maybeEql(u16, self.strtab_sect_index, shndx)) return 0xfa;

    const shdr = self.sections.items(.shdr)[shndx];
    const name = self.shstrtab.getAssumeExists(shdr.sh_name);
    const flags = shdr.sh_flags;
    switch (shdr.sh_type) {
        elf.SHT_NULL => return 0,

        elf.SHT_PREINIT_ARRAY,
        elf.SHT_INIT_ARRAY,
        elf.SHT_FINI_ARRAY,
        => return 0xf1,

        elf.SHT_PROGBITS => if (flags & elf.SHF_ALLOC != 0) {
            if (flags & elf.SHF_EXECINSTR != 0) {
                return 0xf1;
            } else if (flags & elf.SHF_WRITE != 0) {
                return if (flags & elf.SHF_TLS != 0) 0xf2 else 0xf4;
            } else {
                return 0xf0;
            }
        } else {
            if (mem.startsWith(u8, name, ".debug")) {
                return 0xf6;
            } else {
                return 0xf7;
            }
        },

        elf.SHT_NOBITS => return if (flags & elf.SHF_TLS != 0) 0xf3 else 0xf5,
        else => return 0xff,
    }
}

fn sortSections(self: *Elf) !void {
    const Entry = struct {
        shndx: u16,

        pub fn lessThan(elf_file: *Elf, lhs: @This(), rhs: @This()) bool {
            return elf_file.getSectionRank(lhs.shndx) < elf_file.getSectionRank(rhs.shndx);
        }
    };

    const gpa = self.base.allocator;

    var entries = try std.ArrayList(Entry).initCapacity(gpa, self.sections.slice().len);
    defer entries.deinit();
    for (0..self.sections.slice().len) |shndx| {
        entries.appendAssumeCapacity(.{ .shndx = @intCast(u16, shndx) });
    }

    std.sort.sort(Entry, entries.items, self, Entry.lessThan);

    const backlinks = try gpa.alloc(u16, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.shndx] = @intCast(u16, i);
    }

    var slice = self.sections.toOwnedSlice();
    defer slice.deinit(gpa);

    try self.sections.ensureTotalCapacity(gpa, slice.len);
    for (entries.items) |sorted| {
        self.sections.appendAssumeCapacity(slice.get(sorted.shndx));
    }

    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.is_alive) continue;
            atom.out_shndx = backlinks[atom.out_shndx];
        }
    }

    for (&[_]*?u16{
        &self.text_sect_index,
        &self.got_sect_index,
        &self.symtab_sect_index,
        &self.strtab_sect_index,
        &self.shstrtab_sect_index,
        &self.interp_sect_index,
        &self.dynamic_sect_index,
        &self.dynsymtab_sect_index,
        &self.dynstrtab_sect_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }

    if (self.symtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.strtab_sect_index.?;
    }

    if (self.dynsymtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynstrtab_sect_index.?;
    }
}

fn initSegments(self: *Elf) !void {
    const gpa = self.base.allocator;

    // Add PHDR segment
    self.phdr_seg_index = try self.addSegment(.{
        .type = elf.PT_PHDR,
        .flags = elf.PF_R,
        .@"align" = @alignOf(elf.Elf64_Phdr),
    });

    // Add INTERP segment if required
    if (self.interp_sect_index) |index| {
        const seg_index = try self.addSegment(.{
            .type = elf.PT_INTERP,
            .flags = elf.PF_R,
            .@"align" = 1,
        });
        try self.segments.items(.shdrs)[seg_index].append(gpa, index);
        self.interp_seg_index = seg_index;
    }

    // The first loadable segment is always read-only even if there is no
    // read-only section to load. We need a read-only loadable segment
    // to coalesce PHDR segment into together with the Ehdr.
    self.first_load_seg_index = try self.addSegment(.{
        .type = elf.PT_LOAD,
        .flags = elf.PF_R,
        .@"align" = default_page_size,
    });
    var last_phdr = self.first_load_seg_index;

    // Then, we proceed in creating segments for all alloc sections.
    for (self.sections.items(.shdr)) |shdr| {
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        const write = shdr.sh_flags & elf.SHF_WRITE != 0;
        const exec = shdr.sh_flags & elf.SHF_EXECINSTR != 0;
        var flags: u32 = elf.PF_R;
        if (write) flags |= elf.PF_W;
        if (exec) flags |= elf.PF_X;

        const phdr = self.segments.items(.phdr)[last_phdr];
        if (phdr.p_flags != flags) {
            last_phdr = try self.addSegment(.{
                .type = elf.PT_LOAD,
                .flags = flags,
                .@"align" = default_page_size,
            });
        }
    }

    var phdr_index = self.first_load_seg_index;
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const shndx = @intCast(u16, i);
        if (maybeEql(u16, self.interp_sect_index, shndx)) continue;
        if (shdr.sh_flags & elf.SHF_ALLOC == 0) continue;
        const write = shdr.sh_flags & elf.SHF_WRITE != 0;
        const exec = shdr.sh_flags & elf.SHF_EXECINSTR != 0;
        var flags: u32 = elf.PF_R;
        if (write) flags |= elf.PF_W;
        if (exec) flags |= elf.PF_X;
        if (self.segments.items(.phdr)[phdr_index].p_flags != flags) phdr_index += 1;
        try self.segments.items(.shdrs)[phdr_index].append(gpa, shndx);
    }

    // Add PT_GNU_STACK segment that controls some stack attributes that apparently may or may not
    // be respected by the OS.
    _ = try self.addSegment(.{
        .type = elf.PT_GNU_STACK,
        .flags = if (self.options.execstack) elf.PF_W | elf.PF_R | elf.PF_X else elf.PF_W | elf.PF_R,
        .memsz = self.options.stack_size orelse 0,
    });

    // Backpatch size of the PHDR segment now that we now how many program headers
    // we actually have.
    if (self.phdr_seg_index) |index| {
        const phdr = &self.segments.items(.phdr)[index];
        const size = self.segments.slice().len * @sizeOf(elf.Elf64_Phdr);
        phdr.p_filesz = size;
        phdr.p_memsz = size;
    }
}

fn calcLoadSegmentSizes(self: *Elf) void {
    const first_index = self.first_load_seg_index;
    for (self.segments.items(.phdr)[first_index..], first_index..) |*phdr, phdr_index| {
        const file_align = &self.segments.items(.file_align)[phdr_index];
        const sect_range = self.getSectionIndexes(@intCast(u16, phdr_index));
        const start = sect_range.start;
        const end = sect_range.end;

        for (self.sections.items(.shdr)[start..end]) |shdr| {
            file_align.* = @max(file_align.*, shdr.sh_addralign);
            if (shdr.sh_type != elf.SHT_NOBITS) {
                phdr.p_filesz = mem.alignForwardGeneric(u64, phdr.p_filesz, shdr.sh_addralign) + shdr.sh_size;
            }
            phdr.p_memsz = mem.alignForwardGeneric(u64, phdr.p_memsz, shdr.sh_addralign) + shdr.sh_size;
        }
    }

    const load_phdr = &self.segments.items(.phdr)[first_index];
    load_phdr.p_filesz += @sizeOf(elf.Elf64_Ehdr);

    if (self.phdr_seg_index) |index| {
        const phdr = self.segments.items(.phdr)[index];
        load_phdr.p_filesz += mem.alignForwardGeneric(u64, phdr.p_filesz, phdr.p_align);
    }

    if (self.interp_sect_index) |index| {
        const phdr_index = self.sections.items(.phdr)[index].?;
        const phdr = self.segments.items(.phdr)[phdr_index];
        load_phdr.p_filesz += mem.alignForwardGeneric(u64, phdr.p_filesz, phdr.p_align);
    }

    load_phdr.p_memsz = load_phdr.p_filesz;
}

fn allocateSegments(self: *Elf) void {
    // Now that we have initialized segments, we can go ahead and allocate them in file and memory.
    var offset: u64 = @sizeOf(elf.Elf64_Ehdr);
    var vaddr: u64 = default_base_addr + offset;

    // First, allocate segments that are not PT_LOAD.
    // They already have sizes pre-set so we just allocate.
    const first_phdr = self.first_load_seg_index;
    for (self.segments.items(.phdr)[0..first_phdr]) |*phdr| {
        offset = mem.alignForwardGeneric(u64, offset, phdr.p_align);
        vaddr = mem.alignForwardGeneric(u64, vaddr, phdr.p_align);

        phdr.p_offset = offset;
        phdr.p_vaddr = vaddr;
        phdr.p_paddr = vaddr;

        offset += phdr.p_filesz;
        vaddr += phdr.p_memsz;
    }

    // The first loadable segment has to also encompass the headers, program header table, interp, etc.
    offset = 0;
    vaddr = default_base_addr;

    for (self.segments.items(.phdr)[first_phdr..], first_phdr..) |*phdr, i| {
        if (phdr.p_type == elf.PT_GNU_STACK) continue;

        const file_align = self.segments.items(.file_align)[i];
        offset = mem.alignForwardGeneric(u64, offset, file_align);
        vaddr = mem.alignForwardGeneric(u64, vaddr, phdr.p_align) + @rem(offset, phdr.p_align);

        phdr.p_offset = offset;
        phdr.p_vaddr = vaddr;
        phdr.p_paddr = vaddr;

        offset += phdr.p_filesz;
        vaddr += phdr.p_memsz;
    }
}

fn allocateAllocSections(self: *Elf) void {
    const phdrs_offset = self.segments.slice().len * @sizeOf(elf.Elf64_Phdr) + @sizeOf(elf.Elf64_Ehdr);

    const first_index = self.first_load_seg_index;
    for (self.segments.items(.phdr)[first_index..], first_index..) |phdr, phdr_index| {
        const sect_range = self.getSectionIndexes(@intCast(u16, phdr_index));
        const start = sect_range.start;
        const end = sect_range.end;

        var offset = phdr.p_offset;
        var vaddr = phdr.p_vaddr;

        if (phdr_index == 1) {
            offset += phdrs_offset;
            vaddr += phdrs_offset;
        }

        for (self.sections.items(.shdr)[start..end]) |*shdr| {
            offset = mem.alignForwardGeneric(u64, offset, shdr.sh_addralign);
            vaddr = mem.alignForwardGeneric(u64, vaddr, shdr.sh_addralign);

            shdr.sh_offset = offset;
            shdr.sh_addr = vaddr;

            if (shdr.sh_type != elf.SHT_NOBITS) {
                offset += shdr.sh_size;
            }
            vaddr += shdr.sh_size;
        }
    }
}

fn allocateAtoms(self: *Elf) void {
    const slice = self.sections.slice();
    for (slice.items(.shdr), 0..) |shdr, i| {
        var atom_index = slice.items(.first_atom)[i] orelse continue;

        while (true) {
            const atom = self.getAtom(atom_index).?;
            assert(atom.is_alive);
            atom.value += shdr.sh_addr;

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }
    }
}

fn allocateLocals(self: *Elf) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.locals.items) |*symbol| {
            const atom = symbol.getAtom(self) orelse continue;
            if (!atom.is_alive) continue;
            symbol.value += atom.value;
            symbol.shndx = atom.out_shndx;
        }
    }
}

fn allocateGlobals(self: *Elf) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.globals.items) |global_index| {
            const global = self.getGlobal(global_index);
            const atom = global.getAtom(self) orelse continue;
            if (!atom.is_alive) continue;
            if (global.getFile(self).?.object.index != index) continue;
            global.value += atom.value;
            global.shndx = atom.out_shndx;
        }
    }
}

fn allocateSyntheticSymbols(self: *Elf) void {
    if (self.dynamic_index) |index| {
        if (self.got_sect_index) |got_index| {
            const shdr = self.sections.items(.shdr)[got_index];
            self.getGlobal(index).value = shdr.sh_addr;
        }
    }
    if (self.init_array_start_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.init_array_end_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.fini_array_start_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.fini_array_end_index) |index| {
        const global = self.getGlobal(index);
        if (self.text_sect_index) |text_index| {
            global.shndx = text_index;
        }
        if (self.entry_index) |entry_index| {
            global.value = self.getGlobal(entry_index).value;
        }
    }
    if (self.got_index) |index| {
        if (self.got_sect_index) |sect_index| {
            const shdr = self.sections.items(.shdr)[sect_index];
            self.getGlobal(index).value = shdr.sh_addr;
        }
    }
}

const ParseLibsCtx = struct {
    search_dirs: []const []const u8,
    libs: *std.StringArrayHashMap(Zld.SystemLib),
};

fn parsePositional(self: *Elf, arena: Allocator, pos: Zld.LinkObject, ctx: ParseLibsCtx) !void {
    const full_path = full_path: {
        var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
        const path = std.fs.realpath(pos.path, &buffer) catch |err| switch (err) {
            error.FileNotFound => return self.base.fatal("file not found '{s}'", .{pos.path}),
            else => |e| return e,
        };
        break :full_path try arena.dupe(u8, path);
    };

    log.debug("parsing input file path '{s}'", .{full_path});

    if (try self.parseObject(arena, full_path)) return;
    if (try self.parseArchive(arena, full_path)) return;
    if (try self.parseShared(arena, full_path, .{})) return;
    if (try self.parseLdScript(arena, full_path, .{}, ctx)) return;

    self.base.fatal("unknown filetype for positional input file: '{s}'", .{pos.path});
}

fn parseLib(
    self: *Elf,
    arena: Allocator,
    lib_name: []const u8,
    lib_info: Zld.SystemLib,
    ctx: ParseLibsCtx,
) anyerror!void {
    const full_path = (try resolveLib(arena, ctx.search_dirs, lib_name, lib_info)) orelse
        return self.base.fatal("{s}: library not found", .{lib_name});
    const gop = try ctx.libs.getOrPut(full_path);
    if (gop.found_existing) {
        // TODO should we check for differing AS_NEEDED directives and modify parsed DSO?
        return;
    }
    gop.value_ptr.* = lib_info;

    log.debug("parsing lib path '{s}'", .{full_path});

    if (try self.parseArchive(arena, full_path)) return;
    if (try self.parseShared(arena, full_path, lib_info)) return;
    if (try self.parseLdScript(arena, full_path, lib_info, ctx)) return;

    self.base.fatal("unknown filetype for a library: '{s}'", .{full_path});
}

fn parseObject(self: *Elf, arena: Allocator, path: []const u8) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const header = try file.reader().readStruct(elf.Elf64_Ehdr);
    try file.seekTo(0);

    if (!Object.isValidHeader(&header)) return false;
    self.validateOrSetCpuArch(path, header.e_machine.toTargetCpuArch().?);

    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const index = @intCast(u32, try self.files.addOne(gpa));
    self.files.set(index, .{ .object = .{
        .name = path,
        .data = data,
        .index = index,
    } });
    const object = &self.files.items(.data)[index].object;
    try object.parse(self);
    try self.objects.append(gpa, index);

    return true;
}

fn parseArchive(self: *Elf, arena: Allocator, path: []const u8) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const magic = try file.reader().readBytesNoEof(Archive.SARMAG);
    try file.seekTo(0);

    if (!Archive.isValidMagic(&magic)) return false;

    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));
    var archive = Archive{ .name = path, .data = data };
    defer archive.deinit(gpa);
    try archive.parse(self);

    var it = archive.offsets.keyIterator();
    while (it.next()) |offset| {
        var extracted = try archive.getObject(arena, offset.*, self);
        const index = @intCast(File.Index, try self.files.addOne(gpa));
        extracted.index = index;
        self.files.set(index, .{ .object = extracted });
        const object = &self.files.items(.data)[index].object;
        try object.parse(self);
        try self.objects.append(gpa, index);
    }

    return true;
}

fn parseShared(self: *Elf, arena: Allocator, path: []const u8, opts: Zld.SystemLib) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();

    const header = try file.reader().readStruct(elf.Elf64_Ehdr);
    try file.seekTo(0);

    if (!SharedObject.isValidHeader(&header)) return false;
    self.validateOrSetCpuArch(path, header.e_machine.toTargetCpuArch().?);

    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const index = @intCast(File.Index, try self.files.addOne(gpa));
    self.files.set(index, .{ .shared = .{
        .name = path,
        .data = data,
        .index = index,
        .needed = opts.needed,
        .alive = !opts.needed,
    } });
    const dso = &self.files.items(.data)[index].shared;
    try dso.parse(self);
    try self.shared_objects.append(gpa, index);

    return true;
}

fn parseLdScript(self: *Elf, arena: Allocator, path: []const u8, opts: Zld.SystemLib, ctx: ParseLibsCtx) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(gpa, std.math.maxInt(u32));
    defer gpa.free(data);

    var script = LdScript{};
    defer script.deinit(gpa);
    script.parse(data, self) catch |err| switch (err) {
        error.InvalidScript => return false,
        else => |e| return e,
    };

    if (script.cpu_arch) |cpu_arch| {
        self.validateOrSetCpuArch(path, cpu_arch);
    }

    for (script.libs.keys(), script.libs.values()) |s_name, s_opts| {
        const actual_name = if (mem.startsWith(u8, s_name, "-l")) blk: {
            // I cannot believe we are forced to check this at this stage...
            break :blk mem.trimLeft(u8, s_name["-l".len..], " ");
        } else s_name;
        const static = opts.static or s_opts.static;
        const needed = opts.needed or s_opts.needed;
        try self.parseLib(arena, actual_name, .{
            .static = static,
            .needed = needed,
        }, ctx);
    }

    return true;
}

fn validateOrSetCpuArch(self: *Elf, name: []const u8, cpu_arch: std.Target.Cpu.Arch) void {
    const self_cpu_arch = self.options.cpu_arch orelse blk: {
        self.options.cpu_arch = cpu_arch;
        break :blk self.options.cpu_arch.?;
    };
    if (self_cpu_arch != cpu_arch) {
        self.base.fatal("{s}: invalid architecture '{s}', expected '{s}'", .{
            name,
            @tagName(cpu_arch.toElfMachine()),
            @tagName(self_cpu_arch.toElfMachine()),
        });
    }
}

/// When resolving symbols, we approach the problem similarly to `mold`.
/// 1. Resolve symbols across all objects (including those preemptively extracted archives).
/// 2. Resolve symbols across all shared objects.
/// 3. Mark live objects (see `Elf.markLive`)
/// 4. Reset state of all resolved globals since we will redo this bit on the pruned set.
/// 5. Remove references to dead objects/shared objects
/// 6. Re-run symbol resolution on pruned objects and shared objects sets.
fn resolveSymbols(self: *Elf) !void {
    // Resolve symbols on the set of all objects and shared objects (even if some are unneeded).
    for (self.objects.items) |index| self.getFile(index).?.deref().resolveSymbols(self);
    for (self.shared_objects.items) |index| self.getFile(index).?.deref().resolveSymbols(self);

    // Mark live objects.
    self.markLive();

    // Reset state of all globals after marking live objects.
    for (self.objects.items) |index| self.getFile(index).?.deref().resetGlobals(self);
    for (self.shared_objects.items) |index| self.getFile(index).?.deref().resetGlobals(self);

    // Prune dead objects and shared objects.
    var i: usize = 0;
    while (i < self.objects.items.len) {
        const index = self.objects.items[i];
        if (!self.getFile(index).?.deref().isAlive()) {
            _ = self.objects.swapRemove(i);
        } else i += 1;
    }

    i = 0;
    while (i < self.shared_objects.items.len) {
        const index = self.shared_objects.items[i];
        if (!self.getFile(index).?.deref().isAlive()) {
            _ = self.shared_objects.swapRemove(i);
        } else i += 1;
    }

    // Re-resolve the symbols.
    for (self.objects.items) |index| self.getFile(index).?.deref().resolveSymbols(self);
    for (self.shared_objects.items) |index| self.getFile(index).?.deref().resolveSymbols(self);
}

/// Traverses all objects and shared objects marking any object referenced by
/// a live object/shared object as alive itself.
/// This routine will prune unneeded objects extracted from archives and
/// unneeded shared objects.
fn markLive(self: *Elf) void {
    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (file.deref().isAlive()) file.markLive(self);
    }
    for (self.shared_objects.items) |index| {
        const file = self.getFile(index).?;
        if (file.deref().isAlive()) file.markLive(self);
    }
}

fn markImportsAndExports(self: *Elf) !void {
    for (self.shared_objects.items) |index| {
        for (self.getFile(index).?.shared.globals.items) |global_index| {
            const global = self.getGlobal(global_index);
            if (global.getFile(self)) |file| {
                if (file != .shared) global.@"export" = true;
            }
        }
    }

    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.globals.items) |global_index| {
            const global = self.getGlobal(global_index);
            if (global.getFile(self)) |file| {
                if (file == .shared and !global.isAbs(self)) {
                    global.import = true;
                    continue;
                }

                if (file.deref().getIndex() == index) global.@"export" = true;
            }
        }
    }
}

fn resolveSyntheticSymbols(self: *Elf) !void {
    const internal_index = self.internal_object_index orelse return;
    const internal = self.getFile(internal_index).?.internal;
    self.dynamic_index = try internal.addSyntheticGlobal("_DYNAMIC", self);
    self.init_array_start_index = try internal.addSyntheticGlobal("__init_array_start", self);
    self.init_array_end_index = try internal.addSyntheticGlobal("__init_array_end", self);
    self.fini_array_start_index = try internal.addSyntheticGlobal("__fini_array_start", self);
    self.fini_array_end_index = try internal.addSyntheticGlobal("__fini_array_end", self);
    self.got_index = try internal.addSyntheticGlobal("_GLOBAL_OFFSET_TABLE_", self);
    internal.resolveSymbols(self);
}

fn checkDuplicates(self: *Elf) void {
    for (self.objects.items) |index| self.getFile(index).?.object.checkDuplicates(self);
}

fn checkUndefined(self: *Elf) void {
    for (self.objects.items) |index| self.getFile(index).?.object.checkUndefined(self);
}

fn claimUnresolved(self: *Elf) void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        const first_global = object.first_global orelse return;
        for (object.globals.items, 0..) |global_index, i| {
            const sym_idx = @intCast(u32, first_global + i);
            const sym = object.symtab[sym_idx];
            if (sym.st_shndx != elf.SHN_UNDEF) continue;

            const global = self.getGlobal(global_index);
            if (global.getFile(self)) |_| {
                if (global.getSourceSymbol(self).st_shndx != elf.SHN_UNDEF) continue;
            }

            global.* = .{
                .value = 0,
                .name = global.name,
                .atom = 0,
                .sym_idx = sym_idx,
                .file = object.index,
            };
        }
    }
}

fn scanRelocs(self: *Elf) !void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.is_alive) continue;
            try atom.scanRelocs(self);
        }
    }
}

fn setSymtab(self: *Elf) !void {
    const symtab_sect_index = self.symtab_sect_index orelse return;
    const gpa = self.base.allocator;

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.locals.items) |sym| {
            if (sym.getAtom(self)) |atom| {
                if (!atom.is_alive) continue;
            }
            const s_sym = sym.getSourceSymbol(self);
            switch (s_sym.st_type()) {
                elf.STT_SECTION, elf.STT_NOTYPE => continue,
                else => {},
            }
            switch (@intToEnum(elf.STV, s_sym.st_other)) {
                .INTERNAL, .HIDDEN => continue,
                else => {},
            }
            const name = try self.strtab.insert(gpa, sym.getName(self));
            try self.symtab.append(gpa, .{
                .st_name = name,
                .st_info = s_sym.st_info,
                .st_other = s_sym.st_other,
                .st_shndx = sym.shndx,
                .st_value = sym.value,
                .st_size = 0,
            });
        }
    }

    // Denote start of globals.
    {
        const shdr = &self.sections.items(.shdr)[symtab_sect_index];
        shdr.sh_info = @intCast(u32, self.symtab.items.len);
    }

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.globals.items) |global_index| {
            const global = self.getGlobal(global_index);
            if (global.getAtom(self)) |atom| {
                if (!atom.is_alive) continue;
            }
            const sym = global.getSourceSymbol(self);
            switch (@intToEnum(elf.STV, sym.st_other)) {
                .INTERNAL, .HIDDEN => continue,
                else => {},
            }
            const name = try self.strtab.insert(gpa, global.getName(self));
            try self.symtab.append(gpa, .{
                .st_name = name,
                .st_info = sym.st_info,
                .st_other = sym.st_other,
                .st_shndx = global.shndx,
                .st_value = global.value,
                .st_size = 0,
            });
        }
    }

    // Set the section sizes
    {
        const shdr = &self.sections.items(.shdr)[symtab_sect_index];
        shdr.sh_size = self.symtab.items.len * @sizeOf(elf.Elf64_Sym);
    }
    {
        const shdr = &self.sections.items(.shdr)[self.strtab_sect_index.?];
        shdr.sh_size = self.strtab.buffer.items.len;
    }
}

fn setShstrtab(self: *Elf) void {
    const shdr = &self.sections.items(.shdr)[self.shstrtab_sect_index.?];
    shdr.sh_size = self.shstrtab.buffer.items.len;
}

fn setDynsymtab(self: *Elf) !void {
    const dynsymtab_sect_index = self.dynsymtab_sect_index orelse return;
    const gpa = self.base.allocator;

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.globals.items) |global_index| {
            const global = self.getGlobal(global_index);
            if (!global.import) continue;
            const sym = global.getSourceSymbol(self);
            const name = try self.dynstrtab.insert(gpa, global.getName(self));
            try self.dynsymtab.append(gpa, .{
                .st_name = name,
                .st_info = sym.st_info,
                .st_other = sym.st_other,
                .st_shndx = elf.SHN_UNDEF,
                .st_value = 0,
                .st_size = 0,
            });
        }
    }

    // Set the section sizes
    {
        const shdr = &self.sections.items(.shdr)[dynsymtab_sect_index];
        shdr.sh_size = self.dynsymtab.items.len * @sizeOf(elf.Elf64_Sym);
    }
    {
        const shdr = &self.sections.items(.shdr)[self.dynstrtab_sect_index.?];
        shdr.sh_size = self.dynstrtab.buffer.items.len;
    }
}

fn writeAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.first_atom), 0..) |first_atom, i| {
        var atom_index = first_atom orelse continue;
        const shndx = @intCast(u16, i);
        const shdr = slice.items(.shdr)[shndx];

        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        log.debug("writing atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        @memset(buffer, 0);

        var stream = std.io.fixedBufferStream(buffer);

        while (true) {
            const atom = self.getAtom(atom_index).?;
            const off = atom.value - shdr.sh_addr;
            log.debug("writing ATOM(%{d},'{s}') at offset 0x{x}", .{
                atom_index,
                atom.getName(self),
                shdr.sh_offset + off,
            });
            try stream.seekTo(off);
            try atom.resolveRelocs(self, stream.writer());

            if (atom.next) |next| {
                atom_index = next;
            } else break;
        }

        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }
}

fn writeSyntheticSections(self: *Elf) !void {
    const gpa = self.base.allocator;
    if (self.interp_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try gpa.alloc(u8, shdr.sh_size);
        defer gpa.free(buffer);
        const dylinker = self.options.dynamic_linker.?;
        @memcpy(buffer[0..dylinker.len], dylinker);
        buffer[dylinker.len] = 0;
        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }
    if (self.dynsymtab_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(mem.sliceAsBytes(self.dynsymtab.items), shdr.sh_offset);
    }
    if (self.dynstrtab_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(self.dynstrtab.buffer.items, shdr.sh_offset);
    }
    if (self.got_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.got_section.size());
        defer buffer.deinit();
        try self.got_section.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }
    if (self.symtab_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(mem.sliceAsBytes(self.symtab.items), shdr.sh_offset);
    }
    if (self.strtab_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(self.strtab.buffer.items, shdr.sh_offset);
    }
    if (self.shstrtab_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(self.shstrtab.buffer.items, shdr.sh_offset);
    }
}

fn writePhdrs(self: *Elf) !void {
    const phoff = @sizeOf(elf.Elf64_Ehdr);
    const phdrs_size = self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    log.debug("writing program headers from 0x{x} to 0x{x}", .{ phoff, phoff + phdrs_size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.phdrs.items), phoff);
}

fn writeShdrs(self: *Elf) !void {
    const size = self.sections.items(.shdr).len * @sizeOf(elf.Elf64_Shdr);
    log.debug("writing section headers from 0x{x} to 0x{x}", .{ self.shoff, self.shoff + size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.sections.items(.shdr)), self.shoff);
}

fn writeHeader(self: *Elf) !void {
    var header = elf.Elf64_Ehdr{
        .e_ident = undefined,
        .e_type = switch (self.options.output_mode) {
            .exe => elf.ET.EXEC,
            .lib => elf.ET.DYN,
        },
        .e_machine = self.options.cpu_arch.?.toElfMachine(),
        .e_version = 1,
        .e_entry = if (self.entry_index) |index| self.getGlobal(index).value else 0,
        .e_phoff = @sizeOf(elf.Elf64_Ehdr),
        .e_shoff = self.shoff,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @intCast(u16, self.segments.slice().len),
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @intCast(u16, self.sections.items(.shdr).len),
        .e_shstrndx = self.shstrtab_sect_index.?,
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
    try self.base.file.pwriteAll(mem.asBytes(&header), 0);
}

pub const AddSectionOpts = struct {
    name: [:0]const u8,
    type: u32 = elf.SHT_NULL,
    flags: u64 = 0,
    link: u32 = 0,
    info: u32 = 0,
    addralign: u64 = 0,
    entsize: u64 = 0,
};

pub fn addSection(self: *Elf, opts: AddSectionOpts) !u16 {
    const gpa = self.base.allocator;
    const index = @intCast(u16, try self.sections.addOne(gpa));
    self.sections.set(index, .{
        .shdr = .{
            .sh_name = try self.shstrtab.insert(gpa, opts.name),
            .sh_type = opts.type,
            .sh_flags = opts.flags,
            .sh_addr = 0,
            .sh_offset = 0,
            .sh_size = 0,
            .sh_link = 0,
            .sh_info = opts.info,
            .sh_addralign = opts.addralign,
            .sh_entsize = opts.entsize,
        },
        .first_atom = null,
        .last_atom = null,
    });
    return index;
}

pub fn getSectionByName(self: *Elf, name: [:0]const u8) ?u16 {
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const this_name = self.shstrtab.getAssumeExists(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @intCast(u16, i);
    } else return null;
}

fn addSegment(self: *Elf, opts: struct {
    type: u32 = 0,
    flags: u32 = 0,
    @"align": u64 = 0,
    offset: u64 = 0,
    addr: u64 = 0,
    filesz: u64 = 0,
    memsz: u64 = 0,
}) !u16 {
    const index = @intCast(u16, self.phdrs.items.len);
    try self.phdrs.append(self.base.allocator, .{
        .p_type = opts.type,
        .p_flags = opts.flags,
        .p_offset = opts.offset,
        .p_vaddr = opts.addr,
        .p_paddr = opts.addr,
        .p_filesz = opts.filesz,
        .p_memsz = opts.memsz,
        .p_align = opts.@"align",
    });
    return index;
}

pub fn getSectionIndexes(self: *Elf, phdr_index: u16) struct { start: u16, end: u16 } {
    const start: u16 = for (self.sections.items(.phdr), 0..) |phdr, i| {
        if (phdr != null and phdr.? == phdr_index) break @intCast(u16, i);
    } else @intCast(u16, self.sections.slice().len);
    const end: u16 = for (self.sections.items(.phdr)[start..], 0..) |phdr, i| {
        if (phdr == null or phdr.? != phdr_index) break @intCast(u16, start + i);
    } else start;
    return .{ .start = start, .end = end };
}

pub fn getFile(self: *Elf, index: File.Index) ?FilePtr {
    const tag = self.files.items(.tags)[index];
    return switch (tag) {
        .null => null,
        .internal => .{ .internal = &self.files.items(.data)[index].internal },
        .object => .{ .object = &self.files.items(.data)[index].object },
        .shared => .{ .shared = &self.files.items(.data)[index].shared },
    };
}

fn getGotBaseAddress(self: *Elf) u64 {
    const shndx = self.got_sect_index orelse return 0;
    const shdr = self.sections.items(.shdr)[shndx];
    return shdr.sh_addr;
}

fn writeGotEntry(self: *Elf, entry: u32, writer: anytype) !void {
    if (self.got_sect_index == null) return;
    const sym = self.getGlobal(entry);
    try writer.writeIntLittle(u64, sym.value);
}

pub fn addAtom(self: *Elf) !Atom.Index {
    const index = @intCast(u32, self.atoms.items.len);
    const atom = try self.atoms.addOne(self.base.allocator);
    atom.* = .{};
    return index;
}

pub fn getAtom(self: Elf, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

const GetOrCreateGlobalResult = struct {
    found_existing: bool,
    index: u32,
};

pub fn getOrCreateGlobal(self: *Elf, name: [:0]const u8) !GetOrCreateGlobalResult {
    const gpa = self.base.allocator;
    const gop = try self.globals_table.getOrPut(gpa, name);
    if (!gop.found_existing) {
        const index = @intCast(u32, self.globals.items.len);
        const global = try self.globals.addOne(gpa);
        global.* = .{ .name = try self.string_intern.insert(gpa, name) };
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn getGlobal(self: *Elf, index: u32) *Symbol {
    assert(index < self.globals.items.len);
    return &self.globals.items[index];
}

fn maybeEql(comptime T: type, maybe: ?T, other: T) bool {
    const this = maybe orelse return false;
    return this == other;
}

fn fmtSections(self: *Elf) std.fmt.Formatter(formatSections) {
    return .{ .data = self };
}

fn formatSections(
    self: *Elf,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        try writer.print("sect({d}) : {s} : @{x} ({x}) : align({x}) : size({x})\n", .{
            i,                 self.shstrtab.getAssumeExists(shdr.sh_name), shdr.sh_offset, shdr.sh_addr,
            shdr.sh_addralign, shdr.sh_size,
        });
    }
}

fn fmtSegments(self: *Elf) std.fmt.Formatter(formatSegments) {
    return .{ .data = self };
}

fn formatSegments(
    self: *Elf,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.phdrs.items, 0..) |phdr, i| {
        const write = phdr.p_flags & elf.PF_W != 0;
        const read = phdr.p_flags & elf.PF_R != 0;
        const exec = phdr.p_flags & elf.PF_X != 0;
        var flags: [3]u8 = [_]u8{'_'} ** 3;
        if (exec) flags[0] = 'X';
        if (write) flags[1] = 'W';
        if (read) flags[2] = 'R';
        try writer.print("phdr({d}) : {s} : @{x} ({x}) : align({x}) : filesz({x}) : memsz({x})\n", .{
            i, flags, phdr.p_offset, phdr.p_vaddr, phdr.p_align, phdr.p_filesz, phdr.p_memsz,
        });
    }
}

fn dumpState(self: *Elf) std.fmt.Formatter(fmtDumpState) {
    return .{ .data = self };
}

fn fmtDumpState(
    self: *Elf,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        try writer.print("object({d}) : ", .{index});
        if (object.archive) |path| {
            try writer.print("{s}({s})", .{ path, object.name });
        } else try writer.print("{s}", .{object.name});
        if (!object.alive) try writer.writeAll(" : [*]\n");
        try writer.print("{}{}\n", .{ object.fmtAtoms(self), object.fmtSymtab(self) });
    }
    for (self.shared_objects.items) |index| {
        const shared = self.getFile(index).?.shared;
        try writer.print("shared({d}) : ", .{index});
        try writer.print("{s}", .{shared.name});
        if (!shared.alive) try writer.writeAll(" : [*]\n");
        try writer.print("{}\n", .{shared.fmtSymtab(self)});
    }
    if (self.internal_object_index) |index| {
        const internal = self.getFile(index).?.internal;
        try writer.print("internal({d}) : internal\n", .{index});
        try writer.print("{}\n", .{internal.fmtSymtab(self)});
    }
    try writer.writeAll("GOT\n");
    try writer.print("{}\n", .{self.got_section});
    try writer.writeAll("Output sections\n");
    try writer.print("{}\n", .{self.fmtSections()});
    try writer.writeAll("Output segments\n");
    try writer.print("{}\n", .{self.fmtSegments()});
}

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const gc = @import("Elf/gc.zig");
const log = std.log.scoped(.elf);
const state_log = std.log.scoped(.state);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @import("Elf/Archive.zig");
const Atom = @import("Elf/Atom.zig");
const Elf = @This();
const InternalObject = @import("Elf/InternalObject.zig");
const LdScript = @import("Elf/LdScript.zig");
const Object = @import("Elf/Object.zig");
pub const Options = @import("Elf/Options.zig");
const SharedObject = @import("Elf/SharedObject.zig");
const StringTable = @import("strtab.zig").StringTable;
const Symbol = @import("Elf/Symbol.zig");
const SyntheticSection = @import("synthetic_section.zig").SyntheticSection;
const ThreadPool = @import("ThreadPool.zig");
const Zld = @import("Zld.zig");
