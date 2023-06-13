base: Zld,
arena: std.heap.ArenaAllocator.State,
options: Options,
shoff: u64 = 0,

objects: std.ArrayListUnmanaged(File.Index) = .{},
shared_objects: std.ArrayListUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},

sections: std.MultiArrayList(Section) = .{},
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

tls_phdr_index: ?u16 = null,

text_sect_index: ?u16 = null,
eh_frame_hdr_sect_index: ?u16 = null,
eh_frame_sect_index: ?u16 = null,
plt_sect_index: ?u16 = null,
got_sect_index: ?u16 = null,
got_plt_sect_index: ?u16 = null,
plt_got_sect_index: ?u16 = null,
rela_dyn_sect_index: ?u16 = null,
rela_plt_sect_index: ?u16 = null,
copy_rel_sect_index: ?u16 = null,
symtab_sect_index: ?u16 = null,
strtab_sect_index: ?u16 = null,
shstrtab_sect_index: ?u16 = null,
interp_sect_index: ?u16 = null,
dynamic_sect_index: ?u16 = null,
dynsymtab_sect_index: ?u16 = null,
dynstrtab_sect_index: ?u16 = null,
hash_sect_index: ?u16 = null,
gnu_hash_sect_index: ?u16 = null,
versym_sect_index: ?u16 = null,
verneed_sect_index: ?u16 = null,

internal_object_index: ?u32 = null,
dynamic_index: ?u32 = null,
init_array_start_index: ?u32 = null,
init_array_end_index: ?u32 = null,
fini_array_start_index: ?u32 = null,
fini_array_end_index: ?u32 = null,
got_index: ?u32 = null,
plt_index: ?u32 = null,
dso_handle_index: ?u32 = null,

entry_index: ?u32 = null,

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
globals: std.AutoHashMapUnmanaged(u32, u32) = .{},
/// This table will be populated after `scanRelocs` has run.
/// Key is symbol index.
undefs: std.AutoHashMapUnmanaged(u32, std.ArrayListUnmanaged(Atom.Index)) = .{},

string_intern: StringTable(.string_intern) = .{},

shstrtab: StringTable(.shstrtab) = .{},
dynsym: DynsymSection = .{},
dynstrtab: StringTable(.dynstrtab) = .{},
versym: std.ArrayListUnmanaged(elf.Elf64_Versym) = .{},
verneed: VerneedSection = .{},

dynamic: DynamicSection = .{},
hash: HashSection = .{},
gnu_hash: GnuHashSection = .{},
got: GotSection = .{},
plt: PltSection = .{},
plt_got: PltGotSection = .{},
copy_rel: CopyRelSection = .{},
rela_dyn: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},
rela_plt: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

comdat_groups: std.ArrayListUnmanaged(ComdatGroup) = .{},
comdat_groups_owners: std.ArrayListUnmanaged(ComdatGroupOwner) = .{},
comdat_groups_table: std.AutoHashMapUnmanaged(u32, ComdatGroupOwner.Index) = .{},

needs_tlsld: bool = false,
default_sym_version: elf.Elf64_Versym,

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
        .default_sym_version = if (options.output_mode == .lib or options.export_dynamic)
            VER_NDX_GLOBAL
        else
            VER_NDX_LOCAL,
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    const gpa = self.base.allocator;
    self.string_intern.deinit(gpa);
    self.shstrtab.deinit(gpa);
    self.atoms.deinit(gpa);
    self.comdat_groups.deinit(gpa);
    self.comdat_groups_owners.deinit(gpa);
    self.comdat_groups_table.deinit(gpa);
    self.symbols.deinit(gpa);
    self.symbols_extra.deinit(gpa);
    self.globals.deinit(gpa);
    self.got.deinit(gpa);
    self.plt.deinit(gpa);
    self.plt_got.deinit(gpa);
    self.phdrs.deinit(gpa);
    for (self.sections.items(.atoms)) |*atoms| {
        atoms.deinit(gpa);
    }
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
    self.dynsym.deinit(gpa);
    self.dynstrtab.deinit(gpa);
    self.dynamic.deinit(gpa);
    self.hash.deinit(gpa);
    self.versym.deinit(gpa);
    self.verneed.deinit(gpa);
    self.copy_rel.deinit(gpa);
    self.rela_dyn.deinit(gpa);
    self.rela_plt.deinit(gpa);
    {
        var it = self.undefs.valueIterator();
        while (it.next()) |notes| {
            notes.deinit(gpa);
        }
        self.undefs.deinit(gpa);
    }
    self.arena.promote(gpa).deinit();
}

fn resolveFile(
    self: *Elf,
    arena: Allocator,
    obj: LinkObject,
    search_dirs: []const []const u8,
) !LinkObject {
    const full_path = full_path: {
        if (mem.startsWith(u8, obj.path, "-l")) {
            const path = obj.path["-l".len..];
            if (!obj.static) {
                const search_name = try std.fmt.allocPrint(arena, "lib{s}.so", .{path});
                if (try resolveFileInDir(arena, search_dirs, search_name)) |full_path| break :full_path full_path;
            }
            const search_name = try std.fmt.allocPrint(arena, "lib{s}.a", .{path});
            if (try resolveFileInDir(arena, search_dirs, search_name)) |full_path| break :full_path full_path;
            self.base.fatal("{s}: library not found", .{path});
            return error.ResolveFail;
        }

        const path = path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            const path = std.fs.realpath(obj.path, &buffer) catch |err| switch (err) {
                error.FileNotFound => {
                    if (try resolveFileInDir(arena, search_dirs, obj.path)) |path| break :path path;
                    self.base.fatal("file not found '{s}'", .{obj.path});
                    return error.ResolveFail;
                },
                else => |e| return e,
            };
            break :path try arena.dupe(u8, path);
        };
        break :full_path path;
    };
    return .{
        .path = full_path,
        .needed = obj.needed,
        .static = obj.static,
    };
}

fn resolveFileInDir(arena: Allocator, search_dirs: []const []const u8, search_name: []const u8) !?[]const u8 {
    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, search_name });
        if (checkFileExists(full_path)) return full_path;
    }
    return null;
}

fn checkFileExists(path: []const u8) bool {
    const tmp = fs.cwd().openFile(path, .{}) catch return false;
    defer tmp.close();
    return true;
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
    try self.shstrtab.buffer.append(gpa, 0);
    try self.dynstrtab.buffer.append(gpa, 0);
    // Append null section.
    _ = try self.addSection(.{ .name = "" });
    // Append null atom.
    try self.atoms.append(gpa, .{});
    // Append null symbols.
    try self.symbols_extra.append(gpa, 0);
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

    var positionals = std.ArrayList(LinkObject).init(arena);
    try self.unpackPositionals(&positionals);
    self.base.reportWarningsAndErrorsAndExit();

    for (positionals.items) |obj| {
        try self.parsePositional(arena, obj, search_dirs.items);
    }

    if (self.base.errors.items.len > 0) {
        self.base.fatal("library search paths:", .{});
        for (search_dirs.items) |dir| {
            self.base.fatal("  {s}", .{dir});
        }
    }
    self.base.reportWarningsAndErrorsAndExit();

    // Dedup DSOs
    {
        var seen_dsos = std.StringHashMap(void).init(gpa);
        defer seen_dsos.deinit();
        try seen_dsos.ensureTotalCapacity(@intCast(u32, self.shared_objects.items.len));

        var i: usize = 0;
        while (i < self.shared_objects.items.len) {
            const index = self.shared_objects.items[i];
            const shared = self.getFile(index).?.shared;
            const soname = shared.getSoname();
            const gop = seen_dsos.getOrPutAssumeCapacity(soname);
            if (gop.found_existing) {
                _ = self.shared_objects.orderedRemove(i);
            } else i += 1;
        }
    }

    {
        const index = @intCast(File.Index, try self.files.addOne(gpa));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object_index = index;
    }

    try self.resolveSymbols();
    self.markEhFrameAtomsDead();
    try self.convertCommonSymbols();
    try self.markImportsAndExports();

    // Set the entrypoint if found
    self.entry_index = blk: {
        if (self.options.output_mode != .exe) break :blk null;
        const entry_name = self.options.entry orelse "_start";
        break :blk self.getGlobalByName(entry_name);
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

    if (self.options.z_execstack_if_needed) {
        for (self.objects.items) |index| {
            if (self.getFile(index).?.object.needs_exec_stack) {
                self.options.z_execstack = true;
                break;
            }
        }
    }

    self.claimUnresolved();
    try self.scanRelocs();

    try self.initSections();
    try self.sortSections();
    try self.addAtomsToSections();
    try self.sortInitFini();
    try self.setDynamic();
    self.setDynsym();
    try self.setHashes();
    try self.setVerSymtab();
    try self.calcSectionSizes();

    try self.allocateSections();
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

fn sortInitFini(self: *Elf) !void {
    const gpa = self.base.allocator;

    const Entry = struct {
        priority: u16,
        atom_index: Atom.Index,

        pub fn lessThan(ctx: void, lhs: @This(), rhs: @This()) bool {
            _ = ctx;
            return lhs.priority < rhs.priority;
        }
    };

    for (self.sections.items(.shdr), 0..) |shdr, shndx| switch (shdr.sh_type) {
        elf.SHT_INIT_ARRAY, elf.SHT_FINI_ARRAY, elf.SHT_PREINIT_ARRAY => {
            const atoms = &self.sections.items(.atoms)[shndx];
            if (atoms.items.len == 0) continue;

            var entries = std.ArrayList(Entry).init(gpa);
            try entries.ensureTotalCapacityPrecise(atoms.items.len);
            defer entries.deinit();

            for (atoms.items) |atom_index| {
                const atom = self.getAtom(atom_index).?;
                const name = atom.getName(self);
                var it = mem.splitBackwards(u8, name, ".");
                const priority = std.fmt.parseUnsigned(u16, it.first(), 10) catch std.math.maxInt(u16);
                entries.appendAssumeCapacity(.{ .priority = priority, .atom_index = atom_index });
            }

            mem.sort(Entry, entries.items, {}, Entry.lessThan);

            atoms.clearRetainingCapacity();
            for (entries.items) |entry| {
                atoms.appendAssumeCapacity(entry.atom_index);
            }
        },
        else => {},
    };
}

fn initSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.alive) continue;
            try atom.initOutputSection(self);
        }
    }

    const needs_eh_frame = for (self.objects.items) |index| {
        if (self.getFile(index).?.object.cies.items.len > 0) break true;
    } else false;
    if (needs_eh_frame) {
        self.eh_frame_sect_index = try self.addSection(.{
            .name = ".eh_frame",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC,
            .addralign = @alignOf(u64),
        });

        if (self.options.eh_frame_hdr) {
            self.eh_frame_hdr_sect_index = try self.addSection(.{
                .name = ".eh_frame_hdr",
                .type = elf.SHT_PROGBITS,
                .flags = elf.SHF_ALLOC,
                .size = eh_frame_hdr_header_size,
                .addralign = @alignOf(u32),
            });
        }
    }

    if (self.got.symbols.items.len > 0) {
        self.got_sect_index = try self.addSection(.{
            .name = ".got",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .addralign = @alignOf(u64),
        });
    }

    const needs_rela_dyn = blk: {
        if (self.got.needs_rela or self.copy_rel.symbols.items.len > 0) break :blk true;
        for (self.objects.items) |index| {
            if (self.getFile(index).?.object.num_dynrelocs > 0) break :blk true;
        }
        break :blk false;
    };
    if (needs_rela_dyn) {
        self.rela_dyn_sect_index = try self.addSection(.{
            .name = ".rela.dyn",
            .type = elf.SHT_RELA,
            .flags = elf.SHF_ALLOC,
            .addralign = @alignOf(elf.Elf64_Rela),
            .entsize = @sizeOf(elf.Elf64_Rela),
        });
    }

    if (self.plt.symbols.items.len > 0) {
        self.plt_sect_index = try self.addSection(.{
            .name = ".plt",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR,
            .addralign = 16,
        });
        self.got_plt_sect_index = try self.addSection(.{
            .name = ".got.plt",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .addralign = @alignOf(u64),
        });
        self.rela_plt_sect_index = try self.addSection(.{
            .name = ".rela.plt",
            .type = elf.SHT_RELA,
            .flags = elf.SHF_ALLOC,
            .addralign = @alignOf(elf.Elf64_Rela),
            .entsize = @sizeOf(elf.Elf64_Rela),
        });
    }

    if (self.plt_got.symbols.items.len > 0) {
        self.plt_got_sect_index = try self.addSection(.{
            .name = ".plt.got",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR,
            .addralign = 16,
        });
    }

    if (self.copy_rel.symbols.items.len > 0) {
        self.copy_rel_sect_index = try self.addSection(.{
            .name = ".copyrel",
            .type = elf.SHT_NOBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
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
        self.dynamic_sect_index = try self.addSection(.{
            .name = ".dynamic",
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .type = elf.SHT_DYNAMIC,
            .entsize = @sizeOf(elf.Elf64_Dyn),
            .addralign = @alignOf(elf.Elf64_Dyn),
        });
        self.dynsymtab_sect_index = try self.addSection(.{
            .name = ".dynsym",
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_DYNSYM,
            .addralign = @alignOf(elf.Elf64_Sym),
            .entsize = @sizeOf(elf.Elf64_Sym),
        });
        self.hash_sect_index = try self.addSection(.{
            .name = ".hash",
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_HASH,
            .addralign = 4,
            .entsize = 4,
        });
        self.gnu_hash_sect_index = try self.addSection(.{
            .name = ".gnu.hash",
            .flags = elf.SHF_ALLOC,
            .type = SHT_GNU_HASH,
            .addralign = 8,
        });

        const needs_versions = for (self.shared_objects.items) |index| {
            if (self.getFile(index).?.shared.versym_sect_index != null) break true;
        } else false;
        if (needs_versions) {
            self.versym_sect_index = try self.addSection(.{
                .name = ".gnu.version",
                .flags = elf.SHF_ALLOC,
                .type = SHT_GNU_versym,
                .addralign = @alignOf(elf.Elf64_Versym),
                .entsize = @sizeOf(elf.Elf64_Versym),
            });
            self.verneed_sect_index = try self.addSection(.{
                .name = ".gnu.version_r",
                .flags = elf.SHF_ALLOC,
                .type = SHT_GNU_verneed,
                .addralign = @alignOf(elf.Elf64_Verneed),
            });
        }
    }
}

fn addAtomsToSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_shndx];
            try atoms.append(self.base.allocator, atom_index);
        }
    }
}

fn calcSectionSizes(self: *Elf) !void {
    for (self.sections.items(.shdr), self.sections.items(.atoms)) |*shdr, atoms| {
        if (atoms.items.len == 0) continue;

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            const alignment = try math.powi(u64, 2, atom.alignment);
            const offset = mem.alignForwardGeneric(u64, shdr.sh_size, alignment);
            const padding = offset - shdr.sh_size;
            atom.value = offset;
            shdr.sh_size += padding + atom.size;
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
        }
    }

    if (self.eh_frame_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = eh_frame.calcEhFrameSize(self);
        shdr.sh_addralign = @alignOf(u64);
    }

    if (self.eh_frame_hdr_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = eh_frame.calcEhFrameHdrSize(self);
        shdr.sh_addralign = @alignOf(u32);
    }

    if (self.got_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.got.size();
        shdr.sh_addralign = @alignOf(u64);
    }

    if (self.plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.plt.sizePlt();
        shdr.sh_addralign = 16;
    }

    if (self.got_plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.plt.sizeGotPlt();
        shdr.sh_addralign = @alignOf(u64);
    }

    if (self.plt_got_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.plt_got.size();
        shdr.sh_addralign = 16;
    }

    if (self.rela_dyn_sect_index) |shndx| {
        const shdr = &self.sections.items(.shdr)[shndx];
        var num = self.got.numRela(self) + self.copy_rel.numRela();
        for (self.objects.items) |index| {
            num += self.getFile(index).?.object.num_dynrelocs;
        }
        shdr.sh_size = num * @sizeOf(elf.Elf64_Rela);
    }

    if (self.rela_plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.plt.numRela() * @sizeOf(elf.Elf64_Rela);
    }

    if (self.copy_rel_sect_index) |index| {
        try self.copy_rel.calcSectionSize(index, self);
    }

    if (self.interp_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        const size = self.options.dynamic_linker.?.len + 1;
        shdr.sh_size = size;
        shdr.sh_addralign = 1;
    }

    if (self.hash_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.hash.size();
    }

    if (self.gnu_hash_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.gnu_hash.size();
    }

    if (self.dynamic_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.dynamic.size(self);
    }

    if (self.dynsymtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.dynsym.size();
    }

    if (self.dynstrtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.dynstrtab.buffer.items.len;
    }

    if (self.versym_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.versym.items.len * @sizeOf(elf.Elf64_Versym);
    }

    if (self.verneed_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.verneed.size();
    }

    if (!self.options.strip_all) {
        try self.calcSymtabSize();
    }

    if (self.shstrtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.shstrtab.buffer.items.len;
    }
}

fn calcSymtabSize(self: *Elf) !void {
    if (self.options.strip_all) return;

    var sizes = SymtabSize{};

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        try object.calcSymtabSize(self);
        sizes.nlocals += object.output_symtab_size.nlocals;
        sizes.nglobals += object.output_symtab_size.nglobals;
        sizes.strsize += object.output_symtab_size.strsize;
    }

    for (self.shared_objects.items) |index| {
        const shared = self.getFile(index).?.shared;
        try shared.calcSymtabSize(self);
        sizes.nglobals += shared.output_symtab_size.nglobals;
        sizes.strsize += shared.output_symtab_size.strsize;
    }

    if (self.internal_object_index) |index| {
        const internal = self.getFile(index).?.internal;
        try internal.calcSymtabSize(self);
        sizes.nlocals += internal.output_symtab_size.nlocals;
        sizes.strsize += internal.output_symtab_size.strsize;
    }

    if (self.got_sect_index) |_| {
        try self.got.calcSymtabSize(self);
        sizes.nlocals += self.got.output_symtab_size.nlocals;
        sizes.strsize += self.got.output_symtab_size.strsize;
    }

    if (self.plt_sect_index) |_| {
        try self.plt.calcSymtabSize(self);
        sizes.nlocals += self.plt.output_symtab_size.nlocals;
        sizes.strsize += self.plt.output_symtab_size.strsize;
    }

    if (self.plt_got_sect_index) |_| {
        try self.plt_got.calcSymtabSize(self);
        sizes.nlocals += self.plt_got.output_symtab_size.nlocals;
        sizes.strsize += self.plt_got.output_symtab_size.strsize;
    }

    {
        const shdr = &self.sections.items(.shdr)[self.symtab_sect_index.?];
        shdr.sh_size = (sizes.nlocals + 1 + sizes.nglobals) * @sizeOf(elf.Elf64_Sym);
        shdr.sh_info = sizes.nlocals + 1;
    }
    {
        const shdr = &self.sections.items(.shdr)[self.strtab_sect_index.?];
        shdr.sh_size = sizes.strsize + 1;
    }
}

fn writeSymtab(self: *Elf) !void {
    if (self.options.strip_all) return;

    const gpa = self.base.allocator;
    const symtab_shdr = self.sections.items(.shdr)[self.symtab_sect_index.?];
    const strtab_shdr = self.sections.items(.shdr)[self.strtab_sect_index.?];

    var symtab = try gpa.alloc(elf.Elf64_Sym, @divExact(symtab_shdr.sh_size, @sizeOf(elf.Elf64_Sym)));
    defer gpa.free(symtab);
    symtab[0] = null_sym;

    var strtab = StringTable(.strtab){};
    defer strtab.deinit(gpa);
    try strtab.buffer.append(gpa, 0);

    var ctx = WriteSymtabCtx{
        .ilocal = 1,
        .iglobal = symtab_shdr.sh_info,
        .symtab = symtab,
        .strtab = &strtab,
    };

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        try object.writeSymtab(self, ctx);
        ctx.ilocal += object.output_symtab_size.nlocals;
        ctx.iglobal += object.output_symtab_size.nglobals;
    }

    if (self.internal_object_index) |index| {
        const internal = self.getFile(index).?.internal;
        try internal.writeSymtab(self, ctx);
        ctx.ilocal += internal.output_symtab_size.nlocals;
    }

    if (self.got_sect_index) |_| {
        try self.got.writeSymtab(self, ctx);
        ctx.ilocal += self.got.output_symtab_size.nlocals;
    }

    if (self.plt_sect_index) |_| {
        try self.plt.writeSymtab(self, ctx);
        ctx.ilocal += self.plt.output_symtab_size.nlocals;
    }

    if (self.plt_got_sect_index) |_| {
        try self.plt_got.writeSymtab(self, ctx);
        ctx.ilocal += self.plt_got.output_symtab_size.nlocals;
    }

    for (self.shared_objects.items) |index| {
        const shared = self.getFile(index).?.shared;
        try shared.writeSymtab(self, ctx);
        ctx.iglobal += shared.output_symtab_size.nglobals;
    }

    const strtab_padding = strtab_shdr.sh_size - strtab.buffer.items.len;
    try strtab.buffer.writer(gpa).writeByteNTimes(0, strtab_padding);

    try self.base.file.pwriteAll(mem.sliceAsBytes(symtab), symtab_shdr.sh_offset);
    try self.base.file.pwriteAll(strtab.buffer.items, strtab_shdr.sh_offset);
}

fn initPhdrs(self: *Elf) !void {
    // Add PHDR phdr
    const phdr_index = try self.addPhdr(.{
        .type = elf.PT_PHDR,
        .flags = elf.PF_R,
        .@"align" = @alignOf(elf.Elf64_Phdr),
        .addr = default_base_addr + @sizeOf(elf.Elf64_Ehdr),
        .offset = @sizeOf(elf.Elf64_Ehdr),
    });

    // Add INTERP phdr if required
    if (self.interp_sect_index) |index| {
        const shdr = self.sections.items(.shdr)[index];
        _ = try self.addPhdr(.{
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
    const slice = self.sections.slice();
    {
        var last_phdr: ?u16 = null;
        var shndx: usize = 0;
        while (shndx < slice.len) {
            const shdr = &slice.items(.shdr)[shndx];
            if (!shdrIsAlloc(shdr) or shdrIsTbss(shdr)) {
                shndx += 1;
                continue;
            }
            last_phdr = try self.addPhdr(.{
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
                const next = &slice.items(.shdr)[shndx];
                if (shdrIsTbss(next)) continue;
                if (p_flags == shdrToPhdrFlags(next.sh_flags)) {
                    if (shdrIsBss(next) or next.sh_offset - shdr.sh_offset == next.sh_addr - shdr.sh_addr) {
                        try self.addShdrToPhdr(last_phdr.?, next);
                        continue;
                    }
                }
                break;
            }
        }
    }

    // Add TLS phdr
    {
        var shndx: usize = 0;
        outer: while (shndx < slice.len) {
            const shdr = &slice.items(.shdr)[shndx];
            if (!shdrIsTls(shdr)) {
                shndx += 1;
                continue;
            }
            self.tls_phdr_index = try self.addPhdr(.{
                .type = elf.PT_TLS,
                .flags = elf.PF_R,
                .@"align" = shdr.sh_addralign,
                .offset = shdr.sh_offset,
                .addr = shdr.sh_addr,
            });
            try self.addShdrToPhdr(self.tls_phdr_index.?, shdr);
            shndx += 1;

            while (shndx < slice.len) : (shndx += 1) {
                const next = &slice.items(.shdr)[shndx];
                if (!shdrIsTls(next)) continue :outer;
                try self.addShdrToPhdr(self.tls_phdr_index.?, next);
            }
        }
    }

    // Add DYNAMIC phdr
    if (self.dynamic_sect_index) |index| {
        const shdr = self.sections.items(.shdr)[index];
        _ = try self.addPhdr(.{
            .type = elf.PT_DYNAMIC,
            .flags = elf.PF_R | elf.PF_W,
            .@"align" = shdr.sh_addralign,
            .offset = shdr.sh_offset,
            .addr = shdr.sh_addr,
            .memsz = shdr.sh_size,
            .filesz = shdr.sh_size,
        });
    }

    // Add PT_GNU_EH_FRAME phdr if required.
    if (self.eh_frame_hdr_sect_index) |index| {
        const shdr = self.sections.items(.shdr)[index];
        _ = try self.addPhdr(.{
            .type = elf.PT_GNU_EH_FRAME,
            .flags = elf.PF_R,
            .@"align" = shdr.sh_addralign,
            .offset = shdr.sh_offset,
            .addr = shdr.sh_addr,
            .memsz = shdr.sh_size,
            .filesz = shdr.sh_size,
        });
    }

    // Add PT_GNU_STACK phdr that controls some stack attributes that apparently may or may not
    // be respected by the OS.
    _ = try self.addPhdr(.{
        .type = elf.PT_GNU_STACK,
        .flags = if (self.options.z_execstack) elf.PF_W | elf.PF_R | elf.PF_X else elf.PF_W | elf.PF_R,
        .memsz = self.options.z_stack_size orelse 0,
        .@"align" = 1,
    });

    // Backpatch size of the PHDR phdr
    {
        const phdr = &self.phdrs.items[phdr_index];
        const size = @sizeOf(elf.Elf64_Phdr) * self.phdrs.items.len;
        phdr.p_filesz = size;
        phdr.p_memsz = size;
    }
}

fn addShdrToPhdr(self: *Elf, phdr_index: u16, shdr: *const elf.Elf64_Shdr) !void {
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

inline fn shdrIsAlloc(shdr: *const elf.Elf64_Shdr) bool {
    return shdr.sh_flags & elf.SHF_ALLOC != 0;
}

inline fn shdrIsBss(shdr: *const elf.Elf64_Shdr) bool {
    return shdr.sh_type == elf.SHT_NOBITS and !shdrIsTls(shdr);
}

inline fn shdrIsTbss(shdr: *const elf.Elf64_Shdr) bool {
    return shdr.sh_type == elf.SHT_NOBITS and shdrIsTls(shdr);
}

pub inline fn shdrIsTls(shdr: *const elf.Elf64_Shdr) bool {
    return shdr.sh_flags & elf.SHF_TLS != 0;
}

fn allocateSectionsInMemory(self: *Elf, base_offset: u64) !void {
    const Align = struct {
        tls_start_align: u64 = 1,
        first_tls_shndx: ?u16 = null,

        inline fn isFirstTlsShdr(this: @This(), shndx: u16) bool {
            if (this.first_tls_shndx) |tshndx| return tshndx == shndx;
            return false;
        }

        inline fn @"align"(this: @This(), shndx: u16, sh_addralign: u64, addr: u64) u64 {
            const alignment = if (this.isFirstTlsShdr(shndx)) this.tls_start_align else sh_addralign;
            return mem.alignForwardGeneric(u64, addr, alignment);
        }
    };

    var alignment = Align{};
    for (self.sections.items(.shdr)[1..], 1..) |*shdr, shndx| {
        if (!shdrIsTls(shdr)) continue;
        if (alignment.first_tls_shndx == null) alignment.first_tls_shndx = @intCast(u16, shndx);
        alignment.tls_start_align = @max(alignment.tls_start_align, shdr.sh_addralign);
    }

    var addr = default_base_addr + base_offset;
    outer: for (self.sections.items(.shdr)[1..], 1..) |*shdr, i| {
        if (!shdrIsAlloc(shdr)) continue;
        if (i != 1) {
            const prev_shdr = self.sections.items(.shdr)[i - 1];
            if (shdrToPhdrFlags(shdr.sh_flags) != shdrToPhdrFlags(prev_shdr.sh_flags)) {
                // We need advance by page size
                addr += default_page_size;
            }
        }
        if (shdrIsTbss(shdr)) {
            var tbss_addr = addr;
            for (self.sections.items(.shdr)[i..]) |*tbss_shdr| {
                if (!shdrIsTbss(tbss_shdr)) continue :outer;
                tbss_addr = alignment.@"align"(@intCast(u16, i), shdr.sh_addralign, tbss_addr);
                tbss_shdr.sh_addr = tbss_addr;
                tbss_addr += tbss_shdr.sh_size;
            }
        }

        addr = alignment.@"align"(@intCast(u16, i), shdr.sh_addralign, addr);
        shdr.sh_addr = addr;
        addr += shdr.sh_size;
    }
}

fn allocatesSectionsInFile(self: *Elf, base_offset: u64) void {
    var offset = base_offset;
    for (self.sections.items(.shdr)[1..]) |*shdr| {
        if (shdr.sh_type == elf.SHT_NOBITS) continue;
        shdr.sh_offset = mem.alignForwardGeneric(u64, offset, shdr.sh_addralign);
        offset = shdr.sh_offset + shdr.sh_size;
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
    const shdr = self.sections.items(.shdr)[shndx];
    const name = self.shstrtab.getAssumeExists(shdr.sh_name);
    const flags = shdr.sh_flags;
    switch (shdr.sh_type) {
        elf.SHT_NULL => return 0,
        elf.SHT_DYNSYM => return 2,
        elf.SHT_HASH => return 3,
        SHT_GNU_HASH => return 3,
        SHT_GNU_versym => return 4,
        SHT_GNU_verdef => return 4,
        SHT_GNU_verneed => return 4,

        elf.SHT_PREINIT_ARRAY,
        elf.SHT_INIT_ARRAY,
        elf.SHT_FINI_ARRAY,
        => return 0xf2,

        elf.SHT_DYNAMIC => return 0xf3,

        elf.SHT_RELA => return 0xf,

        elf.SHT_PROGBITS => if (flags & elf.SHF_ALLOC != 0) {
            if (flags & elf.SHF_EXECINSTR != 0) {
                return 0xf1;
            } else if (flags & elf.SHF_WRITE != 0) {
                return if (flags & elf.SHF_TLS != 0) 0xf4 else 0xf6;
            } else if (mem.eql(u8, name, ".interp")) {
                return 1;
            } else {
                return 0xf0;
            }
        } else {
            if (mem.startsWith(u8, name, ".debug")) {
                return 0xf8;
            } else {
                return 0xf9;
            }
        },

        elf.SHT_NOBITS => return if (flags & elf.SHF_TLS != 0) 0xf5 else 0xf7,
        elf.SHT_SYMTAB => return 0xfa,
        elf.SHT_STRTAB => return if (mem.eql(u8, name, ".dynstr")) 4 else 0xfb,
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

    mem.sort(Entry, entries.items, self, Entry.lessThan);

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
            if (!atom.alive) continue;
            atom.out_shndx = backlinks[atom.out_shndx];
        }
    }

    for (&[_]*?u16{
        &self.text_sect_index,
        &self.eh_frame_sect_index,
        &self.eh_frame_hdr_sect_index,
        &self.got_sect_index,
        &self.symtab_sect_index,
        &self.strtab_sect_index,
        &self.shstrtab_sect_index,
        &self.interp_sect_index,
        &self.dynamic_sect_index,
        &self.dynsymtab_sect_index,
        &self.dynstrtab_sect_index,
        &self.hash_sect_index,
        &self.gnu_hash_sect_index,
        &self.plt_sect_index,
        &self.got_plt_sect_index,
        &self.plt_got_sect_index,
        &self.rela_dyn_sect_index,
        &self.rela_plt_sect_index,
        &self.copy_rel_sect_index,
        &self.versym_sect_index,
        &self.verneed_sect_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }

    if (self.symtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.strtab_sect_index.?;
    }

    if (self.dynamic_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynstrtab_sect_index.?;
    }

    if (self.dynsymtab_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynstrtab_sect_index.?;
    }

    if (self.hash_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynsymtab_sect_index.?;
    }

    if (self.gnu_hash_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynsymtab_sect_index.?;
    }

    if (self.versym_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynsymtab_sect_index.?;
    }

    if (self.verneed_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynstrtab_sect_index.?;
    }

    if (self.rela_dyn_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynsymtab_sect_index.?;
    }

    if (self.rela_plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynsymtab_sect_index.?;
        shdr.sh_info = self.plt_sect_index.?;
    }
}

fn allocateAtoms(self: *Elf) void {
    for (self.sections.items(.shdr), self.sections.items(.atoms)) |shdr, atoms| {
        if (atoms.items.len == 0) continue;
        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.alive);
            atom.value += shdr.sh_addr;
        }
    }
}

fn allocateLocals(self: *Elf) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.getLocals()) |local_index| {
            const local = self.getSymbol(local_index);
            const atom = local.getAtom(self) orelse continue;
            if (!atom.alive) continue;
            local.value += atom.value;
            local.shndx = atom.out_shndx;
        }
    }
}

fn allocateGlobals(self: *Elf) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.getGlobals()) |global_index| {
            const global = self.getSymbol(global_index);
            const atom = global.getAtom(self) orelse continue;
            if (!atom.alive) continue;
            if (global.getFile(self).?.object.index != index) continue;
            global.value += atom.value;
            global.shndx = atom.out_shndx;
        }
    }
}

fn allocateSyntheticSymbols(self: *Elf) void {
    // _DYNAMIC
    {
        const shndx = self.dynamic_sect_index orelse self.got_sect_index.?;
        const shdr = self.sections.items(.shdr)[shndx];
        const symbol = self.getSymbol(self.dynamic_index.?);
        symbol.value = shdr.sh_addr;
        symbol.shndx = shndx;
    }

    // __init_array_start, __init_array_end
    if (self.getSectionByName(".init_array")) |shndx| {
        const start_sym = self.getSymbol(self.init_array_start_index.?);
        const end_sym = self.getSymbol(self.init_array_end_index.?);
        const shdr = self.sections.items(.shdr)[shndx];
        start_sym.shndx = shndx;
        start_sym.value = shdr.sh_addr;
        end_sym.shndx = shndx;
        end_sym.value = shdr.sh_addr + shdr.sh_size;
    }

    // __fini_array_start, __fini_array_end
    if (self.getSectionByName(".fini_array")) |shndx| {
        const start_sym = self.getSymbol(self.fini_array_start_index.?);
        const end_sym = self.getSymbol(self.fini_array_end_index.?);
        const shdr = self.sections.items(.shdr)[shndx];
        start_sym.shndx = shndx;
        start_sym.value = shdr.sh_addr;
        end_sym.shndx = shndx;
        end_sym.value = shdr.sh_addr + shdr.sh_size;
    }

    // _GLOBAL_OFFSET_TABLE_
    {
        const shndx = self.got_plt_sect_index orelse self.got_sect_index.?;
        const shdr = self.sections.items(.shdr)[shndx];
        const symbol = self.getSymbol(self.got_index.?);
        symbol.value = shdr.sh_addr;
        symbol.shndx = shndx;
    }

    // _PROCEDURE_LINKAGE_TABLE_
    if (self.plt_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        const symbol = self.getSymbol(self.plt_index.?);
        symbol.value = shdr.sh_addr;
        symbol.shndx = shndx;
    }

    // __dso_handle
    if (self.dso_handle_index) |index| {
        const shdr = self.sections.items(.shdr)[1];
        const symbol = self.getSymbol(index);
        symbol.value = shdr.sh_addr;
        symbol.shndx = 0;
    }
}

fn unpackPositionals(self: *Elf, positionals: *std.ArrayList(LinkObject)) !void {
    const State = struct {
        needed: bool,
        static: bool,
    };

    try positionals.ensureTotalCapacity(self.options.positionals.len);

    var stack = std.ArrayList(State).init(self.base.allocator);
    defer stack.deinit();

    var state = State{ .needed = true, .static = self.options.static };

    for (self.options.positionals) |arg| switch (arg.tag) {
        .path => positionals.appendAssumeCapacity(.{ .path = arg.path }),
        .library => positionals.appendAssumeCapacity(.{
            .path = arg.path,
            .needed = state.needed,
            .static = state.static,
        }),
        .static => state.static = true,
        .dynamic => state.static = false,
        .as_needed => state.needed = false,
        .no_as_needed => state.needed = true,
        .push_state => try stack.append(state),
        .pop_state => state = stack.popOrNull() orelse return self.base.fatal("no state pushed before pop", .{}),
    };
}

fn parsePositional(self: *Elf, arena: Allocator, obj: LinkObject, search_dirs: []const []const u8) anyerror!void {
    const resolved_obj = self.resolveFile(arena, obj, search_dirs) catch |err| switch (err) {
        error.ResolveFail => return,
        else => |e| return e,
    };

    log.debug("parsing positional argument '{s}'", .{resolved_obj.path});

    if (try self.parseObject(arena, resolved_obj)) return;
    if (try self.parseArchive(arena, resolved_obj)) return;
    if (try self.parseShared(arena, resolved_obj)) return;
    if (try self.parseLdScript(arena, resolved_obj, search_dirs)) return;

    self.base.fatal("unknown filetype for positional argument: '{s}'", .{resolved_obj.path});
}

fn parseObject(self: *Elf, arena: Allocator, obj: LinkObject) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const header = try file.reader().readStruct(elf.Elf64_Ehdr);
    try file.seekTo(0);

    if (!Object.isValidHeader(&header)) return false;
    self.validateOrSetCpuArch(obj.path, header.e_machine.toTargetCpuArch().?);

    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const index = @intCast(u32, try self.files.addOne(gpa));
    self.files.set(index, .{ .object = .{
        .path = obj.path,
        .data = data,
        .index = index,
    } });
    const object = &self.files.items(.data)[index].object;
    try object.parse(self);
    try self.objects.append(gpa, index);

    return true;
}

fn parseArchive(self: *Elf, arena: Allocator, obj: LinkObject) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const magic = try file.reader().readBytesNoEof(Archive.SARMAG);
    try file.seekTo(0);

    if (!Archive.isValidMagic(&magic)) return false;

    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));
    var archive = Archive{ .path = obj.path, .data = data };
    defer archive.deinit(gpa);
    try archive.parse(arena, self);

    for (archive.objects.items) |extracted| {
        const index = @intCast(File.Index, try self.files.addOne(gpa));
        self.files.set(index, .{ .object = extracted });
        const object = &self.files.items(.data)[index].object;
        object.index = index;
        try object.parse(self);
        try self.objects.append(gpa, index);
    }

    return true;
}

fn parseShared(self: *Elf, arena: Allocator, obj: LinkObject) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const header = try file.reader().readStruct(elf.Elf64_Ehdr);
    try file.seekTo(0);

    if (!SharedObject.isValidHeader(&header)) return false;
    self.validateOrSetCpuArch(obj.path, header.e_machine.toTargetCpuArch().?);

    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const index = @intCast(File.Index, try self.files.addOne(gpa));
    self.files.set(index, .{ .shared = .{
        .path = obj.path,
        .data = data,
        .index = index,
        .needed = obj.needed,
        .alive = obj.needed,
    } });
    const dso = &self.files.items(.data)[index].shared;
    try dso.parse(self);
    try self.shared_objects.append(gpa, index);

    return true;
}

fn parseLdScript(self: *Elf, arena: Allocator, obj: LinkObject, search_dirs: []const []const u8) !bool {
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(gpa, std.math.maxInt(u32));
    defer gpa.free(data);

    log.debug("parsing ld linker script path '{s}'", .{obj.path});

    var script = LdScript{};
    defer script.deinit(gpa);
    script.parse(data, self) catch |err| switch (err) {
        error.InvalidScript => return false,
        else => |e| return e,
    };

    if (script.cpu_arch) |cpu_arch| {
        self.validateOrSetCpuArch(obj.path, cpu_arch);
    }

    for (script.args.items) |s_obj| {
        try self.parsePositional(arena, .{
            .path = s_obj.path,
            .static = obj.static or s_obj.static,
            .needed = obj.needed and s_obj.needed,
        }, search_dirs);
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
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.shared_objects.items) |index| self.getFile(index).?.resolveSymbols(self);

    // Mark live objects.
    self.markLive();

    // Reset state of all globals after marking live objects.
    for (self.objects.items) |index| self.getFile(index).?.resetGlobals(self);
    for (self.shared_objects.items) |index| self.getFile(index).?.resetGlobals(self);

    // Prune dead objects and shared objects.
    var i: usize = 0;
    while (i < self.objects.items.len) {
        const index = self.objects.items[i];
        if (!self.getFile(index).?.isAlive()) {
            _ = self.objects.orderedRemove(i);
        } else i += 1;
    }

    i = 0;
    while (i < self.shared_objects.items.len) {
        const index = self.shared_objects.items[i];
        if (!self.getFile(index).?.isAlive()) {
            _ = self.shared_objects.orderedRemove(i);
        } else i += 1;
    }

    // Dedup comdat groups.
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.comdat_groups.items) |cg_index| {
            const cg = self.getComdatGroup(cg_index);
            const cg_owner = self.getComdatGroupOwner(cg.owner);
            const owner_file_index = if (self.getFile(cg_owner.file)) |file|
                file.object.index
            else
                std.math.maxInt(File.Index);
            cg_owner.file = @min(owner_file_index, index);
        }
    }

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.comdat_groups.items) |cg_index| {
            const cg = self.getComdatGroup(cg_index);
            const cg_owner = self.getComdatGroupOwner(cg.owner);
            if (cg_owner.file != index) {
                for (object.getComdatGroupMembers(cg.shndx)) |shndx| {
                    const atom_index = object.atoms.items[shndx];
                    if (self.getAtom(atom_index)) |atom| atom.alive = false;
                }
            }
        }
    }

    // Re-resolve the symbols.
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.shared_objects.items) |index| self.getFile(index).?.resolveSymbols(self);
}

/// Traverses all objects and shared objects marking any object referenced by
/// a live object/shared object as alive itself.
/// This routine will prune unneeded objects extracted from archives and
/// unneeded shared objects.
fn markLive(self: *Elf) void {
    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (file.isAlive()) file.markLive(self);
    }
    for (self.shared_objects.items) |index| {
        const file = self.getFile(index).?;
        if (file.isAlive()) file.markLive(self);
    }
}

fn markEhFrameAtomsDead(self: *Elf) void {
    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (!file.isAlive()) continue;
        const object = file.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            const is_eh_frame = atom.getInputShdr(self).sh_type == elf.SHT_X86_64_UNWIND or
                mem.eql(u8, atom.getName(self), ".eh_frame");
            if (atom.alive and is_eh_frame) atom.alive = false;
        }
    }
}

fn convertCommonSymbols(self: *Elf) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.convertCommonSymbols(self);
    }
}

fn markImportsAndExports(self: *Elf) !void {
    for (self.shared_objects.items) |index| {
        for (self.getFile(index).?.shared.getGlobals()) |global_index| {
            const global = self.getSymbol(global_index);
            const file = global.getFile(self) orelse continue;
            const vis = @intToEnum(elf.STV, global.getSourceSymbol(self).st_other);
            if (file != .shared and vis != .HIDDEN) global.flags.@"export" = true;
        }
    }

    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.getGlobals()) |global_index| {
            const global = self.getSymbol(global_index);
            if (global.ver_idx == VER_NDX_LOCAL) continue;
            const file = global.getFile(self) orelse continue;
            const vis = @intToEnum(elf.STV, global.getSourceSymbol(self).st_other);
            if (vis == .HIDDEN) continue;
            if (file == .shared and !global.isAbs(self)) {
                global.flags.import = true;
                continue;
            }
            if (file.getIndex() == index) {
                global.flags.@"export" = true;
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
    self.plt_index = try internal.addSyntheticGlobal("_PROCEDURE_LINKAGE_TABLE_", self);

    if (self.getGlobalByName("__dso_handle")) |index| {
        if (self.getSymbol(index).getFile(self) == null)
            self.dso_handle_index = try internal.addSyntheticGlobal("__dso_handle", self);
    }

    internal.resolveSymbols(self);
}

fn checkDuplicates(self: *Elf) void {
    for (self.objects.items) |index| self.getFile(index).?.object.checkDuplicates(self);
}

fn claimUnresolved(self: *Elf) void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        const first_global = object.first_global orelse return;
        for (object.getGlobals(), 0..) |global_index, i| {
            const sym_idx = @intCast(u32, first_global + i);
            const sym = object.symtab[sym_idx];
            if (sym.st_shndx != elf.SHN_UNDEF) continue;

            const global = self.getSymbol(global_index);
            if (global.getFile(self)) |_| {
                if (global.getSourceSymbol(self).st_shndx != elf.SHN_UNDEF) continue;
            }

            global.* = .{
                .value = 0,
                .name = global.name,
                .atom = 0,
                .sym_idx = sym_idx,
                .file = object.index,
                .ver_idx = self.default_sym_version,
            };
        }
    }
}

fn reportUndefs(self: *Elf) !void {
    if (self.undefs.count() == 0) return;

    const max_notes = 4;

    const gpa = self.base.allocator;
    var it = self.undefs.iterator();
    while (it.next()) |entry| {
        const undef_sym = self.getSymbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @boolToInt(notes.items.len > max_notes);

        var err = Zld.ErrorMsg{
            .msg = try std.fmt.allocPrint(gpa, "undefined symbol: {s}", .{undef_sym.getName(self)}),
        };
        err.notes = try gpa.alloc(Zld.ErrorMsg, nnotes);

        var inote: usize = 0;
        while (inote < nnotes) : (inote += 1) {
            const atom = self.getAtom(notes.items[inote]).?;
            const object = atom.getObject(self);
            err.notes.?[inote] = Zld.ErrorMsg{
                .msg = try std.fmt.allocPrint(gpa, "referenced by {}:{s}", .{ object.fmtPath(), atom.getName(self) }),
            };
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            err.notes.?[max_notes] = Zld.ErrorMsg{
                .msg = try std.fmt.allocPrint(gpa, "referenced {d} more times", .{remaining}),
            };
        }

        try self.base.errors.append(gpa, err);
    }
}

fn scanRelocs(self: *Elf) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.scanRelocs(self);
    }

    try self.reportUndefs();
    self.base.reportWarningsAndErrorsAndExit();

    for (self.symbols.items, 0..) |*symbol, i| {
        const index = @intCast(u32, i);
        if (!symbol.isLocal() and !symbol.flags.has_dynamic) {
            log.debug("'{s}' is non-local", .{symbol.getName(self)});
            try self.dynsym.addSymbol(index, self);
        }
        if (symbol.flags.got) {
            log.debug("'{s}' needs GOT", .{symbol.getName(self)});
            try self.got.addSymbol(index, self);
            if (symbol.flags.import) self.got.needs_rela = true;
        }
        if (symbol.flags.plt) {
            if (symbol.flags.got) {
                log.debug("'{s}' needs PLTGOT", .{symbol.getName(self)});
                try self.plt_got.addSymbol(index, self);
            } else {
                log.debug("'{s}' needs PLT", .{symbol.getName(self)});
                try self.plt.addSymbol(index, self);
            }
        }
        if (symbol.flags.copy_rel and !symbol.flags.has_copy_rel) {
            log.debug("'{s}' needs COPYREL!", .{symbol.getName(self)});
            try self.copy_rel.addSymbol(index, self);
        }
        if (symbol.flags.tlsgd) {
            log.warn("'{s}' needs TLSGD!", .{symbol.getName(self)});
        }
    }

    if (self.needs_tlsld) {
        log.warn("needs TLSLD", .{});
        self.got.emit_tlsld = true;
    }
}

fn setDynamic(self: *Elf) !void {
    if (self.dynamic_sect_index == null) return;

    try self.dynamic.setRpath(self.options.rpath_list, self);

    for (self.shared_objects.items) |index| {
        const shared = self.getFile(index).?.shared;
        if (!shared.alive) continue;
        try self.dynamic.addNeeded(shared, self);
    }
}

fn setDynsym(self: *Elf) void {
    if (self.gnu_hash_sect_index == null) return;
    self.dynsym.sort(self);
}

fn setVerSymtab(self: *Elf) !void {
    if (self.versym_sect_index == null) return;
    try self.versym.resize(self.base.allocator, self.dynsym.count());
    self.versym.items[0] = VER_NDX_LOCAL;
    for (self.dynsym.symbols.items, 1..) |dynsym, i| {
        const sym = self.getSymbol(dynsym.index);
        self.versym.items[i] = sym.ver_idx;
    }

    if (self.verneed_sect_index) |shndx| {
        try self.verneed.generate(self);
        const shdr = &self.sections.items(.shdr)[shndx];
        shdr.sh_info = @intCast(u32, self.verneed.verneed.items.len);
    }
}

fn setHashes(self: *Elf) !void {
    if (self.hash_sect_index != null) {
        try self.hash.generate(self);
    }
    if (self.gnu_hash_sect_index != null) {
        try self.gnu_hash.calcSize(self);
    }
}

fn writeAtoms(self: *Elf) !void {
    const slice = self.sections.slice();
    for (slice.items(.shdr), slice.items(.atoms)) |shdr, atoms| {
        if (atoms.items.len == 0) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        log.debug("writing atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        var buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        @memset(buffer, 0xcc); // int3s

        var stream = std.io.fixedBufferStream(buffer);

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.alive);
            const off = if (shdr.sh_flags & elf.SHF_ALLOC == 0) atom.value else atom.value - shdr.sh_addr;
            log.debug("writing ATOM(%{d},'{s}') at offset 0x{x}", .{
                atom_index,
                atom.getName(self),
                shdr.sh_offset + off,
            });
            try stream.seekTo(off);

            if (shdr.sh_flags & elf.SHF_ALLOC == 0)
                try atom.resolveRelocsNonAlloc(self, stream.writer())
            else
                try atom.resolveRelocsAlloc(self, stream.writer());
        }

        try self.base.file.pwriteAll(buffer, shdr.sh_offset);
    }

    try self.reportUndefs();
    self.base.reportWarningsAndErrorsAndExit();
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

    if (self.hash_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(self.hash.buffer.items, shdr.sh_offset);
    }

    if (self.gnu_hash_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.gnu_hash.size());
        defer buffer.deinit();
        try self.gnu_hash.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.versym_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(mem.sliceAsBytes(self.versym.items), shdr.sh_offset);
    }

    if (self.verneed_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.verneed.size());
        defer buffer.deinit();
        try self.verneed.write(buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.dynamic_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.dynamic.size(self));
        defer buffer.deinit();
        try self.dynamic.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.dynsymtab_sect_index) |shndx| {
        const shdr = &self.sections.items(.shdr)[shndx];
        shdr.sh_info = 1;
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.dynsym.size());
        defer buffer.deinit();
        try self.dynsym.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.dynstrtab_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.base.file.pwriteAll(self.dynstrtab.buffer.items, shdr.sh_offset);
    }

    if (self.eh_frame_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, eh_frame.calcEhFrameSize(self));
        defer buffer.deinit();
        try eh_frame.writeEhFrame(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.eh_frame_hdr_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, eh_frame.calcEhFrameHdrSize(self));
        defer buffer.deinit();
        try eh_frame.writeEhFrameHdr(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.got_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.got.size());
        defer buffer.deinit();
        try self.got.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.rela_dyn_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.got.addRela(self);
        try self.copy_rel.addRela(self);
        self.sortRelaDyn();
        try self.base.file.pwriteAll(mem.sliceAsBytes(self.rela_dyn.items), shdr.sh_offset);
    }

    if (self.plt_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.plt.sizePlt());
        defer buffer.deinit();
        try self.plt.writePlt(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.got_plt_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.plt.sizeGotPlt());
        defer buffer.deinit();
        try self.plt.writeGotPlt(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.plt_got_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.plt_got.size());
        defer buffer.deinit();
        try self.plt_got.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.rela_plt_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        try self.plt.addRela(self);
        try self.base.file.pwriteAll(mem.sliceAsBytes(self.rela_plt.items), shdr.sh_offset);
    }

    if (!self.options.strip_all) {
        try self.writeSymtab();
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
        .e_entry = if (self.entry_index) |index| self.getSymbol(index).value else 0,
        .e_phoff = @sizeOf(elf.Elf64_Ehdr),
        .e_shoff = self.shoff,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @intCast(u16, self.phdrs.items.len),
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
    size: u64 = 0,
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
            .sh_size = opts.size,
            .sh_link = 0,
            .sh_info = opts.info,
            .sh_addralign = opts.addralign,
            .sh_entsize = opts.entsize,
        },
    });
    return index;
}

pub fn getSectionByName(self: *Elf, name: [:0]const u8) ?u16 {
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const this_name = self.shstrtab.getAssumeExists(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @intCast(u16, i);
    } else return null;
}

fn addPhdr(self: *Elf, opts: struct {
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

pub fn getFile(self: *Elf, index: File.Index) ?File {
    const tag = self.files.items(.tags)[index];
    return switch (tag) {
        .null => null,
        .internal => .{ .internal = &self.files.items(.data)[index].internal },
        .object => .{ .object = &self.files.items(.data)[index].object },
        .shared => .{ .shared = &self.files.items(.data)[index].shared },
    };
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

pub fn addSymbol(self: *Elf) !u32 {
    const index = @intCast(u32, self.symbols.items.len);
    const symbol = try self.symbols.addOne(self.base.allocator);
    symbol.* = .{};
    return index;
}

pub fn getSymbol(self: *Elf, index: u32) *Symbol {
    assert(index < self.symbols.items.len);
    return &self.symbols.items[index];
}

pub fn addSymbolExtra(self: *Elf, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    try self.symbols_extra.ensureUnusedCapacity(self.base.allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

pub fn addSymbolExtraAssumeCapacity(self: *Elf, extra: Symbol.Extra) u32 {
    const index = @intCast(u32, self.symbols_extra.items.len);
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    inline for (fields) |field| {
        self.symbols_extra.appendAssumeCapacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        });
    }
    return index;
}

pub fn getSymbolExtra(self: *Elf, index: u32) ?Symbol.Extra {
    if (index == 0) return null;
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

pub fn setSymbolExtra(self: *Elf, index: u32, extra: Symbol.Extra) void {
    assert(index > 0);
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    inline for (fields, 0..) |field, i| {
        self.symbols_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
}

pub fn internString(self: *Elf, comptime format: []const u8, args: anytype) !u32 {
    const gpa = self.base.allocator;
    const string = try std.fmt.allocPrintZ(gpa, format, args);
    defer gpa.free(string);
    return self.string_intern.insert(gpa, string);
}

const GetOrCreateGlobalResult = struct {
    found_existing: bool,
    index: u32,
};

pub fn getOrCreateGlobal(self: *Elf, off: u32) !GetOrCreateGlobalResult {
    const gpa = self.base.allocator;
    const gop = try self.globals.getOrPut(gpa, off);
    if (!gop.found_existing) {
        const index = try self.addSymbol();
        const global = self.getSymbol(index);
        global.name = off;
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn getGlobalByName(self: *Elf, name: []const u8) ?u32 {
    const off = self.string_intern.getOffset(name) orelse return null;
    return self.globals.get(off);
}

const GetOrCreateComdatGroupOwnerResult = struct {
    found_existing: bool,
    index: ComdatGroupOwner.Index,
};

pub fn getOrCreateComdatGroupOwner(self: *Elf, off: u32) !GetOrCreateComdatGroupOwnerResult {
    const gpa = self.base.allocator;
    const gop = try self.comdat_groups_table.getOrPut(gpa, off);
    if (!gop.found_existing) {
        const index = @intCast(ComdatGroupOwner.Index, self.comdat_groups_owners.items.len);
        const owner = try self.comdat_groups_owners.addOne(gpa);
        owner.* = .{};
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn addComdatGroup(self: *Elf) !ComdatGroup.Index {
    const index = @intCast(ComdatGroup.Index, self.comdat_groups.items.len);
    _ = try self.comdat_groups.addOne(self.base.allocator);
    return index;
}

pub inline fn getComdatGroup(self: *Elf, index: ComdatGroup.Index) *ComdatGroup {
    assert(index < self.comdat_groups.items.len);
    return &self.comdat_groups.items[index];
}

pub inline fn getComdatGroupOwner(self: *Elf, index: ComdatGroupOwner.Index) *ComdatGroupOwner {
    assert(index < self.comdat_groups_owners.items.len);
    return &self.comdat_groups_owners.items[index];
}

const RelaDyn = struct {
    offset: u64,
    sym: u64,
    type: u32,
    addend: i64 = 0,
};

pub inline fn addRelaDyn(self: *Elf, opts: RelaDyn) !void {
    try self.rela_dyn.ensureUnusedCapacity(self.base.alloctor, 1);
    self.addRelaDynAssumeCapacity(opts);
}

pub inline fn addRelaDynAssumeCapacity(self: *Elf, opts: RelaDyn) void {
    self.rela_dyn.appendAssumeCapacity(.{
        .r_offset = opts.offset,
        .r_info = (opts.sym << 32) | opts.type,
        .r_addend = opts.addend,
    });
}

fn sortRelaDyn(self: *Elf) void {
    const Sort = struct {
        pub fn lessThan(ctx: void, lhs: elf.Elf64_Rela, rhs: elf.Elf64_Rela) bool {
            _ = ctx;
            if (lhs.r_sym() == rhs.r_sym()) return lhs.r_offset < rhs.r_offset;
            return lhs.r_sym() < rhs.r_sym();
        }
    };
    mem.sort(elf.Elf64_Rela, self.rela_dyn.items, {}, Sort.lessThan);
}

pub inline fn getSectionAddress(self: *Elf, shndx: u16) u64 {
    return self.sections.items(.shdr)[shndx].sh_addr;
}

pub inline fn getGotEntryAddress(self: *Elf, index: u32) u64 {
    return self.getSectionAddress(self.got_sect_index.?) + index * @sizeOf(u64);
}

pub inline fn getPltEntryAddress(self: *Elf, index: u32) u64 {
    return self.getSectionAddress(self.plt_sect_index.?) + PltSection.plt_preamble_size + index * 16;
}

pub inline fn getGotPltEntryAddress(self: *Elf, index: u32) u64 {
    return self.getSectionAddress(self.got_plt_sect_index.?) + PltSection.got_plt_preamble_size + index * @sizeOf(u64);
}

pub inline fn getPltGotEntryAddress(self: *Elf, index: u32) u64 {
    return self.getSectionAddress(self.plt_got_sect_index.?) + index * 16;
}

pub inline fn getTlsLdAddress(self: *Elf) u64 {
    return self.getGotEntryAddress(@intCast(u32, self.got.symbols.items.len));
}

pub fn getTpAddress(self: *Elf) u64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    return mem.alignForwardGeneric(u64, phdr.p_vaddr + phdr.p_memsz, phdr.p_align);
}

pub fn getDtpAddress(self: *Elf) u64 {
    return self.getTlsAddress();
}

pub inline fn getTlsAddress(self: *Elf) u64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    return phdr.p_vaddr;
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

fn fmtPhdrs(self: *Elf) std.fmt.Formatter(formatPhdrs) {
    return .{ .data = self };
}

fn formatPhdrs(
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
        try writer.print("object({d}) : {}", .{ index, object.fmtPath() });
        if (!object.alive) try writer.writeAll(" : [*]");
        try writer.writeByte('\n');
        try writer.print("{}{}{}{}{}\n", .{
            object.fmtAtoms(self),
            object.fmtCies(self),
            object.fmtFdes(self),
            object.fmtSymtab(self),
            object.fmtComdatGroups(self),
        });
    }
    for (self.shared_objects.items) |index| {
        const shared = self.getFile(index).?.shared;
        try writer.print("shared({d}) : ", .{index});
        try writer.print("{s}", .{shared.path});
        try writer.print(" : needed({})", .{shared.needed});
        if (!shared.alive) try writer.writeAll(" : [*]");
        try writer.writeByte('\n');
        try writer.print("{}\n", .{shared.fmtSymtab(self)});
    }
    if (self.internal_object_index) |index| {
        const internal = self.getFile(index).?.internal;
        try writer.print("internal({d}) : internal\n", .{index});
        try writer.print("{}\n", .{internal.fmtSymtab(self)});
    }
    try writer.writeAll("GOT\n");
    for (self.got.symbols.items, 0..) |sym_index, i| {
        try writer.print("  {d} => {d} '{s}'\n", .{ i, sym_index, self.getSymbol(sym_index).getName(self) });
    }
    try writer.writeByte('\n');
    try writer.writeAll("PLT\n");
    for (self.plt.symbols.items, 0..) |sym_index, i| {
        try writer.print("  {d} => {d} '{s}'\n", .{ i, sym_index, self.getSymbol(sym_index).getName(self) });
    }
    try writer.writeByte('\n');
    try writer.writeAll("PLTGOT\n");
    for (self.plt_got.symbols.items, 0..) |sym_index, i| {
        try writer.print("  {d} => {d} '{s}'\n", .{ i, sym_index, self.getSymbol(sym_index).getName(self) });
    }
    try writer.writeByte('\n');
    try writer.writeAll("COPYREL\n");
    for (self.copy_rel.symbols.items, 0..) |sym_index, i| {
        const symbol = self.getSymbol(sym_index);
        try writer.print("  {d}@{x} => {d} '{s}'\n", .{
            i,
            symbol.getAddress(self),
            sym_index,
            symbol.getName(self),
        });
    }
    try writer.writeByte('\n');
    try writer.writeAll("Output sections\n");
    try writer.print("{}\n", .{self.fmtSections()});
    try writer.writeAll("Output phdrs\n");
    try writer.print("{}\n", .{self.fmtPhdrs()});
}

pub const LinkObject = struct {
    path: []const u8,
    needed: bool = true,
    static: bool = false,
};

const Section = struct {
    shdr: elf.Elf64_Shdr,
    atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
};

const ComdatGroupOwner = struct {
    file: File.Index = 0,

    const Index = u32;
};

pub const ComdatGroup = struct {
    owner: ComdatGroupOwner.Index,
    shndx: u16,

    pub const Index = u32;
};

pub const SymtabSize = struct {
    nlocals: u32 = 0,
    nglobals: u32 = 0,
    strsize: u32 = 0,
};

pub const WriteSymtabCtx = struct {
    ilocal: u32,
    iglobal: u32,
    symtab: []elf.Elf64_Sym,
    strtab: *StringTable(.strtab),
};

const default_base_addr: u64 = 0x200000;
const default_page_size: u64 = 0x1000;
pub const eh_frame_hdr_header_size: u64 = 12;

pub const null_sym = elf.Elf64_Sym{
    .st_name = 0,
    .st_info = 0,
    .st_other = 0,
    .st_shndx = 0,
    .st_value = 0,
    .st_size = 0,
};

pub const base_tag = Zld.Tag.elf;

pub const VERSYM_HIDDEN = 0x8000;
pub const VERSYM_VERSION = 0x7fff;

/// Symbol is local
pub const VER_NDX_LOCAL = 0;
/// Symbol is global
pub const VER_NDX_GLOBAL = 1;

/// Version definition of the file itself
pub const VER_FLG_BASE = 1;
/// Weak version identifier
pub const VER_FLG_WEAK = 2;

// VERDEF
pub const SHT_GNU_verdef = 0x6ffffffd;
// VERNEED
pub const SHT_GNU_verneed = 0x6ffffffe;
// VERSYM
pub const SHT_GNU_versym = 0x6fffffff;
// GNU_HASH
pub const SHT_GNU_HASH = 0x6ffffff6;

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const eh_frame = @import("Elf/eh_frame.zig");
const elf = std.elf;
const fs = std.fs;
const gc = @import("Elf/gc.zig");
const log = std.log.scoped(.elf);
const state_log = std.log.scoped(.state);
const synthetic = @import("Elf/synthetic.zig");
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Archive = @import("Elf/Archive.zig");
const Atom = @import("Elf/Atom.zig");
const CopyRelSection = synthetic.CopyRelSection;
const DynamicSection = synthetic.DynamicSection;
const DynsymSection = synthetic.DynsymSection;
const Elf = @This();
const File = @import("Elf/file.zig").File;
const GnuHashSection = synthetic.GnuHashSection;
const GotSection = synthetic.GotSection;
const HashSection = synthetic.HashSection;
const InternalObject = @import("Elf/InternalObject.zig");
const LdScript = @import("Elf/LdScript.zig");
const Object = @import("Elf/Object.zig");
pub const Options = @import("Elf/Options.zig");
const PltSection = synthetic.PltSection;
const PltGotSection = synthetic.PltGotSection;
const SharedObject = @import("Elf/SharedObject.zig");
const StringTable = @import("strtab.zig").StringTable;
const Symbol = @import("Elf/Symbol.zig");
const ThreadPool = @import("ThreadPool.zig");
const VerneedSection = synthetic.VerneedSection;
const Zld = @import("Zld.zig");
