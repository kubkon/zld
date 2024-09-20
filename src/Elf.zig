base: Zld,
options: Options,
shoff: u64 = 0,

objects: std.ArrayListUnmanaged(File.Index) = .{},
shared_objects: std.ArrayListUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},
internal_object_index: ?File.Index = null,

sections: std.MultiArrayList(Section) = .{},
phdrs: std.ArrayListUnmanaged(elf.Elf64_Phdr) = .{},

tls_phdr_index: ?u16 = null,

text_sect_index: ?u32 = null,
eh_frame_hdr_sect_index: ?u32 = null,
eh_frame_sect_index: ?u32 = null,
plt_sect_index: ?u32 = null,
got_sect_index: ?u32 = null,
got_plt_sect_index: ?u32 = null,
plt_got_sect_index: ?u32 = null,
rela_dyn_sect_index: ?u32 = null,
rela_plt_sect_index: ?u32 = null,
copy_rel_sect_index: ?u32 = null,
symtab_sect_index: ?u32 = null,
strtab_sect_index: ?u32 = null,
shstrtab_sect_index: ?u32 = null,
interp_sect_index: ?u32 = null,
dynamic_sect_index: ?u32 = null,
dynsymtab_sect_index: ?u32 = null,
dynstrtab_sect_index: ?u32 = null,
hash_sect_index: ?u32 = null,
gnu_hash_sect_index: ?u32 = null,
versym_sect_index: ?u32 = null,
verneed_sect_index: ?u32 = null,

resolver: SymbolResolver = .{},
/// This table will be populated after `scanRelocs` has run.
/// Key is symbol index.
undefs: std.AutoArrayHashMapUnmanaged(SymbolResolver.Index, std.ArrayListUnmanaged(Ref)) = .{},
dupes: std.AutoArrayHashMapUnmanaged(SymbolResolver.Index, std.ArrayListUnmanaged(File.Index)) = .{},

shstrtab: std.ArrayListUnmanaged(u8) = .empty,
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .empty,
dynsym: DynsymSection = .{},
dynstrtab: std.ArrayListUnmanaged(u8) = .empty,
versym: std.ArrayListUnmanaged(elf.Elf64_Versym) = .{},
verneed: VerneedSection = .{},

dynamic: DynamicSection = .{},
hash: HashSection = .{},
gnu_hash: GnuHashSection = .{},
got: GotSection = .{},
plt: PltSection = .{},
got_plt: GotPltSection = .{},
plt_got: PltGotSection = .{},
copy_rel: CopyRelSection = .{},
rela_dyn: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},
rela_plt: std.ArrayListUnmanaged(elf.Elf64_Rela) = .{},
comdat_group_sections: std.ArrayListUnmanaged(ComdatGroupSection) = .{},

thunks: std.ArrayListUnmanaged(Thunk) = .{},

merge_sections: std.ArrayListUnmanaged(MergeSection) = .{},
merge_subsections: std.ArrayListUnmanaged(MergeSubsection) = .{},

has_text_reloc: bool = false,
num_ifunc_dynrelocs: usize = 0,
default_sym_version: elf.Elf64_Versym,

first_eflags: ?elf.Elf64_Word = null,

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
        .options = options,
        .default_sym_version = if (self.options.shared or options.export_dynamic)
            elf.VER_NDX_GLOBAL
        else
            elf.VER_NDX_LOCAL,
    };

    return self;
}

pub fn deinit(self: *Elf) void {
    const gpa = self.base.allocator;
    self.shstrtab.deinit(gpa);
    self.symtab.deinit(gpa);
    self.strtab.deinit(gpa);
    for (self.thunks.items) |*thunk| {
        thunk.deinit(gpa);
    }
    self.thunks.deinit(gpa);
    for (self.merge_sections.items) |*sect| {
        sect.deinit(gpa);
    }
    self.merge_sections.deinit(gpa);
    self.merge_subsections.deinit(gpa);
    self.resolver.deinit(gpa);
    self.got.deinit(gpa);
    self.plt.deinit(gpa);
    self.plt_got.deinit(gpa);
    self.phdrs.deinit(gpa);
    for (self.sections.items(.atoms)) |*atoms| {
        atoms.deinit(gpa);
    }
    self.sections.deinit(gpa);

    for (self.file_handles.items) |file| {
        file.close();
    }
    self.file_handles.deinit(gpa);

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
    self.comdat_group_sections.deinit(gpa);
    for (self.undefs.values()) |*value| {
        value.deinit(gpa);
    }
    self.undefs.deinit(gpa);
    for (self.dupes.values()) |*value| {
        value.deinit(gpa);
    }
    self.dupes.deinit(gpa);
}

fn resolveFile(
    self: *Elf,
    arena: Allocator,
    obj: LinkObject,
    search_dirs: []const []const u8,
) !LinkObject {
    const GetFullPath = struct {
        const Tag = enum {
            dso,
            ar,
            none,
        };

        pub fn getFullPath(alloc: Allocator, dir: []const u8, path: []const u8, comptime tag: Tag) !?[]const u8 {
            const suffix_str = switch (tag) {
                .dso => "lib{s}.so",
                .ar => "lib{s}.a",
                .none => "{s}",
            };
            const full_path = try std.fmt.allocPrint(alloc, "{s}" ++ std.fs.path.sep_str ++ suffix_str, .{
                dir,
                path,
            });
            const tmp = fs.cwd().openFile(full_path, .{}) catch return null;
            defer tmp.close();
            return full_path;
        }
    };
    const getFullPath = GetFullPath.getFullPath;

    const full_path = full_path: {
        if (mem.startsWith(u8, obj.path, "-l")) {
            const path = obj.path["-l".len..];
            for (search_dirs) |search_dir| {
                if (!obj.static) {
                    if (try getFullPath(arena, search_dir, path, .dso)) |full_path| break :full_path full_path;
                }
                if (try getFullPath(arena, search_dir, path, .ar)) |full_path| break :full_path full_path;
            }
            self.base.fatal("library not found '{s}'", .{path});
            return error.FileNotFound;
        }

        const path = path: {
            var buffer: [fs.max_path_bytes]u8 = undefined;
            const path = std.fs.realpath(obj.path, &buffer) catch |err| switch (err) {
                error.FileNotFound => {
                    for (search_dirs) |search_dir| {
                        if (try getFullPath(arena, search_dir, obj.path, .none)) |path| break :path path;
                    }
                    self.base.fatal("file not found '{s}'", .{obj.path});
                    return error.FileNotFound;
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

pub fn flush(self: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    // Append empty string to string tables.
    try self.shstrtab.append(gpa, 0);
    try self.strtab.append(gpa, 0);
    try self.dynstrtab.append(gpa, 0);
    // Append null section.
    _ = try self.addSection(.{});
    // Append null symbol.
    try self.symtab.append(gpa, null_sym);
    // Append null file.
    try self.files.append(gpa, .null);

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    log.debug("search dirs", .{});
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
        log.debug("  -L{s}", .{dir});
    }

    var has_parse_error = false;
    for (self.options.positionals) |obj| {
        self.parsePositional(arena, obj, search_dirs.items) catch |err| {
            has_parse_error = true;
            switch (err) {
                error.MismatchedCpuArch,
                error.MismatchedEflags,
                error.FileNotFound,
                error.ParseFailed,
                => {}, // already reported
                else => |e| {
                    self.base.fatal("{s}: unexpected error occurred while parsing input file: {s}", .{
                        obj.path, @errorName(e),
                    });
                    return e;
                },
            }
        };
    }

    if (has_parse_error) {
        const err = try self.base.addErrorWithNotes(search_dirs.items.len);
        try err.addMsg("library search paths", .{});
        for (search_dirs.items) |dir| {
            try err.addNote("  {s}", .{dir});
        }
        return error.ParseFailed;
    }

    // Dedup DSOs
    {
        var seen_dsos = std.StringHashMap(void).init(gpa);
        defer seen_dsos.deinit();
        try seen_dsos.ensureTotalCapacity(@as(u32, @intCast(self.shared_objects.items.len)));

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
        const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object_index = index;
        const object = self.getInternalObject().?;
        try object.init(gpa);
        try object.initSymbols(self);
    }

    try self.resolveSymbols();
    self.markEhFrameAtomsDead();
    try self.resolveMergeSections();

    if (self.options.relocatable) return relocatable.flush(self);

    try self.convertCommonSymbols();
    try self.markImportsAndExports();

    if (self.options.gc_sections) {
        try gc.gcAtoms(self);

        if (self.options.print_gc_sections) {
            try gc.dumpPrunedAtoms(self);
        }
    }

    if (!self.options.allow_multiple_definition) {
        try self.checkDuplicates();
    }

    try self.addCommentString();
    try self.finalizeMergeSections();
    try self.initOutputSections();

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

    try self.initSyntheticSections();
    try self.sortSections();
    try self.addAtomsToSections();
    try self.sortInitFini();
    try self.setDynamic();
    self.setDynsym();
    try self.setHashes();
    try self.setVerSymtab();
    try self.calcMergeSectionSizes();
    try self.calcSectionSizes();

    try self.allocateSections();

    self.shoff = blk: {
        const shdr = self.sections.items(.shdr)[self.sections.len - 1];
        const offset = shdr.sh_offset + shdr.sh_size;
        break :blk mem.alignForward(u64, offset, @alignOf(elf.Elf64_Shdr));
    };

    state_log.debug("{}", .{self.dumpState()});

    try self.writeAtoms();
    try self.writeMergeSections();
    try self.writeSyntheticSections();
    try self.writePhdrs();
    try self.writeShdrs();
    try self.writeHeader();
}

/// We need to sort constructors/destuctors in the following sections:
/// * .init_array
/// * .fini_array
/// * .preinit_array
/// * .ctors
/// * .dtors
/// The prority of inclusion is defined as part of the input section's name. For example, .init_array.10000.
/// If no priority value has been specified,
/// * for .init_array, .fini_array and .preinit_array, we automatically assign that section max value of maxInt(i32)
///   and push it to the back of the queue,
/// * for .ctors and .dtors, we automatically assign that section min value of -1
///   and push it to the front of the queue,
/// crtbegin and ctrend are assigned minInt(i32) and maxInt(i32) respectively.
/// Ties are broken by the file prority which corresponds to the inclusion of input sections in this output section
/// we are about to sort.
fn sortInitFini(self: *Elf) !void {
    const gpa = self.base.allocator;

    const Entry = struct {
        priority: i32,
        atom_ref: Elf.Ref,

        pub fn lessThan(ctx: *Elf, lhs: @This(), rhs: @This()) bool {
            if (lhs.priority == rhs.priority) {
                return ctx.getAtom(lhs.atom_ref).?.getPriority(ctx) < ctx.getAtom(rhs.atom_ref).?.getPriority(ctx);
            }
            return lhs.priority < rhs.priority;
        }
    };

    for (self.sections.items(.shdr), 0..) |shdr, shndx| {
        if (!shdrIsAlloc(shdr)) continue;

        var is_init_fini = false;
        var is_ctor_dtor = false;
        switch (shdr.sh_type) {
            elf.SHT_PREINIT_ARRAY,
            elf.SHT_INIT_ARRAY,
            elf.SHT_FINI_ARRAY,
            => is_init_fini = true,
            else => {
                const name = self.getShString(shdr.sh_name);
                is_ctor_dtor = mem.indexOf(u8, name, ".ctors") != null or mem.indexOf(u8, name, ".dtors") != null;
            },
        }

        if (!is_init_fini and !is_ctor_dtor) continue;

        const atoms = &self.sections.items(.atoms)[shndx];

        var entries = std.ArrayList(Entry).init(gpa);
        try entries.ensureTotalCapacityPrecise(atoms.items.len);
        defer entries.deinit();

        for (atoms.items) |ref| {
            const atom = self.getAtom(ref).?;
            const file = atom.getObject(self);
            const priority = blk: {
                if (is_ctor_dtor) {
                    if (mem.indexOf(u8, file.path, "crtbegin") != null) break :blk std.math.minInt(i32);
                    if (mem.indexOf(u8, file.path, "crtend") != null) break :blk std.math.maxInt(i32);
                }
                const default: i32 = if (is_ctor_dtor) -1 else std.math.maxInt(i32);
                const name = atom.getName(self);
                var it = mem.splitBackwardsScalar(u8, name, '.');
                const priority = std.fmt.parseUnsigned(u16, it.first(), 10) catch default;
                break :blk priority;
            };
            entries.appendAssumeCapacity(.{ .priority = priority, .atom_ref = ref });
        }

        mem.sort(Entry, entries.items, self, Entry.lessThan);

        atoms.clearRetainingCapacity();
        for (entries.items) |entry| {
            atoms.appendAssumeCapacity(entry.atom_ref);
        }
    }
}

fn initOutputSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms_indexes.items) |atom_index| {
            const atom = object.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_shndx = try object.initOutputSection(self, atom.getInputShdr(self));
        }
    }

    for (self.merge_sections.items) |*msec| {
        if (msec.subsections.items.len == 0) continue;
        const shndx = self.getSectionByName(msec.getName(self)) orelse try self.addSection(.{
            .name = msec.name,
            .type = msec.type,
            .flags = msec.flags,
        });
        msec.out_shndx = shndx;

        var entsize = self.getMergeSubsection(msec.subsections.items[0]).entsize;
        for (msec.subsections.items) |index| {
            const msub = self.getMergeSubsection(index);
            entsize = @min(entsize, msub.entsize);
        }
        const shdr = &self.sections.items(.shdr)[shndx];
        shdr.sh_entsize = entsize;
    }

    self.text_sect_index = self.getSectionByName(".text");
}

fn initSyntheticSections(self: *Elf) !void {
    const needs_eh_frame = for (self.objects.items) |index| {
        if (self.getFile(index).?.object.cies.items.len > 0) break true;
    } else false;
    if (needs_eh_frame) {
        self.eh_frame_sect_index = try self.addSection(.{
            .name = try self.insertShString(".eh_frame"),
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC,
            .addralign = @alignOf(u64),
        });

        if (self.options.eh_frame_hdr) {
            self.eh_frame_hdr_sect_index = try self.addSection(.{
                .name = try self.insertShString(".eh_frame_hdr"),
                .type = elf.SHT_PROGBITS,
                .flags = elf.SHF_ALLOC,
                .addralign = @alignOf(u32),
            });
        }
    }

    if (self.got.entries.items.len > 0) {
        self.got_sect_index = try self.addSection(.{
            .name = try self.insertShString(".got"),
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .addralign = @alignOf(u64),
        });
    }

    self.got_plt_sect_index = try self.addSection(.{
        .name = try self.insertShString(".got.plt"),
        .type = elf.SHT_PROGBITS,
        .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
        .addralign = @alignOf(u64),
    });

    const needs_rela_dyn = blk: {
        if (self.got.flags.needs_rela or self.got.flags.needs_tlsld or
            self.copy_rel.symbols.items.len > 0) break :blk true;
        for (self.objects.items) |index| {
            if (self.getFile(index).?.object.num_dynrelocs > 0) break :blk true;
        }
        break :blk false;
    };
    if (needs_rela_dyn) {
        self.rela_dyn_sect_index = try self.addSection(.{
            .name = try self.insertShString(".rela.dyn"),
            .type = elf.SHT_RELA,
            .flags = elf.SHF_ALLOC,
            .addralign = @alignOf(elf.Elf64_Rela),
            .entsize = @sizeOf(elf.Elf64_Rela),
        });
    }

    if (self.plt.symbols.items.len > 0) {
        self.plt_sect_index = try self.addSection(.{
            .name = try self.insertShString(".plt"),
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR,
            .addralign = 16,
        });
        self.rela_plt_sect_index = try self.addSection(.{
            .name = try self.insertShString(".rela.plt"),
            .type = elf.SHT_RELA,
            .flags = elf.SHF_ALLOC,
            .addralign = @alignOf(elf.Elf64_Rela),
            .entsize = @sizeOf(elf.Elf64_Rela),
        });
    }

    if (self.plt_got.symbols.items.len > 0) {
        self.plt_got_sect_index = try self.addSection(.{
            .name = try self.insertShString(".plt.got"),
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR,
            .addralign = 16,
        });
    }

    if (self.copy_rel.symbols.items.len > 0) {
        self.copy_rel_sect_index = try self.addSection(.{
            .name = try self.insertShString(".copyrel"),
            .type = elf.SHT_NOBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
        });
    }

    try self.initShStrtab();

    if (!self.options.strip_all) {
        try self.initSymtab();
    }

    const needs_interp = blk: {
        // On Ubuntu with musl-gcc, we get a weird combo of options looking like this:
        // -dynamic-linker=<path> -static
        // In this case, if we do generate .interp section and segment, we will get
        // a segfault in the dynamic linker trying to load a binary that is static
        // and doesn't contain .dynamic section.
        if (self.options.static and !self.options.pie) break :blk false;
        break :blk self.options.dynamic_linker != null;
    };
    if (needs_interp) {
        self.interp_sect_index = try self.addSection(.{
            .name = try self.insertShString(".interp"),
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC,
            .addralign = 1,
        });
    }

    if (self.options.shared or self.shared_objects.items.len > 0 or self.options.pie) {
        self.dynstrtab_sect_index = try self.addSection(.{
            .name = try self.insertShString(".dynstr"),
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_STRTAB,
            .entsize = 1,
            .addralign = 1,
        });
        self.dynamic_sect_index = try self.addSection(.{
            .name = try self.insertShString(".dynamic"),
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .type = elf.SHT_DYNAMIC,
            .entsize = @sizeOf(elf.Elf64_Dyn),
            .addralign = @alignOf(elf.Elf64_Dyn),
        });
        self.dynsymtab_sect_index = try self.addSection(.{
            .name = try self.insertShString(".dynsym"),
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_DYNSYM,
            .addralign = @alignOf(elf.Elf64_Sym),
            .entsize = @sizeOf(elf.Elf64_Sym),
        });
        self.hash_sect_index = try self.addSection(.{
            .name = try self.insertShString(".hash"),
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_HASH,
            .addralign = 4,
            .entsize = 4,
        });
        self.gnu_hash_sect_index = try self.addSection(.{
            .name = try self.insertShString(".gnu.hash"),
            .flags = elf.SHF_ALLOC,
            .type = elf.SHT_GNU_HASH,
            .addralign = 8,
        });

        const needs_versions = for (self.dynsym.entries.items) |dynsym| {
            const symbol = self.getSymbol(dynsym.ref).?;
            if (symbol.flags.import and symbol.ver_idx & elf.VERSYM_VERSION > elf.VER_NDX_GLOBAL) break true;
        } else false;
        if (needs_versions) {
            self.versym_sect_index = try self.addSection(.{
                .name = try self.insertShString(".gnu.version"),
                .flags = elf.SHF_ALLOC,
                .type = elf.SHT_GNU_VERSYM,
                .addralign = @alignOf(elf.Elf64_Versym),
                .entsize = @sizeOf(elf.Elf64_Versym),
            });
            self.verneed_sect_index = try self.addSection(.{
                .name = try self.insertShString(".gnu.version_r"),
                .flags = elf.SHF_ALLOC,
                .type = elf.SHT_GNU_VERNEED,
                .addralign = @alignOf(elf.Elf64_Verneed),
            });
        }
    }
}

pub fn initSymtab(self: *Elf) !void {
    self.strtab_sect_index = try self.addSection(.{
        .name = try self.insertShString(".strtab"),
        .type = elf.SHT_STRTAB,
        .entsize = 1,
        .addralign = 1,
    });
    self.symtab_sect_index = try self.addSection(.{
        .name = try self.insertShString(".symtab"),
        .type = elf.SHT_SYMTAB,
        .addralign = @alignOf(elf.Elf64_Sym),
        .entsize = @sizeOf(elf.Elf64_Sym),
    });
}

pub fn initShStrtab(self: *Elf) !void {
    self.shstrtab_sect_index = try self.addSection(.{
        .name = try self.insertShString(".shstrtab"),
        .type = elf.SHT_STRTAB,
        .entsize = 1,
        .addralign = 1,
    });
}

pub fn addAtomsToSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms_indexes.items) |atom_index| {
            const atom = object.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_shndx];
            try atoms.append(self.base.allocator, .{
                .index = atom_index,
                .file = index,
            });
        }
    }
}

pub fn addCommentString(self: *Elf) !void {
    const msec_index = try self.getOrCreateMergeSection(".comment", elf.SHF_MERGE | elf.SHF_STRINGS, elf.SHT_PROGBITS);
    const msec = self.getMergeSection(msec_index);
    const res = try msec.insertZ(self.base.allocator, Options.version);
    if (res.found_existing) return;
    const msub_index = try self.addMergeSubsection();
    const msub = self.getMergeSubsection(msub_index);
    msub.merge_section = msec_index;
    msub.string_index = res.key.pos;
    msub.alignment = 0;
    msub.size = res.key.len;
    msub.entsize = 1;
    msub.alive = true;
    res.sub.* = msub_index;
}

pub fn finalizeMergeSections(self: *Elf) !void {
    for (self.merge_sections.items) |*msec| {
        try msec.finalize(self);
    }
}

pub fn calcMergeSectionSizes(self: *Elf) !void {
    for (self.merge_sections.items) |*msec| {
        const shdr = &self.sections.items(.shdr)[msec.out_shndx];
        for (msec.subsections.items) |msub_index| {
            const msub = self.getMergeSubsection(msub_index);
            assert(msub.alive);
            const alignment = try math.powi(u64, 2, msub.alignment);
            const offset = mem.alignForward(u64, shdr.sh_size, alignment);
            const padding = offset - shdr.sh_size;
            msub.value = @intCast(offset);
            shdr.sh_size += padding + msub.size;
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
        }
    }
}

fn calcSectionSizes(self: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const slice = self.sections.slice();

    for (slice.items(.shdr), slice.items(.atoms)) |*shdr, atoms| {
        if (atoms.items.len == 0) continue;
        if (self.requiresThunks() and shdr.sh_flags & elf.SHF_EXECINSTR != 0) continue;

        for (atoms.items) |ref| {
            const atom = self.getAtom(ref).?;
            const alignment = try math.powi(u64, 2, atom.alignment);
            const offset = mem.alignForward(u64, shdr.sh_size, alignment);
            const padding = offset - shdr.sh_size;
            atom.value = @intCast(offset);
            shdr.sh_size += padding + atom.size;
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
        }
    }

    if (self.requiresThunks()) {
        for (slice.items(.shdr), slice.items(.atoms), 0..) |shdr, atoms, i| {
            if (shdr.sh_flags & elf.SHF_EXECINSTR == 0) continue;
            if (atoms.items.len == 0) continue;

            // Create jump/branch range extenders if needed.
            try self.createThunks(@intCast(i));
        }
    }

    if (self.eh_frame_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = try eh_frame.calcEhFrameSize(self);
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
        shdr.sh_size = self.plt.size(self);
        shdr.sh_addralign = 16;
    }

    if (self.got_plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.got_plt.size(self);
        shdr.sh_addralign = @alignOf(u64);
    }

    if (self.plt_got_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.plt_got.size(self);
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
        shdr.sh_size = self.dynstrtab.items.len;
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
        shdr.sh_size = self.shstrtab.items.len;
    }
}

pub fn calcSymtabSize(self: *Elf) !void {
    if (self.options.strip_all) return;

    var nlocals: u32 = 0;
    var nglobals: u32 = 0;
    var strsize: u32 = 0;

    const gpa = self.base.allocator;
    var files = std.ArrayList(File.Index).init(gpa);
    defer files.deinit();
    try files.ensureTotalCapacityPrecise(self.objects.items.len + self.shared_objects.items.len + 1);
    for (self.objects.items) |index| files.appendAssumeCapacity(index);
    for (self.shared_objects.items) |index| files.appendAssumeCapacity(index);
    if (self.internal_object_index) |index| files.appendAssumeCapacity(index);

    // Section symbols
    const isMergeSection = struct {
        fn isMergeSection(ctx: *Elf, index: usize) bool {
            for (ctx.merge_sections.items) |msec| {
                if (msec.out_shndx == index) return true;
            }
            return false;
        }
    }.isMergeSection;

    for (self.sections.items(.atoms), self.sections.items(.sym_index), 0..) |atoms, *sym_index, index| {
        if (atoms.items.len == 0 and !isMergeSection(self, index)) continue;
        sym_index.* = nlocals + 1;
        nlocals += 1;
    }
    if (self.eh_frame_sect_index) |shndx| {
        self.sections.items(.sym_index)[shndx] = nlocals + 1;
        nlocals += 1;
    }

    for (self.thunks.items) |*thunk| {
        thunk.output_symtab_ctx.ilocal = nlocals + 1;
        thunk.calcSymtabSize(self);
        nlocals += thunk.output_symtab_ctx.nlocals;
        strsize += thunk.output_symtab_ctx.strsize;
    }

    for (files.items) |index| {
        const file = self.getFile(index).?;
        const ctx = switch (file) {
            inline else => |x| &x.output_symtab_ctx,
        };
        ctx.ilocal = nlocals + 1;
        ctx.iglobal = nglobals + 1;
        try file.calcSymtabSize(self);
        nlocals += ctx.nlocals;
        nglobals += ctx.nglobals;
        strsize += ctx.strsize;
    }

    if (self.got_sect_index) |_| {
        self.got.output_symtab_ctx.ilocal = nlocals + 1;
        self.got.calcSymtabSize(self);
        nlocals += self.got.output_symtab_ctx.nlocals;
        strsize += self.got.output_symtab_ctx.strsize;
    }

    if (self.plt_sect_index) |_| {
        self.plt.output_symtab_ctx.ilocal = nlocals + 1;
        self.plt.calcSymtabSize(self);
        nlocals += self.plt.output_symtab_ctx.nlocals;
        strsize += self.plt.output_symtab_ctx.strsize;
    }

    if (self.plt_got_sect_index) |_| {
        self.plt_got.output_symtab_ctx.ilocal = nlocals + 1;
        self.plt_got.calcSymtabSize(self);
        nlocals += self.plt_got.output_symtab_ctx.nlocals;
        strsize += self.plt_got.output_symtab_ctx.strsize;
    }

    for (files.items) |index| {
        const file = self.getFile(index).?;
        const ctx = switch (file) {
            inline else => |x| &x.output_symtab_ctx,
        };
        ctx.iglobal += nlocals;
    }

    {
        const shdr = &self.sections.items(.shdr)[self.symtab_sect_index.?];
        shdr.sh_info = nlocals + 1;
        shdr.sh_link = self.strtab_sect_index.?;
        shdr.sh_size = (nlocals + 1 + nglobals) * @sizeOf(elf.Elf64_Sym);
    }
    {
        const shdr = &self.sections.items(.shdr)[self.strtab_sect_index.?];
        shdr.sh_size = strsize + 1;
    }
}

pub fn writeSymtab(self: *Elf) !void {
    if (self.options.strip_all) return;

    const gpa = self.base.allocator;
    const symtab_shdr = self.sections.items(.shdr)[self.symtab_sect_index.?];
    const strtab_shdr = self.sections.items(.shdr)[self.strtab_sect_index.?];

    const nsyms = @divExact(symtab_shdr.sh_size, @sizeOf(elf.Elf64_Sym));
    try self.symtab.resize(gpa, nsyms);

    const needed_strtab_size = strtab_shdr.sh_size - 1;
    try self.strtab.ensureUnusedCapacity(gpa, needed_strtab_size);

    self.writeSectionSymbols();

    for (self.thunks.items) |thunk| {
        thunk.writeSymtab(self);
    }

    for (self.objects.items) |index| {
        self.getFile(index).?.writeSymtab(self);
    }

    for (self.shared_objects.items) |index| {
        self.getFile(index).?.writeSymtab(self);
    }

    if (self.internal_object_index) |index| {
        self.getFile(index).?.writeSymtab(self);
    }

    if (self.got_sect_index) |_| {
        self.got.writeSymtab(self);
    }

    if (self.plt_sect_index) |_| {
        self.plt.writeSymtab(self);
    }

    if (self.plt_got_sect_index) |_| {
        self.plt_got.writeSymtab(self);
    }

    try self.base.file.pwriteAll(mem.sliceAsBytes(self.symtab.items), symtab_shdr.sh_offset);
    try self.base.file.pwriteAll(self.strtab.items, strtab_shdr.sh_offset);
}

fn writeSectionSymbols(self: *Elf) void {
    for (self.sections.items(.shdr), self.sections.items(.sym_index), 0..) |shdr, sym_index, shndx| {
        if (sym_index == 0) continue;
        const out_sym = &self.symtab.items[sym_index];
        out_sym.* = .{
            .st_name = 0,
            .st_value = shdr.sh_addr,
            .st_info = elf.STT_SECTION,
            .st_shndx = @intCast(shndx),
            .st_size = 0,
            .st_other = 0,
        };
    }
}

fn initPhdrs(self: *Elf) !void {
    // Add PHDR phdr
    const phdr_index = try self.addPhdr(.{
        .type = elf.PT_PHDR,
        .flags = elf.PF_R,
        .@"align" = @alignOf(elf.Elf64_Phdr),
        .addr = self.options.image_base + @sizeOf(elf.Elf64_Ehdr),
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

    const slice = self.sections.slice();

    // Add LOAD phdrs
    {
        var sorted = try std.ArrayList(elf.Elf64_Shdr).initCapacity(self.base.allocator, slice.len);
        defer sorted.deinit();

        for (slice.items(.shdr)) |shdr| {
            if (!shdrIsAlloc(shdr) or shdrIsTbss(shdr)) continue;
            sorted.appendAssumeCapacity(shdr);
        }

        const sortShdr = struct {
            fn lessThan(ctx: void, lhs: elf.Elf64_Shdr, rhs: elf.Elf64_Shdr) bool {
                _ = ctx;
                return lhs.sh_addr < rhs.sh_addr;
            }
        }.lessThan;
        mem.sort(elf.Elf64_Shdr, sorted.items, {}, sortShdr);

        var is_phdr_included = false;
        var shndx: usize = 0;
        while (shndx < sorted.items.len) {
            const shdr = sorted.items[shndx];
            const p_flags = shdrToPhdrFlags(shdr.sh_flags);
            const phndx = try self.addPhdr(.{
                .type = elf.PT_LOAD,
                .flags = p_flags,
                .@"align" = @max(self.options.page_size.?, shdr.sh_addralign),
                .offset = shdr.sh_offset,
                .addr = shdr.sh_addr,
            });
            if (!is_phdr_included and p_flags == elf.PF_R) {
                const phdr = &self.phdrs.items[phndx];
                phdr.p_offset = 0;
                phdr.p_vaddr = self.options.image_base;
                phdr.p_paddr = phdr.p_vaddr;
                is_phdr_included = true;
            }
            try self.addShdrToPhdr(phndx, shdr);
            shndx += 1;

            while (shndx < sorted.items.len) : (shndx += 1) {
                const next = sorted.items[shndx];
                if (p_flags == shdrToPhdrFlags(next.sh_flags)) {
                    if (shdrIsBss(next) or
                        (next.sh_offset > shdr.sh_offset and next.sh_addr > shdr.sh_addr and
                        next.sh_offset - shdr.sh_offset == next.sh_addr - shdr.sh_addr))
                    {
                        try self.addShdrToPhdr(phndx, next);
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
            const shdr = slice.items(.shdr)[shndx];
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
                const next = slice.items(.shdr)[shndx];
                if (!shdrIsTls(next)) continue :outer;
                try self.addShdrToPhdr(self.tls_phdr_index.?, next);
            }
        }

        if (self.tls_phdr_index == null and self.options.static) {
            // Even if we don't emit any TLS data, linking against musl-libc without
            // empty TLS phdr leads to a bizarre segfault in `__copy_tls` function.
            // So far I haven't been able to work out why that is, but adding an empty
            // TLS phdr seems to fix it, so let's go with it for now.
            // TODO try to investigate more
            self.tls_phdr_index = try self.addPhdr(.{
                .type = elf.PT_TLS,
                .flags = elf.PF_R,
                .@"align" = 1,
            });
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

    // Backpatch size of the PHDR phdr and possibly RO segment that holds it
    {
        const phdr = &self.phdrs.items[phdr_index];
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

inline fn shdrIsAlloc(shdr: elf.Elf64_Shdr) bool {
    return shdr.sh_flags & elf.SHF_ALLOC != 0;
}

inline fn shdrIsBss(shdr: elf.Elf64_Shdr) bool {
    return shdrIsZerofill(shdr) and !shdrIsTls(shdr);
}

inline fn shdrIsTbss(shdr: elf.Elf64_Shdr) bool {
    return shdrIsZerofill(shdr) and shdrIsTls(shdr);
}

pub inline fn shdrIsZerofill(shdr: elf.Elf64_Shdr) bool {
    return shdr.sh_type == elf.SHT_NOBITS;
}

pub inline fn shdrIsTls(shdr: elf.Elf64_Shdr) bool {
    return shdr.sh_flags & elf.SHF_TLS != 0;
}

fn allocateSectionsInMemory(self: *Elf, base_offset: u64) !void {
    const shdrs = self.sections.slice().items(.shdr)[1..];

    // We use this struct to track maximum alignment of all TLS sections.
    // According to https://github.com/rui314/mold/commit/bd46edf3f0fe9e1a787ea453c4657d535622e61f in mold,
    // in-file offsets have to be aligned against the start of TLS program header.
    // If that's not ensured, then in a multi-threaded context, TLS variables across a shared object
    // boundary may not get correctly loaded at an aligned address.
    const Align = struct {
        tls_start_align: u64 = 1,
        first_tls_index: ?usize = null,

        inline fn isFirstTlsShdr(this: @This(), other: usize) bool {
            if (this.first_tls_index) |index| return index == other;
            return false;
        }

        inline fn @"align"(this: @This(), index: usize, sh_addralign: u64, addr: u64) u64 {
            const alignment = if (this.isFirstTlsShdr(index)) this.tls_start_align else sh_addralign;
            return mem.alignForward(u64, addr, alignment);
        }
    };

    var alignment = Align{};
    for (shdrs, 0..) |shdr, i| {
        if (!shdrIsTls(shdr)) continue;
        if (alignment.first_tls_index == null) alignment.first_tls_index = i;
        alignment.tls_start_align = @max(alignment.tls_start_align, shdr.sh_addralign);
    }

    var addr = self.options.image_base + base_offset;
    var i: usize = 0;
    while (i < shdrs.len) : (i += 1) {
        const shdr = &shdrs[i];
        const name = self.getShString(shdr.sh_name);
        if (!shdrIsAlloc(shdr.*)) continue;
        if (self.options.section_start.get(name)) |sh_addr| {
            addr = sh_addr;
            shdr.sh_addr = addr;
            addr += shdr.sh_size;
            continue;
        }
        if (i > 0) {
            const prev_shdr = shdrs[i - 1];
            if (shdrToPhdrFlags(shdr.sh_flags) != shdrToPhdrFlags(prev_shdr.sh_flags)) {
                // We need to advance by page size
                addr += self.options.page_size.?;
            }
        }
        if (shdrIsTbss(shdr.*)) {
            // .tbss is a little special as it's used only by the loader meaning it doesn't
            // need to be actually mmap'ed at runtime. We still need to correctly increment
            // the addresses of every TLS zerofill section tho. Thus, we hack it so that
            // we increment the start address like normal, however, after we are done,
            // the next ALLOC section will get its start address allocated within the same
            // range as the .tbss sections. We will get something like this:
            //
            // ...
            // .tbss 0x10
            // .tcommon 0x20
            // .data 0x10
            // ...
            var tbss_addr = addr;
            while (i < shdrs.len and shdrIsTbss(shdrs[i])) : (i += 1) {
                const tbss_shdr = &shdrs[i];
                tbss_addr = alignment.@"align"(i, tbss_shdr.sh_addralign, tbss_addr);
                tbss_shdr.sh_addr = tbss_addr;
                tbss_addr += tbss_shdr.sh_size;
            }
            i -= 1;
            continue;
        }

        addr = alignment.@"align"(i, shdr.sh_addralign, addr);
        shdr.sh_addr = addr;
        addr += shdr.sh_size;
    }
}

fn allocateSectionsInFile(self: *Elf, base_offset: u64) void {
    const page_size = self.options.page_size.?;
    const shdrs = self.sections.slice().items(.shdr)[1..];

    var offset = base_offset;
    var i: usize = 0;
    while (i < shdrs.len) {
        const first = &shdrs[i];
        defer if (!shdrIsAlloc(first.*) or shdrIsZerofill(first.*)) {
            i += 1;
        };

        // Non-alloc sections don't need congruency with their allocated virtual memory addresses
        if (!shdrIsAlloc(first.*)) {
            first.sh_offset = mem.alignForward(u64, offset, first.sh_addralign);
            offset = first.sh_offset + first.sh_size;
            continue;
        }
        // Skip any zerofill section
        if (shdrIsZerofill(first.*)) continue;

        // Set the offset to a value that is congruent with the section's allocated virtual memory address
        if (first.sh_addralign > page_size) {
            offset = mem.alignForward(u64, offset, first.sh_addralign);
        } else {
            const val = mem.alignBackward(u64, offset, page_size) + @rem(first.sh_addr, page_size);
            offset = if (offset <= val) val else val + page_size;
        }

        while (true) {
            const prev = &shdrs[i];
            prev.sh_offset = offset + prev.sh_addr - first.sh_addr;
            i += 1;

            const next = shdrs[i];
            if (i >= shdrs.len or !shdrIsAlloc(next) or shdrIsZerofill(next)) break;
            if (next.sh_addr < first.sh_addr) break;

            const gap = next.sh_addr - prev.sh_addr - prev.sh_size;
            if (gap >= page_size) break;
        }

        const prev = &shdrs[i - 1];
        offset = prev.sh_offset + prev.sh_size;

        // Skip any zerofill section
        while (i < shdrs.len and shdrIsAlloc(shdrs[i]) and shdrIsZerofill(shdrs[i])) : (i += 1) {}
    }
}

fn allocateSections(self: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    while (true) {
        const nphdrs = self.phdrs.items.len;
        const base_offset: u64 = @sizeOf(elf.Elf64_Ehdr) + nphdrs * @sizeOf(elf.Elf64_Phdr);
        try self.allocateSectionsInMemory(base_offset);
        self.allocateSectionsInFile(base_offset);
        self.phdrs.clearRetainingCapacity();
        try self.initPhdrs();
        if (nphdrs == self.phdrs.items.len) break;
    }
}

fn getSectionRank(self: *Elf, shndx: u32) u8 {
    const shdr = self.sections.items(.shdr)[shndx];
    const name = self.getShString(shdr.sh_name);
    const flags = shdr.sh_flags;
    const rank: u8 = switch (shdr.sh_type) {
        elf.SHT_NULL => 0,
        elf.SHT_DYNSYM => 2,
        elf.SHT_HASH => 3,
        elf.SHT_GNU_HASH => 3,
        elf.SHT_GNU_VERSYM => 4,
        elf.SHT_GNU_VERDEF => 4,
        elf.SHT_GNU_VERNEED => 4,

        elf.SHT_PREINIT_ARRAY,
        elf.SHT_INIT_ARRAY,
        elf.SHT_FINI_ARRAY,
        => 0xf2,

        elf.SHT_DYNAMIC => 0xf3,

        elf.SHT_RELA, elf.SHT_GROUP => 0xf,

        elf.SHT_PROGBITS => if (flags & elf.SHF_ALLOC != 0) blk: {
            if (flags & elf.SHF_EXECINSTR != 0) {
                break :blk 0xf1;
            } else if (flags & elf.SHF_WRITE != 0) {
                break :blk if (flags & elf.SHF_TLS != 0) 0xf4 else 0xf6;
            } else if (mem.eql(u8, name, ".interp")) {
                break :blk 1;
            } else {
                break :blk 0xf0;
            }
        } else if (mem.startsWith(u8, name, ".debug"))
            0xf8
        else
            0xf9,

        elf.SHT_NOBITS => if (flags & elf.SHF_TLS != 0) 0xf5 else 0xf7,
        elf.SHT_SYMTAB => 0xfa,
        elf.SHT_STRTAB => if (mem.eql(u8, name, ".dynstr")) 4 else 0xfb,
        else => 0xff,
    };
    return rank;
}

pub fn sortSections(self: *Elf) !void {
    const Entry = struct {
        shndx: u32,

        pub fn lessThan(elf_file: *Elf, lhs: @This(), rhs: @This()) bool {
            return elf_file.getSectionRank(lhs.shndx) < elf_file.getSectionRank(rhs.shndx);
        }
    };

    const gpa = self.base.allocator;

    var entries = try std.ArrayList(Entry).initCapacity(gpa, self.sections.slice().len);
    defer entries.deinit();
    for (0..self.sections.slice().len) |shndx| {
        entries.appendAssumeCapacity(.{ .shndx = @intCast(shndx) });
    }

    mem.sort(Entry, entries.items, self, Entry.lessThan);

    const backlinks = try gpa.alloc(u32, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.shndx] = @intCast(i);
    }

    var slice = self.sections.toOwnedSlice();
    defer slice.deinit(gpa);

    try self.sections.ensureTotalCapacity(gpa, slice.len);
    for (entries.items) |sorted| {
        var out_shdr = slice.get(sorted.shndx);
        out_shdr.rela_shndx = backlinks[out_shdr.rela_shndx];
        self.sections.appendAssumeCapacity(out_shdr);
    }

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms_indexes.items) |atom_index| {
            const atom = object.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_shndx = backlinks[atom.out_shndx];
        }
    }

    for (self.merge_sections.items) |*msec| {
        msec.out_shndx = backlinks[msec.out_shndx];
    }

    for (&[_]*?u32{
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
        shdr.sh_link = self.dynsymtab_sect_index orelse 0;
    }

    if (self.rela_plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_link = self.dynsymtab_sect_index.?;
        shdr.sh_info = self.plt_sect_index.?;
    }

    for (self.comdat_group_sections.items) |*cg| {
        cg.shndx = backlinks[cg.shndx];
    }

    for (self.sections.items(.rela_shndx), 0..) |index, shndx| {
        const shdr = &self.sections.items(.shdr)[index];
        if (shdr.sh_type != elf.SHT_NULL) {
            shdr.sh_link = self.symtab_sect_index.?;
            shdr.sh_info = @intCast(shndx);
        }
    }
}

fn parsePositional(self: *Elf, arena: Allocator, obj: LinkObject, search_dirs: []const []const u8) anyerror!void {
    const resolved_obj = try self.resolveFile(arena, obj, search_dirs);

    log.debug("parsing positional argument '{s}'", .{resolved_obj.path});

    if (try self.parseObject(resolved_obj)) return;
    if (try self.parseArchive(resolved_obj)) return;
    if (try self.parseShared(resolved_obj)) return;
    if (try self.parseLdScript(arena, resolved_obj, search_dirs)) return;

    self.base.fatal("unknown filetype for positional argument: '{s}'", .{resolved_obj.path});
}

fn parseObject(self: *Elf, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    const header = file.reader().readStruct(elf.Elf64_Ehdr) catch return false;
    try file.seekTo(0);

    if (!Object.isValidHeader(&header)) return false;
    const obj_arch = cpuArchFromElfMachine(header.e_machine);
    try self.validateOrSetCpuArch(obj.path, obj_arch);
    try self.validateEFlags(obj.path, header.e_flags);

    const index = @as(u32, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .object = .{
        .path = try gpa.dupe(u8, obj.path),
        .file_handle = fh,
        .index = index,
    } });
    const object = &self.files.items(.data)[index].object;
    try object.parse(self);
    try self.objects.append(gpa, index);

    return true;
}

fn parseArchive(self: *Elf, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    const magic = file.reader().readBytesNoEof(elf.ARMAG.len) catch return false;
    try file.seekTo(0);

    if (!Archive.isValidMagic(&magic)) return false;

    var archive = Archive{};
    defer archive.deinit(gpa);
    try archive.parse(self, obj.path, fh);

    var has_parse_error = false;
    for (archive.objects.items) |extracted| {
        const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
        self.files.set(index, .{ .object = extracted });
        const object = &self.files.items(.data)[index].object;
        object.index = index;
        object.parse(self) catch |err| switch (err) {
            error.ParseFailed => {
                has_parse_error = true;
                continue;
            },
            else => |e| return e,
        };
        try self.objects.append(gpa, index);
    }
    if (has_parse_error) return error.ParseFailed;

    return true;
}

fn parseShared(self: *Elf, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const header = file.reader().readStruct(elf.Elf64_Ehdr) catch return false;
    try file.seekTo(0);

    if (!SharedObject.isValidHeader(&header)) return false;
    const cpu_arch = cpuArchFromElfMachine(header.e_machine);
    try self.validateOrSetCpuArch(obj.path, cpu_arch);

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .shared = .{
        .path = try gpa.dupe(u8, obj.path),
        .index = index,
        .needed = obj.needed,
        .alive = obj.needed,
    } });
    const dso = &self.files.items(.data)[index].shared;
    try dso.parse(self, file);
    try self.shared_objects.append(gpa, index);

    return true;
}

fn parseLdScript(self: *Elf, arena: Allocator, obj: LinkObject, search_dirs: []const []const u8) !bool {
    const tracy = trace(@src());
    defer tracy.end();

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
        try self.validateOrSetCpuArch(obj.path, cpu_arch);
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

// TODO we should also include extracted OS in here.
fn validateOrSetCpuArch(self: *Elf, name: []const u8, cpu_arch: std.Target.Cpu.Arch) !void {
    const self_cpu_arch = self.options.cpu_arch orelse blk: {
        self.options.cpu_arch = cpu_arch;
        const page_size = Options.defaultPageSize(cpu_arch) orelse
            return self.base.fatal("{s}: unhandled architecture '{s}'", .{ name, @tagName(cpu_arch) });
        // TODO move this error into Options
        if (self.options.image_base % page_size != 0) {
            self.base.fatal("specified --image-base=0x{x} is not a multiple of page size of 0x{x}", .{
                self.options.image_base,
                page_size,
            });
        }
        self.options.page_size = page_size;
        break :blk self.options.cpu_arch.?;
    };
    if (self_cpu_arch != cpu_arch) {
        self.base.fatal("{s}: invalid architecture '{s}', expected '{s}'", .{ name, @tagName(cpu_arch), @tagName(self_cpu_arch) });
        return error.MismatchedCpuArch;
    }
}

/// TODO convert from std.Target.Cpu.Arch into std.elf.EM and remove this.
fn cpuArchFromElfMachine(em: std.elf.EM) std.Target.Cpu.Arch {
    return switch (em) {
        .AARCH64 => .aarch64,
        .X86_64 => .x86_64,
        .RISCV => .riscv64,
        else => @panic("unhandled e_machine value"),
    };
}

fn validateEFlags(self: *Elf, name: []const u8, e_flags: elf.Elf64_Word) !void {
    // validateOrSetCpuArch should be called before this.
    const self_cpu_arch = self.options.cpu_arch.?;

    if (self.first_eflags == null) self.first_eflags = e_flags;
    const self_eflags: *elf.Elf64_Word = &self.first_eflags.?;

    switch (self_cpu_arch) {
        .riscv64 => {
            if (e_flags != self_eflags.*) {
                const riscv_eflags: riscv.RiscvEflags = @bitCast(e_flags);
                const self_riscv_eflags: *riscv.RiscvEflags = @ptrCast(self_eflags);

                self_riscv_eflags.rvc = self_riscv_eflags.rvc or riscv_eflags.rvc;
                self_riscv_eflags.tso = self_riscv_eflags.tso or riscv_eflags.tso;

                var is_error: bool = false;
                if (self_riscv_eflags.fabi != riscv_eflags.fabi) {
                    is_error = true;
                    self.base.fatal("{s}: cannot link object files with different float-point ABIs", .{name});
                }
                if (self_riscv_eflags.rve != riscv_eflags.rve) {
                    is_error = true;
                    self.base.fatal("{s}: cannot link object files with different RVEs", .{name});
                }
                if (is_error) return error.MismatchedEflags;
            }
        },
        else => {},
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
    const tracy = trace(@src());
    defer tracy.end();

    // Resolve symbols on the set of all objects and shared objects (even if some are unneeded).
    for (self.objects.items) |index| try self.getFile(index).?.resolveSymbols(self);
    for (self.shared_objects.items) |index| try self.getFile(index).?.resolveSymbols(self);
    if (self.getInternalObject()) |obj| try obj.asFile().resolveSymbols(self);

    // Mark live objects.
    self.markLive();

    // Reset state of all globals after marking live objects.
    self.resolver.reset();

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

    {
        // Dedup comdat groups.
        var table = std.StringHashMap(Ref).init(self.base.allocator);
        defer table.deinit();

        for (self.objects.items) |index| {
            try self.getFile(index).?.object.resolveComdatGroups(self, &table);
        }

        for (self.objects.items) |index| {
            self.getFile(index).?.object.markComdatGroupsDead(self);
        }
    }

    // Re-resolve the symbols.
    for (self.objects.items) |index| try self.getFile(index).?.resolveSymbols(self);
    for (self.shared_objects.items) |index| try self.getFile(index).?.resolveSymbols(self);
    if (self.getInternalObject()) |obj| try obj.asFile().resolveSymbols(self);
}

/// Traverses all objects and shared objects marking any object referenced by
/// a live object/shared object as alive itself.
/// This routine will prune unneeded objects extracted from archives and
/// unneeded shared objects.
fn markLive(self: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

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
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (!file.isAlive()) continue;
        const object = file.object;
        for (object.atoms_indexes.items) |atom_index| {
            const atom = object.getAtom(atom_index) orelse continue;
            const is_eh_frame = (self.options.cpu_arch.? == .x86_64 and atom.getInputShdr(self).sh_type == elf.SHT_X86_64_UNWIND) or
                mem.eql(u8, atom.getName(self), ".eh_frame");
            if (atom.flags.alive and is_eh_frame) atom.flags.alive = false;
        }
    }
}

fn resolveMergeSections(self: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (!file.isAlive()) continue;
        try file.object.initMergeSections(self);
    }

    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (!file.isAlive()) continue;
        try file.object.resolveMergeSubsections(self);
    }
}

fn convertCommonSymbols(self: *Elf) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.convertCommonSymbols(self);
    }
}

fn markImportsAndExports(self: *Elf) !void {
    if (!self.options.shared)
        for (self.shared_objects.items) |index| {
            self.getFile(index).?.shared.markImportsExports(self);
        };

    for (self.objects.items) |index| {
        self.getFile(index).?.object.markImportsExports(self);
    }
}

fn checkDuplicates(self: *Elf) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.checkDuplicates(self);
    }
    try self.reportDuplicates();
}

fn claimUnresolved(self: *Elf) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items) |index| {
        self.getFile(index).?.object.claimUnresolved(self);
    }
}

fn reportDuplicates(self: *Elf) error{ HasDuplicates, OutOfMemory }!void {
    if (self.dupes.keys().len == 0) return; // Nothing to do

    const max_notes = 3;

    for (self.dupes.keys(), self.dupes.values()) |key, notes| {
        const sym = self.resolver.keys.items[key - 1];
        const nnotes = @min(notes.items.len, max_notes) + @intFromBool(notes.items.len > max_notes);

        var err = try self.base.addErrorWithNotes(nnotes + 1);
        try err.addMsg("duplicate symbol definition: {s}", .{sym.getName(self)});
        try err.addNote("defined by {}", .{sym.getFile(self).?.fmtPath()});

        var inote: usize = 0;
        while (inote < @min(notes.items.len, max_notes)) : (inote += 1) {
            const file_ptr = self.getFile(notes.items[inote]).?;
            try err.addNote("defined by {}", .{file_ptr.fmtPath()});
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            try err.addNote("defined {d} more times", .{remaining});
        }
    }

    return error.HasDuplicates;
}

fn reportUndefs(self: *Elf) !void {
    if (self.undefs.keys().len == 0) return;

    const max_notes = 4;

    for (self.undefs.keys(), self.undefs.values()) |key, refs| {
        const undef_sym = self.resolver.keys.items[key - 1];
        const nrefs = @min(refs.items.len, max_notes);
        const nnotes = nrefs + @intFromBool(refs.items.len > max_notes);

        var err = try self.base.addErrorWithNotes(nnotes);
        try err.addMsg("undefined symbol: {s}", .{undef_sym.getName(self)});

        for (refs.items[0..nrefs]) |ref| {
            const atom_ptr = self.getAtom(ref).?;
            const object = atom_ptr.getObject(self);
            try err.addNote("referenced by {s}:{s}", .{ object.fmtPath(), atom_ptr.getName(self) });
        }

        if (refs.items.len > max_notes) {
            const remaining = refs.items.len - max_notes;
            try err.addNote("referenced {d} more times", .{remaining});
        }
    }

    return error.UndefinedSymbols;
}

fn scanRelocs(self: *Elf) !void {
    const tracy = trace(@src());
    defer tracy.end();

    var has_reloc_error = false;
    for (self.objects.items) |index| {
        self.getFile(index).?.object.scanRelocs(self) catch |err| switch (err) {
            error.RelocError => has_reloc_error = true,
            else => |e| return e,
        };
    }

    try self.reportUndefs();
    if (has_reloc_error) return error.RelocError;

    for (self.objects.items) |index| {
        try self.getFile(index).?.createSymbolIndirection(self);
    }
    for (self.shared_objects.items) |index| {
        try self.getFile(index).?.createSymbolIndirection(self);
    }
    if (self.getInternalObject()) |obj| {
        try obj.asFile().createSymbolIndirection(self);
    }
    if (self.got.flags.needs_tlsld) {
        log.debug("program needs TLSLD", .{});
        try self.got.addTlsLdSymbol(self);
    }
}

fn setDynamic(self: *Elf) !void {
    if (self.dynamic_sect_index == null) return;

    for (self.shared_objects.items) |index| {
        const shared = self.getFile(index).?.shared;
        if (!shared.alive) continue;
        try self.dynamic.addNeeded(shared, self);
    }

    if (self.options.soname) |soname| {
        try self.dynamic.setSoname(soname, self);
    }

    try self.dynamic.setRpath(self.options.rpath_list, self);
}

fn setDynsym(self: *Elf) void {
    if (self.gnu_hash_sect_index == null) return;
    self.dynsym.sort(self);
}

fn setVerSymtab(self: *Elf) !void {
    if (self.versym_sect_index == null) return;
    try self.versym.resize(self.base.allocator, self.dynsym.count());
    self.versym.items[0] = elf.VER_NDX_LOCAL;
    for (self.dynsym.entries.items, 1..) |dynsym, i| {
        const sym = self.getSymbol(dynsym.ref).?;
        self.versym.items[i] = sym.ver_idx;
    }

    if (self.verneed_sect_index) |shndx| {
        try self.verneed.generate(self);
        const shdr = &self.sections.items(.shdr)[shndx];
        shdr.sh_info = @as(u32, @intCast(self.verneed.verneed.items.len));
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
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    const slice = self.sections.slice();
    for (slice.items(.shdr), slice.items(.atoms)) |shdr, atoms| {
        if (atoms.items.len == 0) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        log.debug("writing atoms in '{s}' section", .{self.getShString(shdr.sh_name)});

        const buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        const padding_byte: u8 = if (shdr.sh_type == elf.SHT_PROGBITS and
            shdr.sh_flags & elf.SHF_EXECINSTR != 0 and self.options.cpu_arch.? == .x86_64)
            0xcc // int3
        else
            0;
        @memset(buffer, padding_byte);

        var stream = std.io.fixedBufferStream(buffer);

        for (atoms.items) |ref| {
            const atom = self.getAtom(ref).?;
            assert(atom.flags.alive);
            const off: u64 = @intCast(atom.value);
            log.debug("writing ATOM({},'{s}') at offset 0x{x}", .{
                ref,
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

    for (self.thunks.items) |thunk| {
        const shdr = slice.items(.shdr)[thunk.out_shndx];
        const offset = @as(u64, @intCast(thunk.value)) + shdr.sh_offset;
        const buffer = try gpa.alloc(u8, thunk.size(self));
        defer gpa.free(buffer);
        var stream = std.io.fixedBufferStream(buffer);
        try thunk.write(self, stream.writer());
        try self.base.file.pwriteAll(buffer, offset);
    }

    try self.reportUndefs();
}

pub fn writeMergeSections(self: *Elf) !void {
    const gpa = self.base.allocator;
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    for (self.merge_sections.items) |msec| {
        const shdr = self.sections.items(.shdr)[msec.out_shndx];

        try buffer.ensureTotalCapacity(shdr.sh_size);
        buffer.appendNTimesAssumeCapacity(0, shdr.sh_size);

        for (msec.subsections.items) |msub_index| {
            const msub = self.getMergeSubsection(msub_index);
            assert(msub.alive);
            const string = msub.getString(self);
            const off: u64 = @intCast(msub.value);
            @memcpy(buffer.items[off..][0..string.len], string);
        }

        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
        buffer.clearRetainingCapacity();
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
        try self.base.file.pwriteAll(self.dynstrtab.items, shdr.sh_offset);
    }

    if (self.eh_frame_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, shdr.sh_size);
        defer buffer.deinit();
        try eh_frame.writeEhFrame(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.eh_frame_hdr_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, shdr.sh_size);
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
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.plt.size(self));
        defer buffer.deinit();
        try self.plt.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.got_plt_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.got_plt.size(self));
        defer buffer.deinit();
        try self.got_plt.write(self, buffer.writer());
        try self.base.file.pwriteAll(buffer.items, shdr.sh_offset);
    }

    if (self.plt_got_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.plt_got.size(self));
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
        try self.base.file.pwriteAll(self.shstrtab.items, shdr.sh_offset);
    }
}

fn writePhdrs(self: *Elf) !void {
    const phoff = @sizeOf(elf.Elf64_Ehdr);
    const phdrs_size = self.phdrs.items.len * @sizeOf(elf.Elf64_Phdr);
    log.debug("writing program headers from 0x{x} to 0x{x}", .{ phoff, phoff + phdrs_size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.phdrs.items), phoff);
}

pub fn writeShdrs(self: *Elf) !void {
    const size = self.sections.items(.shdr).len * @sizeOf(elf.Elf64_Shdr);
    log.debug("writing section headers from 0x{x} to 0x{x}", .{ self.shoff, self.shoff + size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.sections.items(.shdr)), self.shoff);
}

fn getRiscvEFlags(self: *Elf) !u32 {
    _ = self;
    // TODO: implement this
    return 5;
}

fn writeHeader(self: *Elf) !void {
    const e_entry: u64 = if (self.getInternalObject()) |obj| blk: {
        const entry_sym = obj.getEntrySymbol(self) orelse break :blk 0;
        break :blk @intCast(entry_sym.getAddress(.{}, self));
    } else 0;
    var header = elf.Elf64_Ehdr{
        .e_ident = undefined,
        .e_type = if (self.options.pic) .DYN else .EXEC,
        .e_machine = switch (self.options.cpu_arch.?) {
            .x86_64 => .X86_64,
            .aarch64 => .AARCH64,
            .riscv64 => .RISCV,
            else => unreachable,
        },
        .e_version = 1,
        .e_entry = e_entry,
        .e_phoff = @sizeOf(elf.Elf64_Ehdr),
        .e_shoff = self.shoff,
        .e_flags = if (self.options.cpu_arch.? == .riscv64) try self.getRiscvEFlags() else 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @intCast(self.phdrs.items.len),
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @intCast(self.sections.items(.shdr).len),
        .e_shstrndx = @intCast(self.shstrtab_sect_index.?),
    };
    // Magic
    @memcpy(header.e_ident[0..4], "\x7fELF");
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
    name: u32 = 0,
    type: u32 = elf.SHT_NULL,
    flags: u64 = 0,
    link: u32 = 0,
    info: u32 = 0,
    addralign: u64 = 0,
    entsize: u64 = 0,
    size: u64 = 0,
};

pub fn addSection(self: *Elf, opts: AddSectionOpts) !u32 {
    const gpa = self.base.allocator;
    const index = @as(u32, @intCast(try self.sections.addOne(gpa)));
    self.sections.set(index, .{
        .shdr = .{
            .sh_name = opts.name,
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
    });
    return index;
}

pub fn getSectionByName(self: *Elf, name: [:0]const u8) ?u32 {
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const this_name = self.getShString(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @intCast(i);
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
    const index = @as(u16, @intCast(self.phdrs.items.len));
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

pub fn getInternalObject(self: *Elf) ?*InternalObject {
    const index = self.internal_object_index orelse return null;
    return self.getFile(index).?.internal;
}

pub fn addFileHandle(self: *Elf, file: std.fs.File) !File.HandleIndex {
    const gpa = self.base.allocator;
    const index: File.HandleIndex = @intCast(self.file_handles.items.len);
    const fh = try self.file_handles.addOne(gpa);
    fh.* = file;
    return index;
}

pub fn getFileHandle(self: Elf, index: File.HandleIndex) File.Handle {
    assert(index < self.file_handles.items.len);
    return self.file_handles.items[index];
}

fn addThunk(self: *Elf) !Thunk.Index {
    const index = @as(Thunk.Index, @intCast(self.thunks.items.len));
    const thunk = try self.thunks.addOne(self.base.allocator);
    thunk.* = .{};
    return index;
}

pub fn getThunk(self: *Elf, index: Thunk.Index) *Thunk {
    assert(index < self.thunks.items.len);
    return &self.thunks.items[index];
}

fn createThunks(self: *Elf, shndx: u32) !void {
    const advance = struct {
        fn advance(shdr: *elf.Elf64_Shdr, size: u64, pow2_align: u8) !i64 {
            const alignment = try math.powi(u32, 2, pow2_align);
            const offset = mem.alignForward(u64, shdr.sh_size, alignment);
            const padding = offset - shdr.sh_size;
            shdr.sh_size += padding + size;
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
            return @intCast(offset);
        }
    }.advance;

    const gpa = self.base.allocator;
    const cpu_arch = self.options.cpu_arch.?;
    const slice = self.sections.slice();
    const shdr = &slice.items(.shdr)[shndx];
    const atoms = slice.items(.atoms)[shndx].items;
    assert(atoms.len > 0);

    for (atoms) |ref| {
        self.getAtom(ref).?.value = -1;
    }

    var i: usize = 0;
    while (i < atoms.len) {
        const start = i;
        const start_atom = self.getAtom(atoms[start]).?;
        assert(start_atom.flags.alive);
        start_atom.value = try advance(shdr, start_atom.size, start_atom.alignment);
        i += 1;

        while (i < atoms.len) : (i += 1) {
            const ref = atoms[i];
            const atom = self.getAtom(ref).?;
            assert(atom.flags.alive);
            const alignment = try math.powi(u32, 2, atom.alignment);
            if (@as(i64, @intCast(mem.alignForward(u64, shdr.sh_size, alignment))) - start_atom.value >= Thunk.maxAllowedDistance(cpu_arch)) break;
            atom.value = try advance(shdr, atom.size, atom.alignment);
        }

        // Insert a thunk at the group end
        const thunk_index = try self.addThunk();
        const thunk = self.getThunk(thunk_index);
        thunk.out_shndx = shndx;

        // Scan relocs in the group and create trampolines for any unreachable callsite
        for (atoms[start..i]) |ref| {
            const atom = self.getAtom(ref).?;
            const object = atom.getObject(self);
            log.debug("atom({}) {s}", .{ ref, atom.getName(self) });
            for (atom.getRelocs(self)) |rel| {
                if (Thunk.isReachable(atom, rel, self)) continue;
                const target = object.resolveSymbol(rel.r_sym(), self);
                try thunk.symbols.put(gpa, target, {});
            }
            atom.addExtra(.{ .thunk = thunk_index }, self);
            atom.flags.thunk = true;
        }

        thunk.value = try advance(shdr, thunk.size(self), 2);

        log.debug("thunk({d}) : {}", .{ thunk_index, thunk.fmt(self) });
    }
}

pub fn addMergeSubsection(self: *Elf) !MergeSubsection.Index {
    const index: MergeSubsection.Index = @intCast(self.merge_subsections.items.len);
    const msec = try self.merge_subsections.addOne(self.base.allocator);
    msec.* = .{};
    return index;
}

pub fn getMergeSubsection(self: *Elf, index: MergeSubsection.Index) *MergeSubsection {
    assert(index < self.merge_subsections.items.len);
    return &self.merge_subsections.items[index];
}

pub fn getOrCreateMergeSection(self: *Elf, name: [:0]const u8, flags: u64, @"type": u32) !MergeSection.Index {
    const gpa = self.base.allocator;
    const out_name = name: {
        if (self.options.relocatable) break :name name;
        if (mem.eql(u8, name, ".rodata") or mem.startsWith(u8, name, ".rodata"))
            break :name if (flags & elf.SHF_STRINGS != 0) ".rodata.str" else ".rodata.cst";
        break :name name;
    };
    for (self.merge_sections.items, 0..) |msec, index| {
        if (mem.eql(u8, msec.getName(self), out_name)) return @intCast(index);
    }
    const out_off = try self.insertShString(out_name);
    const out_flags = flags & ~@as(u64, elf.SHF_COMPRESSED | elf.SHF_GROUP);
    const index = @as(MergeSection.Index, @intCast(self.merge_sections.items.len));
    const msec = try self.merge_sections.addOne(gpa);
    msec.* = .{
        .name = out_off,
        .flags = out_flags,
        .type = @"type",
    };
    return index;
}

pub fn getMergeSection(self: *Elf, index: MergeSection.Index) *MergeSection {
    assert(index < self.merge_sections.items.len);
    return &self.merge_sections.items[index];
}

pub fn getAtom(self: *Elf, ref: Ref) ?*Atom {
    const file = self.getFile(ref.file) orelse return null;
    return file.getAtom(ref.index);
}

pub fn getSymbol(self: *Elf, ref: Ref) ?*Symbol {
    const file = self.getFile(ref.file) orelse return null;
    return file.getSymbol(ref.index);
}

pub fn getComdatGroup(self: *Elf, ref: Ref) *ComdatGroup {
    return self.getFile(ref.file).?.getComdatGroup(ref.index);
}

const RelaDyn = struct {
    offset: u64,
    sym: u64 = 0,
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
        inline fn getRank(rel: elf.Elf64_Rela, ctx: *const Elf) u2 {
            const cpu_arch = ctx.options.cpu_arch.?;
            const r_type = rel.r_type();
            const r_kind = relocation.decode(r_type, cpu_arch).?;
            return switch (r_kind) {
                .rel => 0,
                .irel => 2,
                else => 1,
            };
        }

        pub fn lessThan(ctx: *const Elf, lhs: elf.Elf64_Rela, rhs: elf.Elf64_Rela) bool {
            if (getRank(lhs, ctx) == getRank(rhs, ctx)) {
                if (lhs.r_sym() == rhs.r_sym()) return lhs.r_offset < rhs.r_offset;
                return lhs.r_sym() < rhs.r_sym();
            }
            return getRank(lhs, ctx) < getRank(rhs, ctx);
        }
    };
    mem.sort(elf.Elf64_Rela, self.rela_dyn.items, self, Sort.lessThan);
}

fn getNumIRelativeRelocs(self: *Elf) usize {
    var count: usize = self.num_ifunc_dynrelocs;

    for (self.got.entries.items) |entry| {
        if (entry.tag != .got) continue;
        const symbol = self.getSymbol(entry.symbol_index);
        if (symbol.isIFunc(self)) count += 1;
    }

    return count;
}

pub fn isCIdentifier(name: []const u8) bool {
    if (name.len == 0) return false;
    const first_c = name[0];
    if (!std.ascii.isAlphabetic(first_c) and first_c != '_') return false;
    for (name[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    }
    return true;
}

pub fn getStartStopBasename(self: *Elf, shdr: elf.Elf64_Shdr) ?[]const u8 {
    const name = self.getShString(shdr.sh_name);
    if (shdr.sh_flags & elf.SHF_ALLOC != 0 and name.len > 0) {
        if (isCIdentifier(name)) return name;
    }
    return null;
}

pub fn getGotAddress(self: *Elf) i64 {
    const shndx = blk: {
        if (self.options.cpu_arch.? == .x86_64 and self.got_plt_sect_index != null)
            break :blk self.got_plt_sect_index.?;
        break :blk if (self.got_sect_index) |shndx| shndx else null;
    };
    return if (shndx) |index| @intCast(self.sections.items(.shdr)[index].sh_addr) else 0;
}

pub fn getTpAddress(self: *Elf) i64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    const addr = switch (self.options.cpu_arch.?) {
        .x86_64 => mem.alignForward(u64, phdr.p_vaddr + phdr.p_memsz, phdr.p_align),
        .aarch64 => mem.alignBackward(u64, phdr.p_vaddr - 16, phdr.p_align),
        else => @panic("TODO implement getTpAddress for this arch"),
    };
    return @intCast(addr);
}

pub fn getDtpAddress(self: *Elf) i64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    return @intCast(phdr.p_vaddr);
}

pub fn getTlsAddress(self: *Elf) i64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    return @intCast(phdr.p_vaddr);
}

fn requiresThunks(self: Elf) bool {
    return switch (self.options.cpu_arch.?) {
        .aarch64 => true,
        .x86_64, .riscv64 => false,
        else => @panic("unsupported architecture"),
    };
}

pub fn getEntryName(self: Elf) ?[]const u8 {
    if (self.options.shared) return null;
    return self.options.entry orelse "_start";
}

pub fn getShString(self: Elf, off: u32) [:0]const u8 {
    assert(off < self.shstrtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.shstrtab.items.ptr + off)), 0);
}

pub fn insertShString(self: *Elf, name: [:0]const u8) error{OutOfMemory}!u32 {
    const gpa = self.base.allocator;
    const off = @as(u32, @intCast(self.shstrtab.items.len));
    try self.shstrtab.ensureUnusedCapacity(gpa, name.len + 1);
    self.shstrtab.writer(gpa).print("{s}\x00", .{name}) catch unreachable;
    return off;
}

pub fn getDynString(self: Elf, off: u32) [:0]const u8 {
    assert(off < self.dynstrtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.dynstrtab.items.ptr + off)), 0);
}

pub fn insertDynString(self: *Elf, name: []const u8) error{OutOfMemory}!u32 {
    const gpa = self.base.allocator;
    const off = @as(u32, @intCast(self.dynstrtab.items.len));
    try self.dynstrtab.ensureUnusedCapacity(gpa, name.len + 1);
    self.dynstrtab.writer(gpa).print("{s}\x00", .{name}) catch unreachable;
    return off;
}

/// Caller owns the memory.
pub fn preadAllAlloc(allocator: Allocator, file: std.fs.File, offset: usize, size: usize) ![]u8 {
    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);
    const amt = try file.preadAll(buffer, offset);
    if (amt != size) return error.InputOutput;
    return buffer;
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
    for (self.sections.items(.shdr), self.sections.items(.rela_shndx), 0..) |shdr, rela_shndx, i| {
        try writer.print("sect({d}) : {s} : @{x} ({x}) : align({x}) : size({x}) : rela({d})\n", .{
            i,                 self.getShString(shdr.sh_name), shdr.sh_offset, shdr.sh_addr,
            shdr.sh_addralign, shdr.sh_size,                   rela_shndx,
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

pub fn dumpState(self: *Elf) std.fmt.Formatter(fmtDumpState) {
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
    try writer.writeAll("THUNKS\n");
    for (self.thunks.items, 0..) |thunk, index| {
        try writer.print("thunk({d}) : {}\n", .{ index, thunk.fmt(self) });
    }
    try writer.print("GOT\n{}\n", .{self.got.fmt(self)});
    try writer.print("PLT\n{}\n", .{self.plt.fmt(self)});
    try writer.writeAll("PLTGOT\n");
    for (self.plt_got.symbols.items, 0..) |ref, i| {
        try writer.print("  {d} => {} '{s}'\n", .{ i, ref, self.getSymbol(ref).?.getName(self) });
    }
    try writer.writeByte('\n');
    try writer.writeAll("COPYREL\n");
    for (self.copy_rel.symbols.items, 0..) |ref, i| {
        const symbol = self.getSymbol(ref).?;
        try writer.print("  {d}@{x} => {} '{s}'\n", .{
            i,
            symbol.getAddress(.{}, self),
            ref,
            symbol.getName(self),
        });
    }
    try writer.writeByte('\n');
    try writer.writeAll("Merge sections\n");
    for (self.merge_sections.items, 0..) |msec, index| {
        try writer.print("merge_sect({d}) : {}\n", .{ index, msec.fmt(self) });
    }
    try writer.writeByte('\n');
    try writer.writeAll("Output COMDAT groups\n");
    for (self.comdat_group_sections.items) |cg| {
        try writer.print("  shdr({d}) : COMDAT({})\n", .{ cg.shndx, cg.cg_ref });
    }
    try writer.writeByte('\n');
    try writer.writeAll("Output shdrs\n");
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
    atoms: std.ArrayListUnmanaged(Ref) = .{},
    rela_shndx: u32 = 0,
    sym_index: u32 = 0,
};

pub const Ref = struct {
    index: u32 = 0,
    file: u32 = 0,

    pub fn eql(ref: Ref, other: Ref) bool {
        return ref.index == other.index and ref.file == other.file;
    }

    pub fn format(
        ref: Ref,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("ref({},{})", .{ ref.index, ref.file });
    }
};

pub const SymbolResolver = struct {
    keys: std.ArrayListUnmanaged(Key) = .{},
    values: std.ArrayListUnmanaged(Ref) = .{},
    table: std.AutoArrayHashMapUnmanaged(void, void) = .{},

    const Result = struct {
        found_existing: bool,
        index: Index,
        ref: *Ref,
    };

    pub fn deinit(resolver: *SymbolResolver, allocator: Allocator) void {
        resolver.keys.deinit(allocator);
        resolver.values.deinit(allocator);
        resolver.table.deinit(allocator);
    }

    pub fn getOrPut(
        resolver: *SymbolResolver,
        allocator: Allocator,
        ref: Ref,
        elf_file: *Elf,
    ) !Result {
        const adapter = Adapter{ .keys = resolver.keys.items, .elf_file = elf_file };
        const key = Key{ .index = ref.index, .file_index = ref.file };
        const gop = try resolver.table.getOrPutAdapted(allocator, key, adapter);
        if (!gop.found_existing) {
            try resolver.keys.append(allocator, key);
            _ = try resolver.values.addOne(allocator);
        }
        return .{
            .found_existing = gop.found_existing,
            .index = @intCast(gop.index + 1),
            .ref = &resolver.values.items[gop.index],
        };
    }

    pub fn get(resolver: SymbolResolver, index: Index) ?Ref {
        if (index == 0) return null;
        return resolver.values.items[index - 1];
    }

    pub fn reset(resolver: *SymbolResolver) void {
        resolver.keys.clearRetainingCapacity();
        resolver.values.clearRetainingCapacity();
        resolver.table.clearRetainingCapacity();
    }

    const Key = struct {
        index: Symbol.Index,
        file_index: File.Index,

        fn getName(key: Key, elf_file: *Elf) [:0]const u8 {
            const ref = Ref{ .index = key.index, .file = key.file_index };
            return elf_file.getSymbol(ref).?.getName(elf_file);
        }

        fn getFile(key: Key, elf_file: *Elf) ?File {
            return elf_file.getFile(key.file_index);
        }

        fn eql(key: Key, other: Key, elf_file: *Elf) bool {
            const key_name = key.getName(elf_file);
            const other_name = other.getName(elf_file);
            return mem.eql(u8, key_name, other_name);
        }

        fn hash(key: Key, elf_file: *Elf) u32 {
            return @truncate(Hash.hash(0, key.getName(elf_file)));
        }
    };

    const Adapter = struct {
        keys: []const Key,
        elf_file: *Elf,

        pub fn eql(ctx: @This(), key: Key, b_void: void, b_map_index: usize) bool {
            _ = b_void;
            const other = ctx.keys[b_map_index];
            return key.eql(other, ctx.elf_file);
        }

        pub fn hash(ctx: @This(), key: Key) u32 {
            return key.hash(ctx.elf_file);
        }
    };

    pub const Index = u32;
};

pub const ComdatGroup = struct {
    signature_off: u32,
    file_index: File.Index,
    shndx: u32,
    members_start: u32,
    members_len: u32,
    alive: bool = true,

    pub fn getFile(cg: ComdatGroup, elf_file: *Elf) File {
        return elf_file.getFile(cg.file_index).?;
    }

    pub fn getSignature(cg: ComdatGroup, elf_file: *Elf) [:0]const u8 {
        return cg.getFile(elf_file).object.getString(cg.signature_off);
    }

    pub fn getComdatGroupMembers(cg: ComdatGroup, elf_file: *Elf) []const u32 {
        const object = cg.getFile(elf_file).object;
        return object.comdat_group_data.items[cg.members_start..][0..cg.members_len];
    }

    pub const Index = u32;
};

pub const SymtabCtx = struct {
    ilocal: u32 = 0,
    iglobal: u32 = 0,
    nlocals: u32 = 0,
    nglobals: u32 = 0,
    strsize: u32 = 0,
};

pub const null_sym = elf.Elf64_Sym{
    .st_name = 0,
    .st_info = 0,
    .st_other = 0,
    .st_shndx = 0,
    .st_value = 0,
    .st_size = 0,
};

pub const base_tag = Zld.Tag.elf;

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const eh_frame = @import("Elf/eh_frame.zig");
const elf = std.elf;
const fs = std.fs;
const gc = @import("Elf/gc.zig");
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;
const merge_section = @import("Elf/merge_section.zig");
const relocatable = @import("Elf/relocatable.zig");
const relocation = @import("Elf/relocation.zig");
const state_log = std.log.scoped(.state);
const synthetic = @import("Elf/synthetic.zig");
const trace = @import("tracy.zig").trace;
const riscv = @import("riscv.zig");

const Allocator = mem.Allocator;
const Archive = @import("Elf/Archive.zig");
const Atom = @import("Elf/Atom.zig");
const ComdatGroupSection = synthetic.ComdatGroupSection;
const CopyRelSection = synthetic.CopyRelSection;
const DynamicSection = synthetic.DynamicSection;
const DynsymSection = synthetic.DynsymSection;
const Elf = @This();
const File = @import("Elf/file.zig").File;
const GnuHashSection = synthetic.GnuHashSection;
const GotSection = synthetic.GotSection;
const GotPltSection = synthetic.GotPltSection;
const Hash = std.hash.Wyhash;
const HashSection = synthetic.HashSection;
const InputMergeSection = merge_section.InputMergeSection;
const InternalObject = @import("Elf/InternalObject.zig");
const LdScript = @import("Elf/LdScript.zig");
const MergeSection = merge_section.MergeSection;
const MergeSubsection = merge_section.MergeSubsection;
const Object = @import("Elf/Object.zig");
pub const Options = @import("Elf/Options.zig");
const PltSection = synthetic.PltSection;
const PltGotSection = synthetic.PltGotSection;
const SharedObject = @import("Elf/SharedObject.zig");
const StringTable = @import("StringTable.zig");
const Symbol = @import("Elf/Symbol.zig");
const ThreadPool = std.Thread.Pool;
const Thunk = @import("Elf/Thunk.zig");
const VerneedSection = synthetic.VerneedSection;
const Zld = @import("Zld.zig");
