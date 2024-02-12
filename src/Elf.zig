base: Zld,
options: Options,
shoff: u64 = 0,

objects: std.ArrayListUnmanaged(File.Index) = .{},
shared_objects: std.ArrayListUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},

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
ehdr_start_index: ?u32 = null,
init_array_start_index: ?u32 = null,
init_array_end_index: ?u32 = null,
fini_array_start_index: ?u32 = null,
fini_array_end_index: ?u32 = null,
preinit_array_start_index: ?u32 = null,
preinit_array_end_index: ?u32 = null,
got_index: ?u32 = null,
plt_index: ?u32 = null,
dso_handle_index: ?u32 = null,
gnu_eh_frame_hdr_index: ?u32 = null,
rela_iplt_start_index: ?u32 = null,
rela_iplt_end_index: ?u32 = null,
end_index: ?u32 = null,
start_stop_indexes: std.ArrayListUnmanaged(u32) = .{},

entry_index: ?u32 = null,

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
globals: std.AutoHashMapUnmanaged(u32, Symbol.Index) = .{},
/// This table will be populated after `scanRelocs` has run.
/// Key is symbol index.
undefs: std.AutoHashMapUnmanaged(Symbol.Index, std.ArrayListUnmanaged(Atom.Index)) = .{},

string_intern: StringTable(.string_intern) = .{},

shstrtab: StringTable(.shstrtab) = .{},
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
dynsym: DynsymSection = .{},
dynstrtab: StringTable(.dynstrtab) = .{},
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

atoms: std.ArrayListUnmanaged(Atom) = .{},

comdat_groups: std.ArrayListUnmanaged(ComdatGroup) = .{},
comdat_groups_owners: std.ArrayListUnmanaged(ComdatGroupOwner) = .{},
comdat_groups_table: std.AutoHashMapUnmanaged(u32, ComdatGroupOwner.Index) = .{},

has_text_reloc: bool = false,
num_ifunc_dynrelocs: usize = 0,
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
    self.string_intern.deinit(gpa);
    self.shstrtab.deinit(gpa);
    self.symtab.deinit(gpa);
    self.strtab.deinit(gpa);
    self.atoms.deinit(gpa);
    self.comdat_groups.deinit(gpa);
    self.comdat_groups_owners.deinit(gpa);
    self.comdat_groups_table.deinit(gpa);
    self.symbols.deinit(gpa);
    self.symbols_extra.deinit(gpa);
    self.globals.deinit(gpa);
    self.start_stop_indexes.deinit(gpa);
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
    {
        var it = self.undefs.valueIterator();
        while (it.next()) |notes| {
            notes.deinit(gpa);
        }
        self.undefs.deinit(gpa);
    }
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
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
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
    const gpa = self.base.allocator;

    // Append empty string to string tables.
    try self.string_intern.buffer.append(gpa, 0);
    try self.shstrtab.buffer.append(gpa, 0);
    try self.strtab.append(gpa, 0);
    try self.dynstrtab.buffer.append(gpa, 0);
    // Append null section.
    _ = try self.addSection(.{ .name = "" });
    // Append null atom.
    try self.atoms.append(gpa, .{});
    // Append null symbols.
    try self.symtab.append(gpa, null_sym);
    try self.symbols.append(gpa, .{});
    try self.symbols_extra.append(gpa, 0);
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
                error.FileNotFound, error.ParseFailed => {}, // already reported
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
    }

    try self.resolveSymbols();
    self.markEhFrameAtomsDead();

    if (self.options.relocatable) return relocatable.flush(self);

    try self.convertCommonSymbols();
    try self.markImportsAndExports();

    // Set the entrypoint if found
    self.entry_index = blk: {
        if (self.options.shared) break :blk null;
        const entry_name = self.options.entry orelse "_start";
        break :blk self.getGlobalByName(entry_name);
    };
    if (!self.options.shared and self.entry_index == null) {
        self.base.fatal("no entrypoint found: '{s}'", .{self.options.entry orelse "_start"});
    }

    if (self.options.gc_sections) {
        try gc.gcAtoms(self);

        if (self.options.print_gc_sections) {
            try gc.dumpPrunedAtoms(self);
        }
    }

    if (!self.options.allow_multiple_definition) {
        try self.checkDuplicates();
    }

    try self.initOutputSections();
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

    try self.initSyntheticSections();
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
        break :blk mem.alignForward(u64, offset, @alignOf(elf.Elf64_Shdr));
    };

    state_log.debug("{}", .{self.dumpState()});

    try self.writeAtoms();
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
        atom_index: Atom.Index,

        pub fn lessThan(ctx: *Elf, lhs: @This(), rhs: @This()) bool {
            if (lhs.priority == rhs.priority) {
                return ctx.getAtom(lhs.atom_index).?.getPriority(ctx) < ctx.getAtom(rhs.atom_index).?.getPriority(ctx);
            }
            return lhs.priority < rhs.priority;
        }
    };

    for (self.sections.items(.shdr), 0..) |*shdr, shndx| {
        if (!shdrIsAlloc(shdr)) continue;

        var is_init_fini = false;
        var is_ctor_dtor = false;
        switch (shdr.sh_type) {
            elf.SHT_PREINIT_ARRAY,
            elf.SHT_INIT_ARRAY,
            elf.SHT_FINI_ARRAY,
            => is_init_fini = true,
            else => {
                const name = self.shstrtab.getAssumeExists(shdr.sh_name);
                is_ctor_dtor = mem.indexOf(u8, name, ".ctors") != null or mem.indexOf(u8, name, ".dtors") != null;
            },
        }

        if (!is_init_fini and !is_ctor_dtor) continue;

        const atoms = &self.sections.items(.atoms)[shndx];

        var entries = std.ArrayList(Entry).init(gpa);
        try entries.ensureTotalCapacityPrecise(atoms.items.len);
        defer entries.deinit();

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            const file = atom.getObject(self);
            const priority = blk: {
                if (is_ctor_dtor) {
                    if (mem.indexOf(u8, file.path, "crtbegin") != null) break :blk std.math.minInt(i32);
                    if (mem.indexOf(u8, file.path, "crtend") != null) break :blk std.math.maxInt(i32);
                }
                const default: i32 = if (is_ctor_dtor) -1 else std.math.maxInt(i32);
                const name = atom.getName(self);
                var it = mem.splitBackwards(u8, name, ".");
                const priority = std.fmt.parseUnsigned(u16, it.first(), 10) catch default;
                break :blk priority;
            };
            entries.appendAssumeCapacity(.{ .priority = priority, .atom_index = atom_index });
        }

        mem.sort(Entry, entries.items, self, Entry.lessThan);

        atoms.clearRetainingCapacity();
        for (entries.items) |entry| {
            atoms.appendAssumeCapacity(entry.atom_index);
        }
    }
}

fn initOutputSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_shndx = try object.initOutputSection(self, atom.getInputShdr(self));
        }
    }

    self.text_sect_index = self.getSectionByName(".text");
}

fn initSyntheticSections(self: *Elf) !void {
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
                .addralign = @alignOf(u32),
            });
        }
    }

    if (self.got.entries.items.len > 0) {
        self.got_sect_index = try self.addSection(.{
            .name = ".got",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC | elf.SHF_WRITE,
            .addralign = @alignOf(u64),
        });
    }

    self.got_plt_sect_index = try self.addSection(.{
        .name = ".got.plt",
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
            .name = ".interp",
            .type = elf.SHT_PROGBITS,
            .flags = elf.SHF_ALLOC,
            .addralign = 1,
        });
    }

    if (self.options.shared or self.shared_objects.items.len > 0 or self.options.pie) {
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
            .type = elf.SHT_GNU_HASH,
            .addralign = 8,
        });

        const needs_versions = for (self.dynsym.entries.items) |dynsym| {
            const symbol = self.getSymbol(dynsym.index);
            if (symbol.flags.import and symbol.ver_idx & elf.VERSYM_VERSION > elf.VER_NDX_GLOBAL) break true;
        } else false;
        if (needs_versions) {
            self.versym_sect_index = try self.addSection(.{
                .name = ".gnu.version",
                .flags = elf.SHF_ALLOC,
                .type = elf.SHT_GNU_VERSYM,
                .addralign = @alignOf(elf.Elf64_Versym),
                .entsize = @sizeOf(elf.Elf64_Versym),
            });
            self.verneed_sect_index = try self.addSection(.{
                .name = ".gnu.version_r",
                .flags = elf.SHF_ALLOC,
                .type = elf.SHT_GNU_VERNEED,
                .addralign = @alignOf(elf.Elf64_Verneed),
            });
        }
    }
}

pub fn initSymtab(self: *Elf) !void {
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

pub fn initShStrtab(self: *Elf) !void {
    self.shstrtab_sect_index = try self.addSection(.{
        .name = ".shstrtab",
        .type = elf.SHT_STRTAB,
        .entsize = 1,
        .addralign = 1,
    });
}

pub fn addAtomsToSections(self: *Elf) !void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
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
            const offset = mem.alignForward(u64, shdr.sh_size, alignment);
            const padding = offset - shdr.sh_size;
            atom.value = offset;
            shdr.sh_size += padding + atom.size;
            shdr.sh_addralign = @max(shdr.sh_addralign, alignment);
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
        shdr.sh_size = self.plt.size();
        shdr.sh_addralign = 16;
    }

    if (self.got_plt_sect_index) |index| {
        const shdr = &self.sections.items(.shdr)[index];
        shdr.sh_size = self.got_plt.size(self);
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
    for (self.sections.items(.atoms), self.sections.items(.sym_index)) |atoms, *sym_index| {
        if (atoms.items.len == 0) continue;
        sym_index.* = nlocals + 1;
        nlocals += 1;
    }
    if (self.eh_frame_sect_index) |shndx| {
        self.sections.items(.sym_index)[shndx] = nlocals + 1;
        nlocals += 1;
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
                .@"align" = @max(self.options.page_size.?, shdr.sh_addralign),
                .offset = if (last_phdr == null) 0 else shdr.sh_offset,
                .addr = if (last_phdr == null) self.options.image_base else shdr.sh_addr,
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
    return shdrIsZerofill(shdr) and !shdrIsTls(shdr);
}

inline fn shdrIsTbss(shdr: *const elf.Elf64_Shdr) bool {
    return shdrIsZerofill(shdr) and shdrIsTls(shdr);
}

pub inline fn shdrIsZerofill(shdr: *const elf.Elf64_Shdr) bool {
    return shdr.sh_type == elf.SHT_NOBITS;
}

pub inline fn shdrIsTls(shdr: *const elf.Elf64_Shdr) bool {
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
    for (shdrs, 0..) |*shdr, i| {
        if (!shdrIsTls(shdr)) continue;
        if (alignment.first_tls_index == null) alignment.first_tls_index = i;
        alignment.tls_start_align = @max(alignment.tls_start_align, shdr.sh_addralign);
    }

    var addr = self.options.image_base + base_offset;
    var i: usize = 0;
    while (i < shdrs.len) : (i += 1) {
        const shdr = &shdrs[i];
        if (!shdrIsAlloc(shdr)) continue;
        if (i > 0) {
            const prev_shdr = shdrs[i - 1];
            if (shdrToPhdrFlags(shdr.sh_flags) != shdrToPhdrFlags(prev_shdr.sh_flags)) {
                // We need to advance by page size
                addr += self.options.page_size.?;
            }
        }
        if (shdrIsTbss(shdr)) {
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
            while (i < shdrs.len and shdrIsTbss(&shdrs[i])) : (i += 1) {
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
        defer if (!shdrIsAlloc(first) or shdrIsZerofill(first)) {
            i += 1;
        };

        // Non-alloc sections don't need congruency with their allocated virtual memory addresses
        if (!shdrIsAlloc(first)) {
            first.sh_offset = mem.alignForward(u64, offset, first.sh_addralign);
            offset = first.sh_offset + first.sh_size;
            continue;
        }
        // Skip any zerofill section
        if (shdrIsZerofill(first)) continue;

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

            const next = &shdrs[i];
            if (i >= shdrs.len or !shdrIsAlloc(next) or shdrIsZerofill(next)) break;
            if (next.sh_addr < first.sh_addr) break;

            const gap = next.sh_addr - prev.sh_addr - prev.sh_size;
            if (gap >= page_size) break;
        }

        const prev = &shdrs[i - 1];
        offset = prev.sh_offset + prev.sh_size;

        // Skip any zerofill section
        while (i < shdrs.len and shdrIsAlloc(&shdrs[i]) and shdrIsZerofill(&shdrs[i])) : (i += 1) {}
    }
}

fn allocateSections(self: *Elf) !void {
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

fn getSectionRank(self: *Elf, shndx: u16) u8 {
    const shdr = self.sections.items(.shdr)[shndx];
    const name = self.shstrtab.getAssumeExists(shdr.sh_name);
    const flags = shdr.sh_flags;
    switch (shdr.sh_type) {
        elf.SHT_NULL => return 0,
        elf.SHT_DYNSYM => return 2,
        elf.SHT_HASH => return 3,
        elf.SHT_GNU_HASH => return 3,
        elf.SHT_GNU_VERSYM => return 4,
        elf.SHT_GNU_VERDEF => return 4,
        elf.SHT_GNU_VERNEED => return 4,

        elf.SHT_PREINIT_ARRAY,
        elf.SHT_INIT_ARRAY,
        elf.SHT_FINI_ARRAY,
        => return 0xf2,

        elf.SHT_DYNAMIC => return 0xf3,

        elf.SHT_RELA, elf.SHT_GROUP => return 0xf,

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

pub fn sortSections(self: *Elf) !void {
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
        entries.appendAssumeCapacity(.{ .shndx = @as(u16, @intCast(shndx)) });
    }

    mem.sort(Entry, entries.items, self, Entry.lessThan);

    const backlinks = try gpa.alloc(u16, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.shndx] = @as(u16, @intCast(i));
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
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
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

fn allocateAtoms(self: *Elf) void {
    for (self.sections.items(.shdr), self.sections.items(.atoms)) |shdr, atoms| {
        if (atoms.items.len == 0) continue;
        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.flags.alive);
            atom.value += shdr.sh_addr;
        }
    }
}

pub fn allocateLocals(self: *Elf) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.getLocals()) |local_index| {
            const local = self.getSymbol(local_index);
            const atom = local.getAtom(self) orelse continue;
            if (!atom.flags.alive) continue;
            local.value += atom.value;
            local.shndx = atom.out_shndx;
        }
    }
}

pub fn allocateGlobals(self: *Elf) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.getGlobals()) |global_index| {
            const global = self.getSymbol(global_index);
            const atom = global.getAtom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (global.getFile(self).?.object.index != index) continue;
            global.value += atom.value;
            global.shndx = atom.out_shndx;
        }
    }
}

fn allocateSyntheticSymbols(self: *Elf) void {
    // _DYNAMIC
    if (self.dynamic_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        const symbol = self.getSymbol(self.dynamic_index.?);
        symbol.value = shdr.sh_addr;
        symbol.shndx = shndx;
    }

    // __ehdr_start
    {
        const symbol = self.getSymbol(self.ehdr_start_index.?);
        symbol.value = self.options.image_base;
        symbol.shndx = 1;
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

    // __preinit_array_start, __preinit_array_end
    if (self.getSectionByName(".preinit_array")) |shndx| {
        const start_sym = self.getSymbol(self.preinit_array_start_index.?);
        const end_sym = self.getSymbol(self.preinit_array_end_index.?);
        const shdr = self.sections.items(.shdr)[shndx];
        start_sym.shndx = shndx;
        start_sym.value = shdr.sh_addr;
        end_sym.shndx = shndx;
        end_sym.value = shdr.sh_addr + shdr.sh_size;
    }

    // _GLOBAL_OFFSET_TABLE_
    if (self.got_plt_sect_index) |shndx| {
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

    // __GNU_EH_FRAME_HDR
    if (self.eh_frame_hdr_sect_index) |shndx| {
        const shdr = self.sections.items(.shdr)[shndx];
        const symbol = self.getSymbol(self.gnu_eh_frame_hdr_index.?);
        symbol.value = shdr.sh_addr;
        symbol.shndx = shndx;
    }

    // __rela_iplt_start, __rela_iplt_end
    if (self.rela_dyn_sect_index != null and self.options.static and !self.options.pie) {
        const shndx = self.rela_dyn_sect_index.?;
        const shdr = self.sections.items(.shdr)[shndx];
        const end_addr = shdr.sh_addr + shdr.sh_size;
        const start_addr = end_addr - self.getNumIRelativeRelocs() * @sizeOf(elf.Elf64_Rela);
        const start_sym = self.getSymbol(self.rela_iplt_start_index.?);
        const end_sym = self.getSymbol(self.rela_iplt_end_index.?);
        start_sym.value = start_addr;
        start_sym.shndx = shndx;
        end_sym.value = end_addr;
        end_sym.shndx = shndx;
    }

    // _end
    {
        const end_symbol = self.getSymbol(self.end_index.?);
        for (self.sections.items(.shdr), 0..) |shdr, shndx| {
            if (shdr.sh_flags & elf.SHF_ALLOC != 0) {
                end_symbol.value = shdr.sh_addr + shdr.sh_size;
                end_symbol.shndx = @intCast(shndx);
            }
        }
    }

    // __start_*, __stop_*
    {
        var index: usize = 0;
        while (index < self.start_stop_indexes.items.len) : (index += 2) {
            const start = self.getSymbol(self.start_stop_indexes.items[index]);
            const name = start.getName(self);
            const stop = self.getSymbol(self.start_stop_indexes.items[index + 1]);
            const shndx = self.getSectionByName(name["__start_".len..]).?;
            const shdr = self.sections.items(.shdr)[shndx];
            start.value = shdr.sh_addr;
            start.shndx = shndx;
            stop.value = shdr.sh_addr + shdr.sh_size;
            stop.shndx = shndx;
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
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    const header = file.reader().readStruct(elf.Elf64_Ehdr) catch return false;
    try file.seekTo(0);

    if (!Object.isValidHeader(&header)) return false;
    self.validateOrSetCpuArch(obj.path, header.e_machine.toTargetCpuArch().?);

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
    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const header = file.reader().readStruct(elf.Elf64_Ehdr) catch return false;
    try file.seekTo(0);

    if (!SharedObject.isValidHeader(&header)) return false;
    self.validateOrSetCpuArch(obj.path, header.e_machine.toTargetCpuArch().?);

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
        const page_size: u16 = switch (cpu_arch) {
            .x86_64 => 0x1000,
            else => @panic("TODO"),
        };
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
                for (cg.getComdatGroupMembers(self)) |shndx| {
                    const atom_index = object.atoms.items[shndx];
                    if (self.getAtom(atom_index)) |atom| {
                        atom.flags.alive = false;
                        atom.markFdesDead(self);
                    }
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
            if (atom.flags.alive and is_eh_frame) atom.flags.alive = false;
        }
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
            for (self.getFile(index).?.shared.getGlobals()) |global_index| {
                const global = self.getSymbol(global_index);
                const file = global.getFile(self) orelse continue;
                const vis = @as(elf.STV, @enumFromInt(global.getSourceSymbol(self).st_other));
                if (file != .shared and vis != .HIDDEN) global.flags.@"export" = true;
            }
        };

    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.getGlobals()) |global_index| {
            const global = self.getSymbol(global_index);
            if (global.ver_idx == elf.VER_NDX_LOCAL) continue;
            const file = global.getFile(self) orelse continue;
            const vis = @as(elf.STV, @enumFromInt(global.getSourceSymbol(self).st_other));
            if (vis == .HIDDEN) continue;
            if (file == .shared and !global.isAbs(self)) {
                global.flags.import = true;
                continue;
            }
            if (file.getIndex() == index) {
                global.flags.@"export" = true;

                if (self.options.shared and vis != .PROTECTED) {
                    global.flags.import = true;
                }
            }
        }
    }
}

fn resolveSyntheticSymbols(self: *Elf) !void {
    const internal_index = self.internal_object_index orelse return;
    const internal = self.getFile(internal_index).?.internal;
    self.dynamic_index = try internal.addSyntheticGlobal("_DYNAMIC", self);
    self.ehdr_start_index = try internal.addSyntheticGlobal("__ehdr_start", self);
    self.init_array_start_index = try internal.addSyntheticGlobal("__init_array_start", self);
    self.init_array_end_index = try internal.addSyntheticGlobal("__init_array_end", self);
    self.fini_array_start_index = try internal.addSyntheticGlobal("__fini_array_start", self);
    self.fini_array_end_index = try internal.addSyntheticGlobal("__fini_array_end", self);
    self.preinit_array_start_index = try internal.addSyntheticGlobal("__preinit_array_start", self);
    self.preinit_array_end_index = try internal.addSyntheticGlobal("__preinit_array_end", self);
    self.got_index = try internal.addSyntheticGlobal("_GLOBAL_OFFSET_TABLE_", self);
    self.plt_index = try internal.addSyntheticGlobal("_PROCEDURE_LINKAGE_TABLE_", self);
    self.end_index = try internal.addSyntheticGlobal("_end", self);

    if (self.options.eh_frame_hdr) {
        self.gnu_eh_frame_hdr_index = try internal.addSyntheticGlobal("__GNU_EH_FRAME_HDR", self);
    }

    if (self.getGlobalByName("__dso_handle")) |index| {
        if (self.getSymbol(index).getFile(self) == null)
            self.dso_handle_index = try internal.addSyntheticGlobal("__dso_handle", self);
    }

    self.rela_iplt_start_index = try internal.addSyntheticGlobal("__rela_iplt_start", self);
    self.rela_iplt_end_index = try internal.addSyntheticGlobal("__rela_iplt_end", self);

    for (self.sections.items(.shdr)) |shdr| {
        if (self.getStartStopBasename(shdr)) |name| {
            const gpa = self.base.allocator;
            try self.start_stop_indexes.ensureUnusedCapacity(gpa, 2);

            const start = try std.fmt.allocPrintZ(gpa, "__start_{s}", .{name});
            defer gpa.free(start);
            const stop = try std.fmt.allocPrintZ(gpa, "__stop_{s}", .{name});
            defer gpa.free(stop);

            self.start_stop_indexes.appendAssumeCapacity(try internal.addSyntheticGlobal(start, self));
            self.start_stop_indexes.appendAssumeCapacity(try internal.addSyntheticGlobal(stop, self));
        }
    }

    internal.resolveSymbols(self);
}

fn checkDuplicates(self: *Elf) !void {
    var has_dupes = false;
    for (self.objects.items) |index| {
        if (self.getFile(index).?.object.checkDuplicates(self)) {
            has_dupes = true;
        }
    }
    if (has_dupes) return error.MultipleSymbolDefinition;
}

fn claimUnresolved(self: *Elf) void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        const first_global = object.first_global orelse return;
        for (object.getGlobals(), 0..) |global_index, i| {
            const sym_idx = @as(u32, @intCast(first_global + i));
            const sym = object.symtab.items[sym_idx];
            if (sym.st_shndx != elf.SHN_UNDEF) continue;

            const global = self.getSymbol(global_index);
            if (global.getFile(self)) |_| {
                if (global.getSourceSymbol(self).st_shndx != elf.SHN_UNDEF) continue;
            }

            const is_import = blk: {
                if (!self.options.shared) break :blk false;
                const vis = @as(elf.STV, @enumFromInt(sym.st_other));
                if (vis == .HIDDEN) break :blk false;
                break :blk true;
            };

            global.value = 0;
            global.atom = 0;
            global.sym_idx = sym_idx;
            global.file = object.index;
            global.ver_idx = if (is_import) elf.VER_NDX_LOCAL else self.default_sym_version;
            global.flags.import = is_import;
        }
    }
}

fn reportUndefs(self: *Elf) !void {
    if (self.undefs.count() == 0) return;

    const max_notes = 4;

    var it = self.undefs.iterator();
    while (it.next()) |entry| {
        const undef_sym = self.getSymbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @intFromBool(notes.items.len > max_notes);

        const err = try self.base.addErrorWithNotes(nnotes);
        try err.addMsg("undefined symbol: {s}", .{undef_sym.getName(self)});

        var inote: usize = 0;
        while (inote < @min(notes.items.len, max_notes)) : (inote += 1) {
            const atom = self.getAtom(notes.items[inote]).?;
            const object = atom.getObject(self);
            try err.addNote("referenced by {}:{s}", .{ object.fmtPath(), atom.getName(self) });
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            try err.addNote("referenced {d} more times", .{remaining});
        }
    }
    return error.UndefinedSymbols;
}

fn scanRelocs(self: *Elf) !void {
    var has_reloc_error = false;
    for (self.objects.items) |index| {
        self.getFile(index).?.object.scanRelocs(self) catch |err| switch (err) {
            error.RelocError => has_reloc_error = true,
            else => |e| return e,
        };
    }
    try self.reportUndefs();
    if (has_reloc_error) return error.RelocError;

    for (self.symbols.items, 0..) |*symbol, i| {
        const index = @as(u32, @intCast(i));
        if (!symbol.isLocal(self) and !symbol.flags.has_dynamic) {
            log.debug("'{s}' is non-local", .{symbol.getName(self)});
            try self.dynsym.addSymbol(index, self);
        }
        if (symbol.flags.got) {
            log.debug("'{s}' needs GOT", .{symbol.getName(self)});
            try self.got.addGotSymbol(index, self);
        }
        if (symbol.flags.plt) {
            if (symbol.flags.is_canonical) {
                log.debug("'{s}' needs CPLT", .{symbol.getName(self)});
                symbol.flags.@"export" = true;
                try self.plt.addSymbol(index, self);
            } else if (symbol.flags.got) {
                log.debug("'{s}' needs PLTGOT", .{symbol.getName(self)});
                try self.plt_got.addSymbol(index, self);
            } else {
                log.debug("'{s}' needs PLT", .{symbol.getName(self)});
                try self.plt.addSymbol(index, self);
            }
        }
        if (symbol.flags.copy_rel and !symbol.flags.has_copy_rel) {
            log.debug("'{s}' needs COPYREL", .{symbol.getName(self)});
            try self.copy_rel.addSymbol(index, self);
        }
        if (symbol.flags.tlsgd) {
            log.debug("'{s}' needs TLSGD", .{symbol.getName(self)});
            try self.got.addTlsGdSymbol(index, self);
        }
        if (symbol.flags.gottp) {
            log.debug("'{s}' needs GOTTP", .{symbol.getName(self)});
            try self.got.addGotTpSymbol(index, self);
        }
        if (symbol.flags.tlsdesc) {
            log.debug("'{s}' needs TLSDESC", .{symbol.getName(self)});
            try self.dynsym.addSymbol(index, self);
            try self.got.addTlsDescSymbol(index, self);
        }
    }

    if (self.got.flags.needs_tlsld) {
        log.debug("needs TLSLD", .{});
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
        const sym = self.getSymbol(dynsym.index);
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
    const slice = self.sections.slice();
    for (slice.items(.shdr), slice.items(.atoms)) |shdr, atoms| {
        if (atoms.items.len == 0) continue;
        if (shdr.sh_type == elf.SHT_NOBITS) continue;

        log.debug("writing atoms in '{s}' section", .{self.shstrtab.getAssumeExists(shdr.sh_name)});

        const buffer = try self.base.allocator.alloc(u8, shdr.sh_size);
        defer self.base.allocator.free(buffer);
        const padding_byte: u8 = if (shdr.sh_type == elf.SHT_PROGBITS and
            shdr.sh_flags & elf.SHF_EXECINSTR != 0)
            0xcc // int3
        else
            0;
        @memset(buffer, padding_byte);

        var stream = std.io.fixedBufferStream(buffer);

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.flags.alive);
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
        var buffer = try std.ArrayList(u8).initCapacity(gpa, self.plt.size());
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

pub fn writeShdrs(self: *Elf) !void {
    const size = self.sections.items(.shdr).len * @sizeOf(elf.Elf64_Shdr);
    log.debug("writing section headers from 0x{x} to 0x{x}", .{ self.shoff, self.shoff + size });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.sections.items(.shdr)), self.shoff);
}

fn writeHeader(self: *Elf) !void {
    var header = elf.Elf64_Ehdr{
        .e_ident = undefined,
        .e_type = if (self.options.pic) .DYN else .EXEC,
        .e_machine = self.options.cpu_arch.?.toElfMachine(),
        .e_version = 1,
        .e_entry = if (self.entry_index) |index| self.getSymbol(index).value else 0,
        .e_phoff = @sizeOf(elf.Elf64_Ehdr),
        .e_shoff = self.shoff,
        .e_flags = 0,
        .e_ehsize = @sizeOf(elf.Elf64_Ehdr),
        .e_phentsize = @sizeOf(elf.Elf64_Phdr),
        .e_phnum = @as(u16, @intCast(self.phdrs.items.len)),
        .e_shentsize = @sizeOf(elf.Elf64_Shdr),
        .e_shnum = @as(u16, @intCast(self.sections.items(.shdr).len)),
        .e_shstrndx = self.shstrtab_sect_index.?,
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
    const index = @as(u16, @intCast(try self.sections.addOne(gpa)));
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
    });
    return index;
}

pub fn getSectionByName(self: *Elf, name: [:0]const u8) ?u16 {
    for (self.sections.items(.shdr), 0..) |shdr, i| {
        const this_name = self.shstrtab.getAssumeExists(shdr.sh_name);
        if (mem.eql(u8, this_name, name)) return @as(u16, @intCast(i));
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

pub fn addAtom(self: *Elf) !Atom.Index {
    const index = @as(u32, @intCast(self.atoms.items.len));
    const atom = try self.atoms.addOne(self.base.allocator);
    atom.* = .{};
    return index;
}

pub fn getAtom(self: Elf, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn addSymbol(self: *Elf) !Symbol.Index {
    const index = @as(Symbol.Index, @intCast(self.symbols.items.len));
    const symbol = try self.symbols.addOne(self.base.allocator);
    symbol.* = .{};
    return index;
}

pub fn getSymbol(self: *Elf, index: Symbol.Index) *Symbol {
    assert(index < self.symbols.items.len);
    return &self.symbols.items[index];
}

pub fn addSymbolExtra(self: *Elf, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    try self.symbols_extra.ensureUnusedCapacity(self.base.allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

pub fn addSymbolExtraAssumeCapacity(self: *Elf, extra: Symbol.Extra) u32 {
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
        const index = @as(ComdatGroupOwner.Index, @intCast(self.comdat_groups_owners.items.len));
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
    const index = @as(ComdatGroup.Index, @intCast(self.comdat_groups.items.len));
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
        inline fn getRank(rel: elf.Elf64_Rela) u2 {
            return switch (rel.r_type()) {
                elf.R_X86_64_RELATIVE => 0,
                elf.R_X86_64_IRELATIVE => 2,
                else => 1,
            };
        }

        pub fn lessThan(ctx: void, lhs: elf.Elf64_Rela, rhs: elf.Elf64_Rela) bool {
            _ = ctx;
            if (getRank(lhs) == getRank(rhs)) {
                if (lhs.r_sym() == rhs.r_sym()) return lhs.r_offset < rhs.r_offset;
                return lhs.r_sym() < rhs.r_sym();
            }
            return getRank(lhs) < getRank(rhs);
        }
    };
    mem.sort(elf.Elf64_Rela, self.rela_dyn.items, {}, Sort.lessThan);
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

fn getStartStopBasename(self: *Elf, shdr: elf.Elf64_Shdr) ?[]const u8 {
    const name = self.shstrtab.get(shdr.sh_name) orelse return null;
    if (shdr.sh_flags & elf.SHF_ALLOC != 0 and name.len > 0) {
        if (isCIdentifier(name)) return name;
    }
    return null;
}

pub fn getTpAddress(self: *Elf) u64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    return mem.alignForward(u64, phdr.p_vaddr + phdr.p_memsz, phdr.p_align);
}

pub fn getDtpAddress(self: *Elf) u64 {
    return self.getTlsAddress();
}

pub fn getTlsAddress(self: *Elf) u64 {
    const index = self.tls_phdr_index orelse return 0;
    const phdr = self.phdrs.items[index];
    return phdr.p_vaddr;
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
            i,                 self.shstrtab.getAssumeExists(shdr.sh_name), shdr.sh_offset, shdr.sh_addr,
            shdr.sh_addralign, shdr.sh_size,                                rela_shndx,
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
    try writer.print("GOT\n{}\n", .{self.got.fmt(self)});
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
            symbol.getAddress(.{}, self),
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
    rela_shndx: u32 = 0,
    sym_index: u32 = 0,
};

const ComdatGroupOwner = struct {
    file: File.Index = 0,

    const Index = u32;
};

pub const ComdatGroup = struct {
    owner: ComdatGroupOwner.Index,
    file: File.Index,
    shndx: u32,
    members_start: u32,
    members_len: u32,

    pub fn getComdatGroupMembers(cg: ComdatGroup, elf_file: *Elf) []const u32 {
        const object = elf_file.getFile(cg.file).?.object;
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
const relocatable = @import("Elf/relocatable.zig");
const state_log = std.log.scoped(.state);
const synthetic = @import("Elf/synthetic.zig");
const math = std.math;
const mem = std.mem;

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
const ThreadPool = std.Thread.Pool;
const VerneedSection = synthetic.VerneedSection;
const Zld = @import("Zld.zig");
