base: Zld,
options: Options,

internal_object_index: ?File.Index = null,
objects: std.ArrayListUnmanaged(File.Index) = .{},
dlls: std.StringArrayHashMapUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},

sections: std.MultiArrayList(Section) = .{},

text_section_index: ?u16 = null,
data_section_index: ?u16 = null,
idata_section_index: ?u16 = null,
reloc_section_index: ?u16 = null,

string_intern: StringTable = .{},

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
globals: std.AutoHashMapUnmanaged(u32, Symbol.Index) = .{},
/// Global symbols we need to resolve for the link to succeed.
undefined_symbols: std.AutoArrayHashMapUnmanaged(Symbol.Index, void) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},
merge_rules: std.AutoArrayHashMapUnmanaged(u32, u32) = .{},

entry_index: ?Symbol.Index = null,
load_config_used_index: ?Symbol.Index = null,
image_base_index: ?Symbol.Index = null,
guard_fids_count_index: ?Symbol.Index = null,
guard_fids_table_index: ?Symbol.Index = null,
guard_flags_index: ?Symbol.Index = null,
guard_iat_count_index: ?Symbol.Index = null,
guard_iat_table_index: ?Symbol.Index = null,
guard_longjmp_count_index: ?Symbol.Index = null,
guard_longjmp_table_index: ?Symbol.Index = null,
enclave_config_index: ?Symbol.Index = null,
guard_eh_cont_count_index: ?Symbol.Index = null,
guard_eh_cont_table_index: ?Symbol.Index = null,

data_dirs: [coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES]coff.ImageDataDirectory,
base_relocs: RelocSection = .{},

pub fn openPath(allocator: Allocator, options: Options, thread_pool: *ThreadPool) !*Coff {
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

fn createEmpty(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*Coff {
    const self = try gpa.create(Coff);

    self.* = .{
        .base = .{
            .tag = .coff,
            .allocator = gpa,
            .file = undefined,
            .thread_pool = thread_pool,
        },
        .options = options,
        .data_dirs = [_]coff.ImageDataDirectory{.{
            .virtual_address = 0,
            .size = 0,
        }} ** coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
    };

    return self;
}

pub fn deinit(self: *Coff) void {
    const gpa = self.base.allocator;

    for (self.file_handles.items) |file| {
        file.close();
    }
    self.file_handles.deinit(gpa);

    for (self.files.items(.tags), self.files.items(.data)) |tag, *data| switch (tag) {
        .null => {},
        .internal => data.internal.deinit(gpa),
        .object => data.object.deinit(gpa),
        .dll => data.dll.deinit(gpa),
    };
    self.files.deinit(gpa);
    self.objects.deinit(gpa);
    self.dlls.deinit(gpa);

    for (self.sections.items(.atoms)) |*list| {
        list.deinit(gpa);
    }
    self.sections.deinit(gpa);
    self.atoms.deinit(gpa);
    self.symbols.deinit(gpa);
    self.symbols_extra.deinit(gpa);
    self.globals.deinit(gpa);
    self.undefined_symbols.deinit(gpa);
    self.merge_rules.deinit(gpa);
    self.base_relocs.deinit(gpa);
}

pub fn flush(self: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    // Atom at index 0 is reserved as null atom
    try self.atoms.append(gpa, .{});
    // Append empty string to string tables
    try self.string_intern.buffer.append(gpa, 0);
    // Append null file.
    try self.files.append(gpa, .null);
    // Append null symbols.
    try self.symbols.append(gpa, .{});
    try self.symbols_extra.append(gpa, 0);

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // Set up library search paths
    var lib_paths = std.ArrayList([]const u8).init(arena);
    try lib_paths.ensureUnusedCapacity(self.options.lib_paths.len + 1);
    lib_paths.appendAssumeCapacity(".");
    lib_paths.appendSliceAssumeCapacity(self.options.lib_paths);
    // TODO: do not parse LIB env var if mingw
    // TODO: detect WinSDK
    try addLibPathsFromEnv(arena, &lib_paths);

    if (build_options.enable_logging) {
        log.debug("library search paths:", .{});
        for (lib_paths.items) |path| {
            log.debug("  {s}", .{path});
        }
    }

    // TODO infer CPU arch and perhaps subsystem and whatnot?

    // Parse positionals and any additional file that might have been requested
    // by any of the already parsed positionals via the linker directives section.
    var has_file_not_found_error = false;
    var has_parse_error = false;
    var positionals = std.fifo.LinearFifo(LinkObject, .Dynamic).init(gpa);
    defer positionals.deinit();
    try positionals.ensureUnusedCapacity(self.options.positionals.len);
    for (self.options.positionals) |obj| {
        positionals.writeItemAssumeCapacity(obj);
    }

    var visited = std.StringHashMap(void).init(gpa);
    defer visited.deinit();

    while (positionals.readItem()) |obj| {
        self.parsePositional(arena, obj, lib_paths.items, &positionals, &visited) catch |err| switch (err) {
            error.AlreadyVisited => continue,
            error.FileNotFound => has_file_not_found_error = true,
            error.ParseFailed => has_parse_error = true,
            else => |e| {
                self.base.fatal("{s}: unexpected error occurred while parsing input file: {s}", .{
                    obj.path, @errorName(e),
                });
                return e;
            },
        };
    }

    if (has_file_not_found_error) {
        self.base.fatal("tried library search paths:", .{});
        for (lib_paths.items) |path| {
            self.base.fatal("  {s}", .{path});
        }
        has_parse_error = true;
    }
    if (has_parse_error) return error.ParseFailed;

    for (self.dlls.values()) |index| {
        try self.getFile(index).?.dll.initSymbols(self);
    }

    {
        const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object_index = index;
    }

    try self.addUndefinedSymbols();
    try self.resolveSymbols();
    try self.resolveSyntheticSymbols();
    try self.convertCommonSymbols();
    try self.claimUnresolved();
    self.markExports();
    self.markImports();
    try self.reportUndefs();

    try self.parseMergeRules();
    try self.createImportThunks();
    try self.collectBaseRelocs();
    try self.initSections();
    try self.sortSections();
    try self.addAtomsToSections();
    try self.updateSectionSizes();
    self.updateDataDirectorySizes();

    try self.allocateSections();
    self.allocateDataDirectories();
    self.allocateSyntheticSymbols();

    if (build_options.enable_logging)
        state_log.debug("{}", .{self.dumpState()});

    try self.writeAtoms();
    try self.writeImportSection();
    try self.writeBaseRelocs();
    try self.writeDataDirectoryHeaders();
    try self.writeSectionHeaders();
    try self.writeHeader();
}

fn addLibPathsFromEnv(arena: Allocator, lib_paths: *std.ArrayList([]const u8)) !void {
    const env_var = try std.process.getEnvVarOwned(arena, "LIB");
    var it = mem.splitScalar(u8, env_var, ';');
    while (it.next()) |path| {
        try lib_paths.append(path);
    }
}

fn resolveFile(
    self: *Coff,
    arena: Allocator,
    obj: LinkObject,
    lib_dirs: []const []const u8,
    visited: anytype,
) !LinkObject {
    if (std.fs.path.isAbsolute(obj.name)) {
        if (visited.get(obj.name)) |_| return error.AlreadyVisited;
        if (try accessPath(obj.name)) {
            try visited.putNoClobber(obj.name, {});
            return .{ .name = obj.name, .path = obj.name, .tag = obj.tag };
        }
        self.base.fatal("file not found '{s}'", .{obj.name});
        return error.FileNotFound;
    }
    const gpa = self.base.allocator;
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const obj_name = if (std.fs.path.extension(obj.name).len == 0 and obj.tag == .default_lib)
        try std.fmt.allocPrint(arena, "{s}.lib", .{obj.name})
    else
        obj.name;

    for (lib_dirs) |dir| {
        try buffer.writer().print("{s}" ++ std.fs.path.sep_str ++ "{s}", .{ dir, obj_name });
        if (visited.get(buffer.items)) |_| return error.AlreadyVisited;
        if (try accessPath(buffer.items)) {
            const path = try arena.dupe(u8, buffer.items);
            try visited.putNoClobber(path, {});
            return .{ .name = obj_name, .path = path, .tag = obj.tag };
        }
        buffer.clearRetainingCapacity();
    }
    self.base.fatal("file not found '{s}'", .{obj_name});
    return error.FileNotFound;
}

fn accessPath(path: []const u8) !bool {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return true;
}

const ParseError = error{
    AlreadyVisited,
    FileNotFound,
    ParseFailed,
    OutOfMemory,
    Overflow,
    InvalidCharacter,
} || std.fs.Dir.AccessError || std.fs.File.OpenError || std.fs.File.PReadError;

fn parsePositional(
    self: *Coff,
    arena: Allocator,
    obj: LinkObject,
    lib_paths: []const []const u8,
    queue: anytype,
    visited: anytype,
) ParseError!void {
    const resolved_obj = try self.resolveFile(arena, obj, lib_paths, visited);

    if (try self.parseObject(resolved_obj, queue)) return;
    if (try self.parseArchive(resolved_obj, queue)) return;

    self.base.fatal("unknown filetype for positional argument: {} resolved as {s}", .{
        resolved_obj,
        resolved_obj.path,
    });
}

fn parseObject(self: *Coff, obj: LinkObject, queue: anytype) ParseError!bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    var header_buffer: [@sizeOf(coff.CoffHeader)]u8 = undefined;
    const amt = file.preadAll(&header_buffer, 0) catch return false;
    if (amt != @sizeOf(coff.CoffHeader)) return false;
    if (!isCoffObj(&header_buffer)) return false;
    // TODO validate CPU arch

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .object = .{
        .path = try gpa.dupe(u8, obj.path),
        .file_handle = fh,
        .index = index,
    } });
    const object = &self.files.items(.data)[index].object;
    try object.parse(self);
    try self.objects.append(gpa, index);
    try parseLibsFromDirectives(object, queue);

    return true;
}

fn parseLibsFromDirectives(object: *const Object, queue: anytype) !void {
    for (object.default_libs.items) |off| {
        const name = object.getString(off);
        const dir_obj = LinkObject{ .name = name, .tag = .default_lib };
        try queue.writeItem(dir_obj);
    }
    // TODO handle /disallowlib and /nodefaultlib
}

fn parseArchive(self: *Coff, obj: LinkObject, queue: anytype) ParseError!bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const cpu_arch = self.options.cpu_arch.?;
    const file = try fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    var magic: [Archive.magic.len]u8 = undefined;
    var amt = file.preadAll(&magic, 0) catch return false;
    if (amt != Archive.magic.len) return false;
    if (!isArchive(&magic)) return false;

    var archive = Archive{};
    defer archive.deinit(gpa);
    try archive.parse(obj.path, fh, self);

    var has_parse_error = false;
    for (archive.members.items) |member| {
        const member_cpu_arch = cpuArchFromCoffMachineType(member.machine) orelse {
            extra_log.debug("{s}({s}): TODO unhandled machine type {}", .{ obj.path, member.name, member.machine });
            continue;
        };
        if (member_cpu_arch != cpu_arch) continue;

        switch (member.tag) {
            .object => {
                const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
                self.files.set(index, .{ .object = .{
                    .archive = .{
                        .path = try gpa.dupe(u8, obj.path),
                        .offset = member.offset,
                    },
                    .path = try gpa.dupe(u8, member.name),
                    .file_handle = fh,
                    .index = index,
                    .alive = false,
                } });
                const object = &self.files.items(.data)[index].object;
                object.parse(self) catch |err| switch (err) {
                    error.ParseFailed => {
                        has_parse_error = true;
                        continue;
                    },
                    else => |e| return e,
                };
                try self.objects.append(gpa, index);
                try parseLibsFromDirectives(object, queue);
            },
            .import => {
                var import_hdr_buffer: [@sizeOf(coff.ImportHeader)]u8 = undefined;
                amt = try file.preadAll(&import_hdr_buffer, member.offset);
                if (amt != @sizeOf(coff.ImportHeader)) return error.InputOutput;
                const import_hdr = @as(*align(1) const coff.ImportHeader, @ptrCast(&import_hdr_buffer));

                const strings = try gpa.alloc(u8, import_hdr.size_of_data);
                defer gpa.free(strings);
                amt = try file.preadAll(strings, member.offset + @sizeOf(coff.ImportHeader));
                if (amt != import_hdr.size_of_data) return error.InputOutput;

                const import_name = mem.sliceTo(@as([*:0]const u8, @ptrCast(strings.ptr)), 0);
                const dll_name = mem.sliceTo(@as([*:0]const u8, @ptrCast(strings.ptr + import_name.len + 1)), 0);

                const name = try gpa.dupe(u8, dll_name);
                const gop = try self.dlls.getOrPut(gpa, name);
                defer if (gop.found_existing) gpa.free(name);
                if (!gop.found_existing) {
                    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
                    self.files.set(index, .{ .dll = .{
                        .path = name,
                        .index = index,
                    } });
                    gop.value_ptr.* = index;
                }

                const dll = &self.files.items(.data)[gop.value_ptr.*].dll;
                dll.addExport(self, .{
                    .name = import_name,
                    .strings = strings,
                    .type = import_hdr.types.type,
                    .name_type = import_hdr.types.name_type,
                    .hint = import_hdr.hint,
                }) catch |err| switch (err) {
                    error.ParseFailed => {
                        has_parse_error = true;
                        continue;
                    },
                    else => |e| return e,
                };
            },
        }
    }
    if (has_parse_error) return error.ParseFailed;

    return true;
}

fn addUndefinedSymbols(self: *Coff) !void {
    const addUndefined = struct {
        fn addUndefined(coff_file: *Coff, name: []const u8) !Symbol.Index {
            const gpa = coff_file.base.allocator;
            const off = try coff_file.string_intern.insert(gpa, name);
            const gop = try coff_file.getOrCreateGlobal(off);
            try coff_file.undefined_symbols.put(gpa, gop.index, {});
            return gop.index;
        }
    }.addUndefined;

    // Entry point
    self.entry_index = try addUndefined(self, self.getDefaultEntryPoint());

    // Windows specific - try resolving _load_config_used
    self.load_config_used_index = try addUndefined(self, "_load_config_used");
}

fn resolveSymbols(self: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // Resolve symbols on the set of all objects and shared objects (even if some are unneeded).
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.dlls.values()) |index| self.getFile(index).?.resolveSymbols(self);

    // Mark live objects.
    self.markLive();

    // Reset state of all globals after marking live objects.
    for (self.objects.items) |index| self.getFile(index).?.resetGlobals(self);
    for (self.dlls.values()) |index| self.getFile(index).?.resetGlobals(self);

    // Prune dead objects.
    var i: usize = 0;
    while (i < self.objects.items.len) {
        const index = self.objects.items[i];
        if (!self.getFile(index).?.isAlive()) {
            _ = self.objects.orderedRemove(i);
            self.files.items(.data)[index].object.deinit(self.base.allocator);
            self.files.set(index, .null);
        } else i += 1;
    }

    i = 0;
    while (i < self.dlls.keys().len) {
        const key = self.dlls.keys()[i];
        const index = self.dlls.values()[i];
        if (!self.getFile(index).?.isAlive()) {
            _ = self.dlls.orderedRemove(key);
            self.files.items(.data)[index].dll.deinit(self.base.allocator);
            self.files.set(index, .null);
        } else i += 1;
    }

    // Re-resolve the symbols.
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.dlls.values()) |index| self.getFile(index).?.resolveSymbols(self);
}

fn markLive(self: *Coff) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.undefined_symbols.keys()) |index| {
        if (self.getSymbol(index).getFile(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        if (object.alive and !object.visited) {
            log.debug("Reading {}", .{object.fmtPathShort()});
            log.debug("Directives: {}: {}", .{ object.fmtPathShort(), object.fmtDirectives() });
            object.markLive(self);
        }
    }

    for (self.undefined_symbols.keys()) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self)) |file| {
            log.debug("Loaded {} for {s}", .{ file.fmtPathShort(), sym.getName(self) });
        }
    }
}

fn resolveSyntheticSymbols(self: *Coff) !void {
    const internal = self.getInternalObject() orelse return;

    self.image_base_index = try internal.addSymbol("__ImageBase", self);
    self.guard_fids_count_index = try internal.addSymbol("__guard_fids_count", self);
    self.guard_fids_table_index = try internal.addSymbol("__guard_fids_table", self);
    self.guard_flags_index = try internal.addSymbol("__guard_flags", self);
    self.guard_iat_count_index = try internal.addSymbol("__guard_iat_count", self);
    self.guard_iat_table_index = try internal.addSymbol("__guard_iat_table", self);
    self.guard_longjmp_count_index = try internal.addSymbol("__guard_longjmp_count", self);
    self.guard_longjmp_table_index = try internal.addSymbol("__guard_longjmp_table", self);
    // Needed for MSVC 2017 15.5 CRT
    self.enclave_config_index = try internal.addSymbol("__enclave_config", self);
    // Needed for MSVC 2019 16.8 CRT
    self.guard_eh_cont_count_index = try internal.addSymbol("__guard_eh_cont_count", self);
    self.guard_eh_cont_table_index = try internal.addSymbol("__guard_eh_cont_table", self);
}

fn convertCommonSymbols(self: *Coff) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.convertCommonSymbols(self);
    }
}

fn claimUnresolved(self: *Coff) !void {
    const claim = struct {
        fn claim(coff_file: *Coff, sym_index: Symbol.Index) !void {
            const gpa = coff_file.base.allocator;
            const sym = coff_file.getSymbol(sym_index);
            sym.value = 0;
            sym.atom = 0;
            sym.coff_sym_idx = 0;
            sym.file = coff_file.internal_object_index.?;
            sym.flags = .{ .global = true, .import = true, .weak = true };
            try coff_file.getInternalObject().?.symbols.append(gpa, sym_index);
        }
    }.claim;

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;

        for (object.symbols.items, 0..) |sym_index, i| {
            const sym = self.getSymbol(sym_index);
            if (sym.getFile(self)) |_| continue;
            if (!sym.flags.global and !sym.flags.weak) continue;

            if (sym.flags.weak) {
                const coff_sym_idx = @as(Symbol.Index, @intCast(i));
                const coff_sym = object.symtab.items[coff_sym_idx];
                const aux = object.auxtab.items[coff_sym.aux_index].weak_ext;
                const alt_index = object.symbols.items[aux.sym_index];
                const alt = self.getSymbol(alt_index);
                if (alt.getFile(self)) |_| {
                    sym.value = alt.value;
                    sym.file = alt.file;
                    sym.atom = alt.atom;
                    sym.coff_sym_idx = alt.coff_sym_idx;
                    sym.flags = alt.flags;
                    sym.extra = alt.extra;
                    continue;
                }
            }

            const is_undf_ok = sym.flags.weak; // TODO: or /force
            if (is_undf_ok) try claim(self, sym_index);
        }
    }

    if (self.load_config_used_index) |sym_index| {
        const sym = self.getSymbol(sym_index);
        if (sym.getFile(self) == null) {
            try claim(self, sym_index);
        }
    }
}

fn markExports(self: *Coff) void {
    _ = self;
    // TODO: traverse self.exports and for (self.objects.items) { object.exports }
    // and mark any referenced symbol as export.
}

fn markImports(self: *Coff) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.getSymbols()) |sym_index| {
            const sym = self.getSymbol(sym_index);
            const file = sym.getFile(self) orelse continue;
            if (!sym.flags.global) continue;
            if (file == .dll) sym.flags.import = true;
        }
    }

    for (self.undefined_symbols.keys()) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self)) |file| {
            if (file == .dll) sym.flags.import = true;
        }
    }
}

fn reportUndefs(self: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    var undefs = std.AutoHashMap(Symbol.Index, std.ArrayListUnmanaged(Atom.Index)).init(gpa);
    defer {
        var it = undefs.valueIterator();
        while (it.next()) |notes| {
            notes.deinit(gpa);
        }
        undefs.deinit();
    }

    for (self.objects.items) |index| {
        try self.getFile(index).?.object.reportUndefs(self, &undefs);
    }

    const max_notes = 4;

    var has_undefs = false;
    var it = undefs.iterator();
    while (it.next()) |entry| {
        const undef_sym = self.getSymbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @intFromBool(notes.items.len > max_notes);

        const err = try self.base.addErrorWithNotes(nnotes);
        try err.addMsg("undefined symbol: {s}", .{undef_sym.getName(self)});
        has_undefs = true;

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

    for (self.undefined_symbols.keys()) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self)) |_| continue;
        has_undefs = true;
        const err = try self.base.addErrorWithNotes(1);
        try err.addMsg("undefined symbol: {s}", .{sym.getName(self)});
        try err.addNote("/force command line option", .{});
    }

    if (has_undefs) return error.UndefinedSymbols;
}

fn parseMergeRules(self: *Coff) !void {
    const addRule = struct {
        fn addRule(coff_file: *Coff, from: []const u8, to: []const u8) !void {
            const gpa = coff_file.base.allocator;
            const from_rule = try coff_file.string_intern.insert(gpa, from);
            const to_rule = try coff_file.string_intern.insert(gpa, to);
            try coff_file.merge_rules.put(gpa, from_rule, to_rule);
        }
    }.addRule;

    // TODO break/report cycles, report duplicates
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        assert(object.alive);
        for (object.merge_rules.items) |rule| {
            try addRule(self, object.getString(rule.from), object.getString(rule.to));
        }
    }

    // Add default merge rules
    // try addRule(self, ".idata", ".rdata"); // TODO why does LLD do it?
    // try addRule(self, ".edata", ".rdata"); // TODO why does LLD do it?
    try addRule(self, ".didat", ".rdata");
    try addRule(self, ".xdata", ".rdata");
    try addRule(self, ".00cfg", ".rdata");
    try addRule(self, ".bss", ".data");
}

pub fn getMergeRule(self: *Coff, from: []const u8) ?struct { []const u8, i32 } {
    const from_off = self.string_intern.getOffset(from) orelse return null;
    const index = self.merge_rules.getIndex(from_off) orelse return null;
    const to_off = self.merge_rules.values()[index];
    return .{ self.string_intern.getAssumeExists(to_off), @intCast(index) };
}

fn createImportThunks(self: *Coff) !void {
    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        if (!dll.alive) continue;
        try dll.addThunks(self);
    }
}

fn collectBaseRelocs(self: *Coff) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.collectBaseRelocs(self);
    }
}

fn initSections(self: *Coff) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const out_section_number, const merge_rule_index = try object.initSection(atom, self);
            atom.out_section_number = out_section_number;
            atom.merge_rule_index = merge_rule_index;
        }
    }
    self.text_section_index = self.getSectionByName(".text");
    self.data_section_index = self.getSectionByName(".data");

    const needs_idata = for (self.dlls.values()) |index| {
        if (self.getFile(index).?.dll.alive) break true;
    } else false;
    if (needs_idata) {
        self.idata_section_index = try self.addSection(".idata", .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_READ = 1,
        });
    }

    if (self.base_relocs.entries.items.len > 0) {
        self.reloc_section_index = try self.addSection(".reloc", .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_READ = 1,
            .MEM_DISCARDABLE = 1,
        });
    }

    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        for (dll.thunks_table.items) |thunk_index| {
            const thunk = dll.getThunk(thunk_index) orelse continue;
            thunk.out_section_number = self.text_section_index.?;
        }
    }
}

/// Copying lld logic for now.
fn getSectionRank(self: *Coff, header: SectionHeader) u8 {
    const name = header.getName(self);
    if (mem.eql(u8, name, ".text")) return 0;
    if (mem.eql(u8, name, ".bss")) return 1;
    if (mem.eql(u8, name, ".rdata")) return 2;
    if (mem.eql(u8, name, ".buildid")) return 3;
    if (mem.eql(u8, name, ".data")) return 4;
    if (mem.eql(u8, name, ".pdata")) return 5;
    if (mem.eql(u8, name, ".idata")) return 6;
    if (mem.eql(u8, name, ".edata")) return 7;
    if (mem.eql(u8, name, ".didat")) return 8;
    if (mem.eql(u8, name, ".rsrc")) return 9;
    if (mem.eql(u8, name, ".reloc")) return 10;
    if (mem.eql(u8, name, ".ctors")) return 11;
    if (mem.eql(u8, name, ".dtors")) return 12;
    return std.math.maxInt(u8);
}

fn sortSections(self: *Coff) !void {
    const Entry = struct {
        index: u16,

        pub fn lessThan(coff_file: *Coff, lhs: @This(), rhs: @This()) bool {
            const lhs_header = coff_file.sections.items(.header)[lhs.index];
            const rhs_header = coff_file.sections.items(.header)[rhs.index];
            const lhs_rank = coff_file.getSectionRank(lhs_header);
            const rhs_rank = coff_file.getSectionRank(rhs_header);
            if (lhs_rank == rhs_rank) {
                return mem.order(u8, lhs_header.getName(coff_file), rhs_header.getName(coff_file)) == .lt;
            }
            return lhs_rank < rhs_rank;
        }
    };

    const gpa = self.base.allocator;

    var entries = try std.ArrayList(Entry).initCapacity(gpa, self.sections.slice().len);
    defer entries.deinit();
    for (0..self.sections.slice().len) |index| {
        entries.appendAssumeCapacity(.{ .index = @intCast(index) });
    }

    mem.sort(Entry, entries.items, self, Entry.lessThan);

    const backlinks = try gpa.alloc(u8, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.index] = @intCast(i);
    }

    var slice = self.sections.toOwnedSlice();
    defer slice.deinit(gpa);

    try self.sections.ensureTotalCapacity(gpa, slice.len);
    for (entries.items) |sorted| {
        self.sections.appendAssumeCapacity(slice.get(sorted.index));
    }

    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_section_number = backlinks[atom.out_section_number.?];
        }
    }

    for (&[_]*?u16{
        &self.text_section_index,
        &self.data_section_index,
        &self.idata_section_index,
        &self.reloc_section_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }
}

fn addAtomsToSections(self: *Coff) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_section_number.?];
            try atoms.append(self.base.allocator, atom_index);
        }
        for (object.symbols.items) |sym_index| {
            const sym = self.getSymbol(sym_index);
            const atom = sym.getAtom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (sym.getFile(self).?.getIndex() != index) continue;
            sym.out_section_number = atom.out_section_number;
        }
    }

    // Sort atoms by name suffix and merge rule index.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#grouped-sections-object-only
    const sortFn = struct {
        fn sortFn(ctx: *Coff, lhs: Atom.Index, rhs: Atom.Index) bool {
            const lhs_atom = ctx.getAtom(lhs).?;
            const lhs_name_suffix = lhs_atom.getNameSuffix(ctx);
            const rhs_atom = ctx.getAtom(rhs).?;
            const rhs_name_suffix = rhs_atom.getNameSuffix(ctx);
            if (lhs_atom.merge_rule_index == rhs_atom.merge_rule_index) {
                const rel = mem.order(u8, lhs_name_suffix, rhs_name_suffix);
                if (rel == .eq) {
                    if (lhs_atom.file == rhs_atom.file) {
                        return lhs < rhs;
                    }
                    return lhs_atom.file < rhs_atom.file;
                }
                return rel == .lt;
            }
            return lhs_atom.merge_rule_index < rhs_atom.merge_rule_index;
        }
    }.sortFn;

    for (self.sections.items(.atoms)) |*atoms| {
        mem.sort(Atom.Index, atoms.items, self, sortFn);
    }

    // for (self.sections.items(.atoms), self.sections.items(.header)) |atoms, header| {
    //     std.debug.print("\n{s}\n", .{self.string_intern.getAssumeExists(header.name)});
    //     for (atoms.items) |atom_index| {
    //         const atom = self.getAtom(atom_index).?;
    //         std.debug.print("  atom({d}) : {s} : {d} : {d}\n", .{ atom_index, atom.getName(self), atom.file, atom.merge_rule_index });
    //     }
    // }
}

fn updateSectionSizes(self: *Coff) !void {
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.atoms)) |*header, atoms| {
        if (atoms.items.len == 0) continue;

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            const atom_alignment = try std.math.powi(u32, 2, atom.alignment);
            const offset = mem.alignForward(u32, header.virtual_size, atom_alignment);
            const padding = offset - header.virtual_size;
            atom.value = offset;
            header.virtual_size += padding + atom.size;
            if (atom.hasData(self)) {
                header.size_of_raw_data += padding + atom.size;
            }
            header.setAlignment(@max(header.getAlignment() orelse 0, atom.alignment));
        }
    }

    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        for (dll.thunks_table.items) |thunk_index| {
            const thunk = dll.getThunk(thunk_index) orelse continue;
            const header = &self.sections.items(.header)[thunk.out_section_number.?];
            const thunk_alignment = try std.math.powi(u32, 2, Dll.Thunk.thunkAlignment(self));
            const offset = mem.alignForward(u32, header.virtual_size, thunk_alignment);
            const padding = offset - header.virtual_size;
            thunk.value = offset;
            header.virtual_size += padding + Dll.Thunk.thunkSize(self);
            header.size_of_raw_data += padding + Dll.Thunk.thunkSize(self);
            header.setAlignment(@max(header.getAlignment() orelse 0, Dll.Thunk.thunkAlignment(self)));
        }
    }

    if (self.idata_section_index != null) {
        try self.updateImportSectionSize();
    }

    if (self.reloc_section_index) |index| {
        const header = &self.sections.items(.header)[index];
        const size = try self.base_relocs.updateSize(self);
        header.virtual_size = size;
        header.size_of_raw_data = size;
        header.setAlignment(2);
    }

    for (slice.items(.header)) |*header| {
        header.size_of_raw_data = mem.alignForward(u32, header.size_of_raw_data, self.getFileAlignment());
    }
}

fn updateImportSectionSize(self: *Coff) !void {
    var dir_table_size: u32 = 0;
    var lookup_table_size: u32 = 0;
    var names_table_size: u32 = 0;
    var dll_names_size: u32 = 0;
    var iat_size: u32 = 0;

    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        if (!dll.alive) continue;
        const ctx = &dll.idata_ctx;

        ctx.dir_table_offset = dir_table_size;
        ctx.lookup_table_offset = lookup_table_size;
        ctx.names_table_offset = names_table_size;
        ctx.dll_names_offset = dll_names_size;
        ctx.iat_offset = iat_size;

        try dll.updateImportSectionSize(self);

        dir_table_size += @sizeOf(coff.ImportDirectoryEntry);
        lookup_table_size += ctx.lookup_table_size;
        iat_size += ctx.iat_size;
        names_table_size += ctx.names_table_size;
        dll_names_size += ctx.dll_names_size;
    }

    dir_table_size += @sizeOf(coff.ImportDirectoryEntry); // sentinel

    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        if (!dll.alive) continue;
        const ctx = &dll.idata_ctx;

        ctx.lookup_table_offset += dir_table_size;
        ctx.iat_offset += dir_table_size + lookup_table_size;
        ctx.names_table_offset += dir_table_size + lookup_table_size + iat_size;
        ctx.dll_names_offset += dir_table_size + lookup_table_size + iat_size + names_table_size;
    }

    const needed_size = dir_table_size + lookup_table_size + names_table_size + dll_names_size + iat_size;
    const header = &self.sections.items(.header)[self.idata_section_index.?];
    header.virtual_size = needed_size;
    header.size_of_raw_data = needed_size;
    header.setAlignment(3);
}

fn updateDataDirectorySizes(self: *Coff) void {
    if (self.idata_section_index) |_| {
        const import_dir = &self.data_dirs[@intFromEnum(coff.DirectoryEntry.IMPORT)];
        const iat_dir = &self.data_dirs[@intFromEnum(coff.DirectoryEntry.IAT)];

        var import_size: u32 = @sizeOf(coff.ImportDirectoryEntry);
        var iat_offset: u32 = std.math.maxInt(u32);
        var iat_size: u32 = 0;
        for (self.dlls.values()) |index| {
            const ctx = self.getFile(index).?.dll.idata_ctx;
            import_size += @sizeOf(coff.ImportDirectoryEntry);
            iat_offset = @min(iat_offset, ctx.iat_offset);
            iat_size += ctx.iat_size;
        }
        import_dir.size = import_size;
        iat_dir.virtual_address = iat_offset;
        iat_dir.size = iat_size;
    }

    if (self.reloc_section_index) |index| {
        const header = self.sections.items(.header)[index];
        const dir = &self.data_dirs[@intFromEnum(coff.DirectoryEntry.BASERELOC)];
        dir.size = header.virtual_size;
    }
}

fn allocateSections(self: *Coff) !void {
    const sect_align = self.getSectionAlignment();
    const file_align = self.getFileAlignment();
    const size_headers = mem.alignForward(u32, self.getSizeOfHeaders(), file_align);

    // According to LLD, the first page is left unmapped.
    var vmaddr = mem.alignForward(u32, size_headers, sect_align);
    var fileoff = size_headers;

    for (self.sections.items(.header)) |*header| {
        vmaddr = mem.alignForward(u32, vmaddr, sect_align);
        header.virtual_address = vmaddr;
        vmaddr += header.virtual_size;

        fileoff = mem.alignForward(u32, fileoff, file_align);
        header.pointer_to_raw_data = fileoff;
        fileoff += header.size_of_raw_data;
    }
}

fn allocateDataDirectories(self: *Coff) void {
    if (self.idata_section_index) |index| {
        const header = self.sections.items(.header)[index];
        const import_dir = &self.data_dirs[@intFromEnum(coff.DirectoryEntry.IMPORT)];
        const iat_dir = &self.data_dirs[@intFromEnum(coff.DirectoryEntry.IAT)];
        import_dir.virtual_address += header.virtual_address;
        iat_dir.virtual_address += header.virtual_address;
    }

    if (self.reloc_section_index) |index| {
        const header = self.sections.items(.header)[index];
        const dir = &self.data_dirs[@intFromEnum(coff.DirectoryEntry.BASERELOC)];
        dir.virtual_address += header.virtual_address;
    }
}

fn allocateSyntheticSymbols(self: *Coff) void {
    _ = self;
    // TODO __guard_* symbols
}

fn writeAtoms(self: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const cpu_arch = self.options.cpu_arch.?;
    const slice = self.sections.slice();

    for (slice.items(.header), slice.items(.atoms)) |header, atoms| {
        if (atoms.items.len == 0) continue;
        if (header.flags.CNT_UNINITIALIZED_DATA == 1) continue;

        const buffer = try gpa.alloc(u8, header.size_of_raw_data);
        defer gpa.free(buffer);
        const padding_byte: u8 = if (header.flags.CNT_CODE == 1 and cpu_arch == .x86_64) 0xcc else 0;
        @memset(buffer, padding_byte);

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.flags.alive);
            if (!atom.hasData(self)) continue;
            const off = atom.value;
            try atom.getData(buffer[off..][0..atom.size], self);
            try atom.resolveRelocs(buffer[off..][0..atom.size], self);
        }

        try self.base.file.pwriteAll(buffer, header.pointer_to_raw_data);
    }

    // TODO: collect thunks by output section
    {
        const buffer = try gpa.alloc(u8, Dll.Thunk.thunkSize(self));
        defer gpa.free(buffer);
        @memset(buffer, 0);
        for (self.dlls.values()) |index| {
            const dll = self.getFile(index).?.dll;
            if (dll.thunks_table.items.len == 0) continue;
            for (dll.thunks_table.items) |thunk_index| {
                if (dll.getThunk(thunk_index)) |th| {
                    const header = self.sections.items(.header)[th.out_section_number.?];
                    const off = th.value;
                    try th.write(buffer, self);
                    try self.base.file.pwriteAll(buffer, header.pointer_to_raw_data + off);
                }
            }
        }
    }
}

fn writeImportSection(self: *Coff) !void {
    const sect_index = self.idata_section_index orelse return;
    const gpa = self.base.allocator;
    const header = self.sections.items(.header)[sect_index];
    const buffer = try gpa.alloc(u8, header.size_of_raw_data);
    defer gpa.free(buffer);
    @memset(buffer, 0);

    for (self.dlls.values()) |index| {
        try self.getFile(index).?.dll.writeImportSection(buffer, self);
    }

    try self.base.file.pwriteAll(buffer, header.pointer_to_raw_data);
}

fn writeBaseRelocs(self: *Coff) !void {
    const sect_index = self.reloc_section_index orelse return;
    const gpa = self.base.allocator;
    const header = self.sections.items(.header)[sect_index];
    const buffer = try gpa.alloc(u8, header.size_of_raw_data);
    defer gpa.free(buffer);
    @memset(buffer, 0);
    var stream = std.io.fixedBufferStream(buffer);
    try self.base_relocs.write(self, stream.writer());
    try self.base.file.pwriteAll(buffer, header.pointer_to_raw_data);
}

fn writeSectionHeaders(self: *Coff) !void {
    const offset = self.getSectionHeadersOffset();
    var headers = try std.ArrayList(coff.SectionHeader).initCapacity(self.base.allocator, self.sections.items(.header).len);
    defer headers.deinit();
    for (self.sections.items(.header)) |header| {
        const out = headers.addOneAssumeCapacity();
        out.* = .{
            .name = undefined,
            .virtual_size = header.virtual_size,
            .virtual_address = header.virtual_address,
            .size_of_raw_data = header.size_of_raw_data,
            .pointer_to_raw_data = header.pointer_to_raw_data,
            .pointer_to_relocations = header.pointer_to_relocations,
            .pointer_to_linenumbers = header.pointer_to_linenumbers,
            .number_of_relocations = header.number_of_relocations,
            .number_of_linenumbers = header.number_of_linenumbers,
            .flags = header.flags,
        };
        out.flags.ALIGN = 0;
        @memset(&out.name, 0);
        const name = self.string_intern.getAssumeExists(header.name);
        if (name.len >= out.name.len) {
            @memcpy(out.name[0 .. out.name.len - 1], name[0 .. out.name.len - 1]);
        } else {
            @memcpy(out.name[0..name.len], name);
        }
    }
    try self.base.file.pwriteAll(mem.sliceAsBytes(headers.items), offset);
}

fn writeDataDirectoryHeaders(self: *Coff) !void {
    const offset = self.getDataDirectoryHeadersOffset();
    try self.base.file.pwriteAll(mem.sliceAsBytes(&self.data_dirs), offset);
}

fn writeHeader(self: *Coff) !void {
    const gpa = self.base.allocator;

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    const writer = buffer.writer();

    try buffer.ensureTotalCapacity(self.getSizeOfHeaders());
    writer.writeAll(msdos_stub) catch unreachable;
    mem.writeInt(u32, buffer.items[0x3c..][0..4], msdos_stub.len, .little);

    writer.writeAll("PE\x00\x00") catch unreachable;
    const flags = coff.CoffHeaderFlags{
        .EXECUTABLE_IMAGE = 1,
        .DEBUG_STRIPPED = 1, // TODO
        .LARGE_ADDRESS_AWARE = 1,
    };

    const timestamp = std.time.timestamp();
    const size_of_optional_header = @as(u16, @intCast(self.getOptionalHeaderSize() + self.getDataDirectoryHeadersSize()));
    var coff_header = coff.CoffHeader{
        .machine = switch (self.options.cpu_arch.?) {
            .x86_64 => .X64,
            .aarch64 => .ARM64,
            else => unreachable,
        },
        .number_of_sections = @as(u16, @intCast(self.sections.slice().len)),
        .time_date_stamp = @as(u32, @truncate(@as(u64, @bitCast(timestamp)))),
        .pointer_to_symbol_table = 0, // TODO relocatable
        .number_of_symbols = 0,
        .size_of_optional_header = size_of_optional_header,
        .flags = flags,
    };

    writer.writeAll(mem.asBytes(&coff_header)) catch unreachable;

    const dll_flags: coff.DllFlags = .{
        .HIGH_ENTROPY_VA = 1, // TODO do we want to permit non-PIE builds at all?
        .DYNAMIC_BASE = 1,
        .TERMINAL_SERVER_AWARE = 1, // We are not a legacy app
        .NX_COMPAT = 1, // We are compatible with Data Execution Prevention
    };
    const subsystem: coff.Subsystem = .WINDOWS_CUI;
    const size_of_image: u32 = self.getSizeOfImage();
    const size_of_headers: u32 = mem.alignForward(u32, self.getSizeOfHeaders(), self.getFileAlignment());
    const base_of_code = if (self.text_section_index) |index|
        self.sections.items(.header)[index].virtual_address
    else
        0;

    var size_of_code: u32 = 0;
    var size_of_initialized_data: u32 = 0;
    var size_of_uninitialized_data: u32 = 0;
    for (self.sections.items(.header)) |header| {
        if (header.flags.CNT_CODE == 1) {
            size_of_code += header.size_of_raw_data;
        }
        if (header.flags.CNT_INITIALIZED_DATA == 1) {
            size_of_initialized_data += header.size_of_raw_data;
        }
        if (header.flags.CNT_UNINITIALIZED_DATA == 1) {
            size_of_uninitialized_data += header.size_of_raw_data;
        }
    }

    const entry_addr = if (self.entry_index) |index|
        self.getSymbol(index).getAddress(.{}, self)
    else
        0;
    const opt_header = coff.OptionalHeaderPE64{
        .magic = coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        .major_linker_version = 0,
        .minor_linker_version = 0,
        .size_of_code = size_of_code,
        .size_of_initialized_data = size_of_initialized_data,
        .size_of_uninitialized_data = size_of_uninitialized_data,
        .address_of_entry_point = entry_addr,
        .base_of_code = base_of_code,
        .image_base = self.getImageBase(),
        .section_alignment = self.getSectionAlignment(),
        .file_alignment = self.getFileAlignment(),
        .major_operating_system_version = 6,
        .minor_operating_system_version = 0,
        .major_image_version = 0,
        .minor_image_version = 0,
        .major_subsystem_version = 6,
        .minor_subsystem_version = 0,
        .win32_version_value = 0,
        .size_of_image = size_of_image,
        .size_of_headers = size_of_headers,
        .checksum = 0,
        .subsystem = subsystem,
        .dll_flags = dll_flags,
        .size_of_stack_reserve = self.getSizeOfStackReserve(),
        .size_of_stack_commit = self.getSizeOfStackCommit(),
        .size_of_heap_reserve = self.getSizeOfHeapReserve(),
        .size_of_heap_commit = self.getSizeOfHeapCommit(),
        .loader_flags = 0,
        .number_of_rva_and_sizes = @intCast(self.data_dirs.len),
    };
    writer.writeAll(mem.asBytes(&opt_header)) catch unreachable;

    try self.base.file.pwriteAll(buffer.items, 0);
}

pub fn isCoffObj(buffer: *const [@sizeOf(coff.CoffHeader)]u8) bool {
    const header = @as(*align(1) const coff.CoffHeader, @ptrCast(buffer)).*;
    if (header.machine == .UNKNOWN and header.number_of_sections == 0xffff) return false;
    if (header.size_of_optional_header != 0) return false;
    return true;
}

pub fn isImportLib(buffer: *const [@sizeOf(coff.ImportHeader)]u8) bool {
    const header = @as(*align(1) const coff.ImportHeader, @ptrCast(buffer)).*;
    return header.sig1 == .UNKNOWN and header.sig2 == 0xffff;
}

pub fn isArchive(data: *const [Archive.magic.len]u8) bool {
    if (!mem.eql(u8, data, Archive.magic)) {
        extra_log.debug("invalid archive magic: expected '{s}', found '{s}'", .{ Archive.magic, data });
        return false;
    }
    return true;
}

fn getDefaultEntryPoint(self: *Coff) [:0]const u8 {
    // TODO: actually implement this
    _ = self;
    return "mainCRTStartup";
}

fn getSectionAlignment(self: Coff) u32 {
    return self.options.@"align" orelse 0x1000;
}

fn getFileAlignment(self: Coff) u32 {
    return self.options.file_align orelse 0x200;
}

fn getSizeOfStackReserve(self: Coff) u32 {
    _ = self;
    // TODO handle user flag
    return 0x1000000;
}

fn getSizeOfStackCommit(self: Coff) u32 {
    _ = self;
    // TODO handle user flag
    return 0x1000;
}

fn getSizeOfHeapReserve(self: Coff) u32 {
    _ = self;
    // TODO handle user flag
    return 0x100000;
}

fn getSizeOfHeapCommit(self: Coff) u32 {
    _ = self;
    // TODO handle user flag
    return 0x1000;
}

fn getSizeOfHeaders(self: Coff) u32 {
    const msdos_hdr_size = msdos_stub.len + 4;
    return @as(u32, @intCast(msdos_hdr_size + @sizeOf(coff.CoffHeader) + self.getOptionalHeaderSize() +
        self.getDataDirectoryHeadersSize() + self.getSectionHeadersSize()));
}

fn getOptionalHeaderSize(self: Coff) u32 {
    _ = self;
    return @sizeOf(coff.OptionalHeaderPE64);
}

fn getDataDirectoryHeadersSize(self: Coff) u32 {
    return @intCast(self.data_dirs.len * @sizeOf(coff.ImageDataDirectory));
}

fn getSectionHeadersSize(self: Coff) u32 {
    return @intCast(self.sections.slice().len * @sizeOf(coff.SectionHeader));
}

fn getDataDirectoryHeadersOffset(self: Coff) u32 {
    const msdos_hdr_size = msdos_stub.len + 4;
    return @intCast(msdos_hdr_size + @sizeOf(coff.CoffHeader) + self.getOptionalHeaderSize());
}

fn getSectionHeadersOffset(self: Coff) u32 {
    return self.getDataDirectoryHeadersOffset() + self.getDataDirectoryHeadersSize();
}

fn getSizeOfImage(self: Coff) u32 {
    const alignment = self.getSectionAlignment();
    var image_size: u32 = mem.alignForward(u32, self.getSizeOfHeaders(), alignment);
    for (self.sections.items(.header)) |header| {
        image_size += mem.alignForward(u32, header.virtual_size, alignment);
    }
    return image_size;
}

pub fn getImageBase(self: Coff) u64 {
    // TODO handle user flag
    return switch (self.options.cpu_arch.?) {
        .aarch64 => 0x140000000,
        .x86_64, .x86 => 0x400000,
        else => unreachable,
    };
}

/// TODO convert from std.Target.Cpu.Arch into std.coff.MachineType and remove this.
fn cpuArchFromCoffMachineType(em: std.coff.MachineType) ?std.Target.Cpu.Arch {
    return switch (em) {
        .ARM64 => .aarch64,
        .X64 => .x86_64,
        else => null,
    };
}

pub fn addAlternateName(self: *Coff, from: []const u8, to: []const u8) !void {
    const gpa = self.base.allocator;
    const from_index = blk: {
        const off = try self.string_intern.insert(gpa, from);
        const gop = try self.getOrCreateGlobal(off);
        const sym = self.getSymbol(gop.index);
        sym.flags.alt_name = true;
        break :blk gop.index;
    };
    const to_index = blk: {
        const off = try self.string_intern.insert(gpa, to);
        const gop = try self.getOrCreateGlobal(off);
        break :blk gop.index;
    };
    try self.getSymbol(from_index).addExtra(.{ .alt_name = to_index }, self);
}

pub fn getFile(self: *Coff, index: File.Index) ?File {
    const tag = self.files.items(.tags)[index];
    return switch (tag) {
        .null => null,
        .internal => .{ .internal = &self.files.items(.data)[index].internal },
        .object => .{ .object = &self.files.items(.data)[index].object },
        .dll => .{ .dll = &self.files.items(.data)[index].dll },
    };
}

pub fn addFileHandle(self: *Coff, file: std.fs.File) !File.HandleIndex {
    const gpa = self.base.allocator;
    const index: File.HandleIndex = @intCast(self.file_handles.items.len);
    const fh = try self.file_handles.addOne(gpa);
    fh.* = file;
    return index;
}

pub fn getFileHandle(self: Coff, index: File.HandleIndex) File.Handle {
    assert(index < self.file_handles.items.len);
    return self.file_handles.items[index];
}

pub fn getInternalObject(self: *Coff) ?*InternalObject {
    const index = self.internal_object_index orelse return null;
    return self.getFile(index).?.internal;
}

pub fn addSection(self: *Coff, name: []const u8, flags: coff.SectionHeaderFlags) !u16 {
    const gpa = self.base.allocator;
    const index = @as(u16, @intCast(try self.sections.addOne(gpa)));
    self.sections.set(index, .{
        .header = .{
            .name = try self.string_intern.insert(gpa, name),
            .virtual_address = 0,
            .virtual_size = 0,
            .pointer_to_raw_data = 0,
            .size_of_raw_data = 0,
            .pointer_to_relocations = 0,
            .number_of_relocations = 0,
            .pointer_to_linenumbers = 0,
            .number_of_linenumbers = 0,
            .flags = flags,
        },
    });
    return index;
}

pub fn getSectionByName(self: *Coff, name: []const u8) ?u16 {
    for (self.sections.items(.header), 0..) |header, index| {
        if (mem.eql(u8, header.getName(self), name)) return @intCast(index);
    }
    return null;
}

pub fn addAtom(self: *Coff) !Atom.Index {
    const index = @as(Atom.Index, @intCast(self.atoms.items.len));
    const atom = try self.atoms.addOne(self.base.allocator);
    atom.* = .{};
    return index;
}

pub fn getAtom(self: *Coff, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn addSymbol(self: *Coff) !Symbol.Index {
    const index = @as(Symbol.Index, @intCast(self.symbols.items.len));
    const symbol = try self.symbols.addOne(self.base.allocator);
    symbol.* = .{};
    return index;
}

pub fn getSymbol(self: *Coff, index: Symbol.Index) *Symbol {
    assert(index < self.symbols.items.len);
    return &self.symbols.items[index];
}

pub fn addSymbolExtra(self: *Coff, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).@"struct".fields;
    try self.symbols_extra.ensureUnusedCapacity(self.base.allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

pub fn addSymbolExtraAssumeCapacity(self: *Coff, extra: Symbol.Extra) u32 {
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

pub fn getSymbolExtra(self: Coff, index: u32) ?Symbol.Extra {
    if (index == 0) return null;
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

pub fn setSymbolExtra(self: *Coff, index: u32, extra: Symbol.Extra) void {
    assert(index > 0);
    const fields = @typeInfo(Symbol.Extra).@"struct".fields;
    inline for (fields, 0..) |field, i| {
        self.symbols_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compileError("bad field type"),
        };
    }
}

const GetOrCreateGlobalResult = struct {
    found_existing: bool,
    index: Symbol.Index,
};

pub fn getOrCreateGlobal(self: *Coff, off: u32) !GetOrCreateGlobalResult {
    const gpa = self.base.allocator;
    const gop = try self.globals.getOrPut(gpa, off);
    if (!gop.found_existing) {
        const index = try self.addSymbol();
        const global = self.getSymbol(index);
        global.flags.global = true;
        global.name = off;
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn dumpState(self: *Coff) std.fmt.Formatter(fmtDumpState) {
    return .{ .data = self };
}

fn fmtDumpState(
    self: *Coff,
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
        try writer.print("{}{}\n", .{
            object.fmtAtoms(self),
            object.fmtSymbols(self),
        });
    }
    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        try writer.print("dll({d}) : {s}", .{ index, dll.path });
        if (!dll.alive) try writer.writeAll(" : [*]");
        try writer.writeByte('\n');
        try writer.print("{}{}\n", .{
            dll.fmtSymbols(self),
            dll.fmtThunks(self),
        });
    }
    if (self.getInternalObject()) |internal| {
        try writer.print("internal({d}) : internal\n", .{internal.index});
        try writer.print("{}\n", .{internal.fmtSymbols(self)});
    }
    try writer.writeByte('\n');
    try writer.writeAll("Output sections\n");
    try writer.print("{}\n", .{self.fmtSections()});
}

fn fmtSections(self: *Coff) std.fmt.Formatter(formatSections) {
    return .{ .data = self };
}

fn formatSections(
    self: *Coff,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.sections.items(.header), 0..) |header, i| {
        try writer.print("sect({d}) : {s} : @{x} ({x}) : align({?x}) : size({x};{x}) : flags({})\n", .{
            i,
            header.getName(self),
            header.virtual_address,
            header.pointer_to_raw_data,
            header.getAlignment(),
            header.virtual_size,
            header.size_of_raw_data,
            fmtSectionFlags(header.flags),
        });
    }
}

fn fmtSectionFlags(flags: coff.SectionHeaderFlags) std.fmt.Formatter(formatSectionFlags) {
    return .{ .data = flags };
}

fn formatSectionFlags(
    flags: coff.SectionHeaderFlags,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    inline for (@typeInfo(coff.SectionHeaderFlags).@"struct".fields) |field| {
        if (@field(flags, field.name) == 0b1) {
            try writer.writeAll(field.name ++ " ");
        }
    }
}

const Section = struct {
    header: SectionHeader,
    atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
};

pub const SectionHeader = struct {
    name: u32,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    flags: coff.SectionHeaderFlags,

    pub fn getName(hdr: SectionHeader, coff_file: *Coff) [:0]const u8 {
        return coff_file.string_intern.getAssumeExists(hdr.name);
    }

    pub fn isComdat(hdr: SectionHeader) bool {
        return hdr.flags.LNK_COMDAT == 0b1;
    }

    pub fn isCode(hdr: SectionHeader) bool {
        return hdr.flags.CNT_CODE == 0b1;
    }

    pub fn getAlignment(hdr: SectionHeader) ?u4 {
        if (hdr.flags.ALIGN == 0) return null;
        return hdr.flags.ALIGN - 1;
    }

    pub fn setAlignment(hdr: *SectionHeader, alignment: u4) void {
        assert(alignment <= 0xd);
        hdr.flags.ALIGN = alignment + 1;
    }
};

pub const LinkObject = struct {
    name: []const u8,
    path: []const u8 = "",
    tag: enum { explicit, default_lib },

    pub fn format(
        obj: LinkObject,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        switch (obj.tag) {
            .explicit => {},
            .default_lib => try writer.writeAll("/defaultlib:"),
        }
        try writer.print("{s}", .{obj.name});
    }
};

const AlternateName = struct {
    name: u32,
    index: Symbol.Index,
};

pub const base_tag = Zld.Tag.coff;

const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const coff = std.coff;
const fs = std.fs;
const log = std.log.scoped(.coff);
const extra_log = std.log.scoped(.coff_extra);
const mem = std.mem;
const msdos_stub = @embedFile("Coff/msdos-stub.bin");
const state_log = std.log.scoped(.state);
const std = @import("std");
const synthetic = @import("Coff/synthetic.zig");
const trace = @import("tracy.zig").trace;

const Allocator = mem.Allocator;
const Archive = @import("Coff/Archive.zig");
const Atom = @import("Coff/Atom.zig");
const Coff = @This();
const Dll = @import("Coff/Dll.zig");
const File = @import("Coff/file.zig").File;
const InternalObject = @import("Coff/InternalObject.zig");
const Object = @import("Coff/Object.zig");
pub const Options = @import("Coff/Options.zig");
const RelocSection = synthetic.RelocSection;
const StringTable = @import("StringTable.zig");
const Symbol = @import("Coff/Symbol.zig");
const ThreadPool = std.Thread.Pool;
const Zld = @import("Zld.zig");
