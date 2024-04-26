base: Zld,
options: Options,

internal_object_index: ?File.Index = null,
objects: std.ArrayListUnmanaged(File.Index) = .{},
dlls: std.StringArrayHashMapUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},

sections: std.MultiArrayList(Section) = .{},

string_intern: StringTable = .{},

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
globals: std.AutoHashMapUnmanaged(u32, Symbol.Index) = .{},
/// Global symbols we need to resolve for the link to succeed.
undefined_symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},
merge_rules: std.AutoArrayHashMapUnmanaged(u32, u32) = .{},

entry_index: ?Symbol.Index = null,
image_base_index: ?Symbol.Index = null,

idata: IdataSection = .{},

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
    self.idata.deinit(gpa);
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

    try self.initSyntheticSections();

    if (build_options.enable_logging)
        state_log.debug("{}", .{self.dumpState()});

    return error.Todo;
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

    log.debug("parsing positional {}", .{resolved_obj});

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
        log.debug("{}: adding implicit import {}", .{ object.fmtPath(), dir_obj });
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
        const member_cpu_arch = member.machine.toTargetCpuArch() orelse {
            log.debug("{s}({s}): TODO unhandled machine type {}", .{ obj.path, member.name, member.machine });
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
    const gpa = self.base.allocator;

    {
        // Entry point
        const name = self.getDefaultEntryPoint();
        const off = try self.string_intern.insert(gpa, name);
        const gop = try self.getOrCreateGlobal(off);
        self.entry_index = gop.index;
    }
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

    for (self.undefined_symbols.items) |index| {
        if (self.getSymbol(index).getFile(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }

    if (self.entry_index) |index| {
        if (self.getSymbol(index).getFile(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        if (object.alive) object.markLive(self);
    }
}

fn resolveSyntheticSymbols(self: *Coff) !void {
    const internal = self.getInternalObject() orelse return;

    self.image_base_index = try internal.addSymbol("__ImageBase", self);
}

fn convertCommonSymbols(self: *Coff) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.convertCommonSymbols(self);
    }
}

fn claimUnresolved(self: *Coff) !void {
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
            if (is_undf_ok) {
                sym.value = 0;
                sym.atom = 0;
                sym.coff_sym_idx = 0;
                sym.file = self.internal_object_index.?;
                sym.flags = .{ .global = true, .import = true, .weak = true };
                try self.getInternalObject().?.symbols.append(self.base.allocator, sym_index);
            }
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

    for (self.undefined_symbols.items) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self)) |file| {
            if (file == .dll) sym.flags.import = true;
        }
    }

    if (self.entry_index) |index| {
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

    if (undefs.count() == 0) return;

    const max_notes = 4;

    var it = undefs.iterator();
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

fn initSyntheticSections(self: *Coff) !void {
    for (self.dlls.values()) |index| {
        const dll = self.getFile(index).?.dll;
        for (dll.symbols.items, dll.exports.items, 0..) |sym_index, exp, exp_index| {
            const sym = self.getSymbol(sym_index);
            if (!sym.flags.import) continue;

            switch (exp.type) {
                .DATA, .CONST => {
                    self.base.fatal("{s}: TODO unhandled import type for symbol '{s}':  {s}", .{
                        dll.path,
                        sym.getName(self),
                        @tagName(exp.type),
                    });
                },
                .CODE => {
                    sym.flags.import_thunk = true;
                    try self.idata.addThunk(sym_index, @intCast(exp_index), self);
                },
                else => |other| {
                    self.base.fatal("{s}: unknown import type for symbol '{s}': 0x{x}", .{
                        dll.path,
                        sym.getName(self),
                        other,
                    });
                },
            }
        }
    }
}

pub fn isCoffObj(buffer: *const [@sizeOf(coff.CoffHeader)]u8) bool {
    const header = @as(*align(1) const coff.CoffHeader, @ptrCast(buffer)).*;
    if (header.machine == .Unknown and header.number_of_sections == 0xffff) return false;
    if (header.size_of_optional_header != 0) return false;
    return true;
}

pub fn isImportLib(buffer: *const [@sizeOf(coff.ImportHeader)]u8) bool {
    const header = @as(*align(1) const coff.ImportHeader, @ptrCast(buffer)).*;
    return header.sig1 == .Unknown and header.sig2 == 0xffff;
}

pub fn isArchive(data: *const [Archive.magic.len]u8) bool {
    if (!mem.eql(u8, data, Archive.magic)) {
        log.debug("invalid archive magic: expected '{s}', found '{s}'", .{ Archive.magic, data });
        return false;
    }
    return true;
}

fn getDefaultEntryPoint(self: *Coff) [:0]const u8 {
    // TODO: actually implement this
    _ = self;
    return "mainCRTStartup";
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
    log.debug("adding /alternatename:{s}={s}", .{
        self.getSymbol(from_index).getName(self),
        self.getSymbol(to_index).getName(self),
    });
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
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    try self.symbols_extra.ensureUnusedCapacity(self.base.allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

pub fn addSymbolExtraAssumeCapacity(self: *Coff, extra: Symbol.Extra) u32 {
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

pub fn getSymbolExtra(self: Coff, index: u32) ?Symbol.Extra {
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

pub fn setSymbolExtra(self: *Coff, index: u32, extra: Symbol.Extra) void {
    assert(index > 0);
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
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

fn addMergeRule(self: *Coff, from: []const u8, to: []const u8) !void {
    const gpa = self.base.allocator;
    const from_rule = try self.string_intern.insert(gpa, from);
    const to_rule = try self.string_intern.insert(gpa, to);
    try self.merge_rules.put(gpa, from_rule, to_rule);
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
        try writer.print("{}\n", .{
            dll.fmtSymbols(self),
        });
    }
    if (self.getInternalObject()) |internal| {
        try writer.print("internal({d}) : internal\n", .{internal.index});
        try writer.print("{}\n", .{internal.fmtSymbols(self)});
    }
    try writer.writeByte('\n');
    try writer.writeAll("idata\n");
    for (self.idata.entries.items, 0..) |entry, i| {
        const sym = entry.getSymbol(self);
        const exp = entry.getExport(self);
        try writer.print("  {d} => {d} '{s}' ({s})\n", .{
            i,                 entry.sym_index,
            sym.getName(self), @tagName(exp.type),
        });
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

    pub fn isComdat(hdr: SectionHeader) bool {
        return hdr.flags.LNK_COMDAT == 0b1;
    }

    pub fn isCode(hdr: SectionHeader) bool {
        return hdr.flags.CNT_CODE == 0b1;
    }

    pub fn getAlignment(hdr: SectionHeader) ?u16 {
        if (hdr.flags.ALIGN == 0) return null;
        return hdr.flags.ALIGN - 1;
    }

    pub fn setAlignment(hdr: *SectionHeader, alignment: u16) void {
        assert(alignment > 0 and alignment <= 8192);
        hdr.flags.ALIGN = std.math.log2_int(u16, alignment);
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
const mem = std.mem;
const state_log = std.log.scoped(.state);
const std = @import("std");
const synthetic = @import("Coff/synthetic.zig");
const trace = @import("tracy.zig").trace;

const Allocator = mem.Allocator;
const Archive = @import("Coff/Archive.zig");
const Atom = @import("Coff/Atom.zig");
const Coff = @This();
const File = @import("Coff/file.zig").File;
const IdataSection = synthetic.IdataSection;
const InternalObject = @import("Coff/InternalObject.zig");
const Object = @import("Coff/Object.zig");
pub const Options = @import("Coff/Options.zig");
const StringTable = @import("StringTable.zig");
const Symbol = @import("Coff/Symbol.zig");
const ThreadPool = std.Thread.Pool;
const Zld = @import("Zld.zig");
