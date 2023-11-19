base: Zld,
arena: std.heap.ArenaAllocator.State,
options: Options,

dyld_info_cmd: macho.dyld_info_command = .{},
symtab_cmd: macho.symtab_command = .{},
dysymtab_cmd: macho.dysymtab_command = .{},
function_starts_cmd: macho.linkedit_data_command = .{ .cmd = .FUNCTION_STARTS },
data_in_code_cmd: macho.linkedit_data_command = .{ .cmd = .DATA_IN_CODE },
uuid_cmd: macho.uuid_command = .{
    .uuid = [_]u8{0} ** 16,
},
codesig_cmd: macho.linkedit_data_command = .{ .cmd = .CODE_SIGNATURE },

internal_object_index: ?File.Index = null,
objects: std.ArrayListUnmanaged(File.Index) = .{},
dylibs: std.ArrayListUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},

segments: std.ArrayListUnmanaged(macho.segment_command_64) = .{},
sections: std.MultiArrayList(Section) = .{},

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
globals: std.AutoHashMapUnmanaged(u32, Symbol.Index) = .{},
/// This table will be populated after `scanRelocs` has run.
/// Key is symbol index.
undefs: std.AutoHashMapUnmanaged(Symbol.Index, std.ArrayListUnmanaged(Atom.Index)) = .{},

got_sect_index: ?u8 = null,
stubs_sect_index: ?u8 = null,
stubs_helper_sect_index: ?u8 = null,
la_symbol_ptr_sect_index: ?u8 = null,
tlv_sect_index: ?u8 = null,

mh_execute_header_index: ?Symbol.Index = null,
dyld_stub_binder_index: ?Symbol.Index = null,
dso_handle_index: ?Symbol.Index = null,

entry_index: ?Symbol.Index = null,

string_intern: StringTable(.string_intern) = .{},

got: GotSection = .{},
stubs: StubsSection = .{},
stubs_helper: StubsHelperSection = .{},
la_symbol_ptr: LaSymbolPtrSection = .{},
tlv: TlvSection = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

pub fn openPath(allocator: Allocator, options: Options, thread_pool: *ThreadPool) !*MachO {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options, thread_pool);
    errdefer self.base.destroy();

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: Allocator, options: Options, thread_pool: *ThreadPool) !*MachO {
    const self = try gpa.create(MachO);
    self.* = .{
        .base = .{
            .tag = .macho,
            .allocator = gpa,
            .file = undefined,
            .thread_pool = thread_pool,
        },
        .arena = std.heap.ArenaAllocator.init(gpa).state,
        .options = options,
    };
    return self;
}

pub fn deinit(self: *MachO) void {
    const gpa = self.base.allocator;

    self.symbols.deinit(gpa);
    self.symbols_extra.deinit(gpa);
    self.globals.deinit(gpa);
    self.undefs.deinit(gpa);
    self.string_intern.deinit(gpa);

    self.objects.deinit(gpa);
    self.dylibs.deinit(gpa);

    for (self.files.items(.tags), self.files.items(.data)) |tag, *data| switch (tag) {
        .null => {},
        .internal => data.internal.deinit(gpa),
        .object => data.object.deinit(gpa),
        .dylib => data.dylib.deinit(gpa),
    };
    self.files.deinit(gpa);

    self.segments.deinit(gpa);
    self.sections.deinit(gpa);
    self.atoms.deinit(gpa);

    self.got.deinit(gpa);
    self.stubs.deinit(gpa);
    self.tlv.deinit(gpa);

    self.arena.promote(gpa).deinit();
}

pub fn flush(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    // Atom at index 0 is reserved as null atom
    try self.atoms.append(gpa, .{});
    // Append empty string to string tables
    try self.string_intern.buffer.append(gpa, 0);
    // Append null file
    try self.files.append(gpa, .null);
    // Append null symbols
    try self.symbols.append(gpa, .{});
    try self.symbols_extra.append(gpa, 0);

    var arena_allocator = self.arena.promote(gpa);
    defer self.arena = arena_allocator.state;
    const arena = arena_allocator.allocator();

    const syslibroot = self.options.syslibroot;

    // Resolve paths
    log.debug("library search dirs", .{});
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.lib_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try lib_dirs.append(search_dir);
            log.debug("  {s}", .{dir});
        } else {
            self.base.warn("{s}: library search directory not found", .{dir});
        }
    }

    log.debug("framework search dirs", .{});
    var framework_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.framework_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try framework_dirs.append(search_dir);
            log.debug("  {s}", .{dir});
        } else {
            self.base.warn("{s}: framework search directory not found", .{dir});
        }
    }

    for (self.options.positionals) |obj| {
        try self.parsePositional(arena, obj, lib_dirs.items, framework_dirs.items);
    }

    if (self.options.platform == null) {
        // Check if we have already inferred a version from env vars.
        inline for (self.options.inferred_platform_versions) |platform| {
            if (platform.version.value > 0) {
                self.options.platform = .{ .platform = platform.platform, .version = platform.version };
                break;
            }
        }
    }

    if (self.options.sdk_version == null) {
        // First, try inferring SDK version from the SDK path if we have one.
        if (self.options.syslibroot) |path| {
            self.options.sdk_version = Options.inferSdkVersionFromSdkPath(path);
        }
        // Next, if platform has been worked out to be macOS but wasn't inferred from env vars,
        // do a syscall.
        if (self.options.sdk_version == null and self.options.platform != null) blk: {
            if ((comptime builtin.target.isDarwin()) and
                self.options.platform.?.platform == .MACOS and
                self.options.inferred_platform_versions[0].version.value == 0)
            {
                var ver_str: [100]u8 = undefined;
                var size: usize = 100;
                std.os.sysctlbynameZ("kern.osrelease", &ver_str, &size, null, 0) catch {
                    std.log.warn("ERROR", .{});
                    break :blk;
                };
                const kern_ver = Options.Version.parse(ver_str[0 .. size - 1]) orelse break :blk;
                // According to Apple, kernel major version is 4 ahead of x in 10.
                const minor = @as(u8, @truncate((kern_ver.value >> 16) - 4));
                self.options.sdk_version = Options.Version.new(10, minor, 0);
            }
        }
    }

    // TODO parse dependent dylibs

    self.base.reportWarningsAndErrorsAndExit();

    // TODO dedup dylibs

    {
        const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object_index = index;
    }

    try self.resolveSymbols();

    // TODO kill __eh_frame atoms
    // TODO convert tentative definitions

    self.markImportsAndExports();

    self.entry_index = blk: {
        if (self.options.dylib) break :blk null;
        const entry_name = self.options.entry orelse "_main";
        break :blk self.getGlobalByName(entry_name);
    };
    if (!self.options.dylib and self.entry_index == null) {
        self.base.fatal("no entrypoint found: '{s}'", .{self.options.entry orelse "_main"});
    }

    // TODO dead strip atoms

    try self.initOutputSections();
    try self.resolveSyntheticSymbols();

    self.claimUnresolved();
    try self.scanRelocs();

    try self.initSyntheticSections();
    try self.sortSections();
    try self.addAtomsToSections();

    state_log.debug("{}", .{self.dumpState()});

    self.base.reportWarningsAndErrorsAndExit();
}

fn resolveSearchDir(
    arena: Allocator,
    dir: []const u8,
    syslibroot: ?[]const u8,
) !?[]const u8 {
    var candidates = std.ArrayList([]const u8).init(arena);

    if (fs.path.isAbsolute(dir)) {
        if (syslibroot) |root| {
            const common_dir = if (builtin.os.tag == .windows) blk: {
                // We need to check for disk designator and strip it out from dir path so
                // that we can concat dir with syslibroot.
                // TODO we should backport this mechanism to 'MachO.Dylib.parseDependentLibs()'
                const disk_designator = fs.path.diskDesignatorWindows(dir);

                if (mem.indexOf(u8, dir, disk_designator)) |where| {
                    break :blk dir[where + disk_designator.len ..];
                }

                break :blk dir;
            } else dir;
            const full_path = try fs.path.join(arena, &[_][]const u8{ root, common_dir });
            try candidates.append(full_path);
        }
    }

    try candidates.append(dir);

    for (candidates.items) |candidate| {
        // Verify that search path actually exists
        var tmp = fs.cwd().openDir(candidate, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return candidate;
    }

    return null;
}

fn resolvePathsFirst(arena: Allocator, dirs: []const []const u8, path: []const u8) !?[]const u8 {
    for (dirs) |dir| {
        for (&[_][]const u8{ ".tbd", ".dylib", ".a" }) |ext| {
            const with_ext = try std.fmt.allocPrint(arena, "{s}{s}", .{ path, ext });
            const full_path = try std.fs.path.join(arena, &[_][]const u8{ dir, with_ext });
            const file = std.fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            defer file.close();
            return full_path;
        }
    }
    return null;
}

fn resolveDylibsFirst(arena: Allocator, dirs: []const []const u8, path: []const u8) !?[]const u8 {
    for (dirs) |dir| {
        for (&[_][]const u8{ ".tbd", ".dylib" }) |ext| {
            const with_ext = try std.fmt.allocPrint(arena, "{s}{s}", .{ path, ext });
            const full_path = try std.fs.path.join(arena, &[_][]const u8{ dir, with_ext });
            const file = std.fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            defer file.close();
            return full_path;
        }
    }
    for (dirs) |dir| {
        const with_ext = try std.fmt.allocPrint(arena, "{s}.a", .{path});
        const full_path = try std.fs.path.join(arena, &[_][]const u8{ dir, with_ext });
        const file = std.fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer file.close();
        return full_path;
    }
    return null;
}

fn resolveLib(
    self: *MachO,
    arena: Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
) !?[]const u8 {
    const path = try std.fmt.allocPrint(arena, "lib{s}", .{name});
    const search_strategy = self.options.search_strategy orelse .paths_first;
    switch (search_strategy) {
        .paths_first => return try resolvePathsFirst(arena, search_dirs, path),
        .dylibs_first => return try resolveDylibsFirst(arena, search_dirs, path),
    }
}

fn resolveFramework(
    self: *MachO,
    arena: Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
) !?[]const u8 {
    const prefix = try std.fmt.allocPrint(arena, "{s}.framework", .{name});
    const path = try std.fs.path.join(arena, &[_][]const u8{ prefix, name });
    const search_strategy = self.options.search_strategy orelse .paths_first;
    switch (search_strategy) {
        .paths_first => return try resolvePathsFirst(arena, search_dirs, path),
        .dylibs_first => return try resolveDylibsFirst(arena, search_dirs, path),
    }
}

fn resolveFile(
    self: *MachO,
    arena: Allocator,
    obj: LinkObject,
    lib_dirs: []const []const u8,
    framework_dirs: []const []const u8,
) !LinkObject {
    const tracy = trace(@src());
    defer tracy.end();

    const full_path = blk: {
        switch (obj.tag) {
            .obj => {
                var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
                const full_path = std.fs.realpath(obj.path, &buffer) catch |err| switch (err) {
                    error.FileNotFound => {
                        self.base.fatal("file not found '{s}'", .{obj.path});
                        return error.ResolveFail;
                    },
                    else => |e| return e,
                };
                break :blk try arena.dupe(u8, full_path);
            },
            .lib => {
                const full_path = (try self.resolveLib(arena, lib_dirs, obj.path)) orelse {
                    const err = try self.base.addErrorWithNotes(2 + lib_dirs.len);
                    try err.addMsg("library not found for -l{s}", .{obj.path});
                    try err.addNote("searched in", .{});
                    for (lib_dirs) |dir| try err.addNote("{s}", .{dir});
                    return error.ResolveFail;
                };
                break :blk full_path;
            },
            .framework => {
                const full_path = (try self.resolveFramework(arena, framework_dirs, obj.path)) orelse {
                    const err = try self.base.addErrorWithNotes(2 + framework_dirs.len);
                    try err.addMsg("framework not found for -framework {s}", .{obj.path});
                    try err.addNote("searched in", .{});
                    for (framework_dirs) |dir| try err.addNote("{s}", .{dir});
                    return error.ResolveFail;
                };
                break :blk full_path;
            },
        }
    };
    return .{
        .path = full_path,
        .tag = obj.tag,
        .needed = obj.needed,
        .weak = obj.weak,
        .must_link = obj.must_link,
    };
}

fn parsePositional(
    self: *MachO,
    arena: Allocator,
    obj: LinkObject,
    lib_dirs: []const []const u8,
    framework_dirs: []const []const u8,
) !void {
    const resolved_obj = self.resolveFile(arena, obj, lib_dirs, framework_dirs) catch |err| switch (err) {
        error.ResolveFail => return,
        else => |e| return e,
    };

    log.debug("parsing positional {}", .{resolved_obj});

    if (try self.parseObject(arena, resolved_obj)) return;
    // if (try self.parseArchive(arena, resolved_obj)) return;
    // if (try self.parseDylib(arena, resolved_obj)) return;
    if (try self.parseTbd(resolved_obj)) return;

    self.base.fatal("unknown filetype for positional argument: '{s}'", .{resolved_obj.path});
}

fn parseObject(self: *MachO, arena: Allocator, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const header = file.reader().readStruct(macho.mach_header_64) catch return false;
    try file.seekTo(0);

    if (header.filetype != macho.MH_OBJECT) return false;
    self.validateOrSetCpuArch(obj.path, header.cputype);

    const mtime: u64 = mtime: {
        const stat = file.stat() catch break :mtime 0;
        break :mtime @as(u64, @intCast(@divFloor(stat.mtime, 1_000_000_000)));
    };
    const data = try file.readToEndAlloc(arena, std.math.maxInt(u32));

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .object = .{
        .path = obj.path,
        .data = data,
        .index = index,
        .mtime = mtime,
    } });
    const object = &self.files.items(.data)[index].object;
    try object.parse(self);
    try self.objects.append(gpa, index);

    // if (object.getPlatform()) |platform| {
    //     const self_platform = self.options.platform orelse blk: {
    //         self.options.platform = platform;
    //         break :blk self.options.platform.?;
    //     };
    //     if (self_platform.platform != platform.platform) {
    //         return self.base.fatal(
    //             "{s}: object file was built for different platform: expected {s}, got {s}",
    //             .{ obj.path, @tagName(self_platform.platform), @tagName(platform.platform) },
    //         );
    //     }
    //     if (self_platform.version.value < platform.version.value) {
    //         return self.base.warn(
    //             "{s}: object file was built for newer platform version: expected {}, got {}",
    //             .{
    //                 obj.path,
    //                 self_platform.version,
    //                 platform.version,
    //             },
    //         );
    //     }
    // }

    return true;
}

fn validateOrSetCpuArch(self: *MachO, path: []const u8, cputype: i32) void {
    const cpu_arch: std.Target.Cpu.Arch = switch (cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => unreachable,
    };
    const self_cpu_arch = self.options.cpu_arch orelse blk: {
        self.options.cpu_arch = cpu_arch;
        break :blk self.options.cpu_arch.?;
    };
    if (self_cpu_arch != cpu_arch) {
        return self.base.fatal("{s}: invalid architecture '{s}', expected '{s}'", .{
            path,
            @tagName(cpu_arch),
            @tagName(self_cpu_arch),
        });
    }
}

fn parseLibrary(self: *MachO, obj: LinkObject, dependent_libs: anytype) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    if (Object.isObject(file)) return;

    if (fat.isFatLibrary(file)) {
        const offset = self.parseFatLibrary(obj.path, file) catch |err| switch (err) {
            error.NoArchSpecified, error.MissingArch => return,
            else => |e| return e,
        };
        try file.seekTo(offset);

        if (Archive.isArchive(file, offset)) {
            try self.parseArchive(obj.path, offset, obj.must_link);
        } else if (Dylib.isDylib(file, offset)) {
            try self.parseDylib(obj.path, file, offset, dependent_libs, .{
                .syslibroot = self.options.syslibroot,
                .needed = obj.needed,
                .weak = obj.weak,
            });
        } else return self.base.fatal("{s}: unknown file type", .{obj.path});
    } else if (Archive.isArchive(file, 0)) {
        try self.parseArchive(obj.path, 0, obj.must_link);
    } else if (Dylib.isDylib(file, 0)) {
        try self.parseDylib(obj.path, file, 0, dependent_libs, .{
            .syslibroot = self.options.syslibroot,
            .needed = obj.needed,
            .weak = obj.weak,
        });
    } else {
        self.parseLibStub(obj.path, file, dependent_libs, .{
            .syslibroot = self.options.syslibroot,
            .needed = obj.needed,
            .weak = obj.weak,
        }) catch |err| switch (err) {
            error.NotLibStub, error.UnexpectedToken => return self.base.fatal("{s}: unknown file type", .{obj.path}),
            else => |e| return e,
        };
    }
}

fn parseFatLibrary(self: *MachO, path: []const u8, file: fs.File) !u64 {
    var buffer: [2]fat.Arch = undefined;
    const fat_archs = try fat.parseArchs(file, &buffer);
    const cpu_arch = self.options.cpu_arch orelse {
        const err = try self.base.addErrorWithNotes(1 + fat_archs.len);
        try err.addMsg("{s}: ignoring universal file as no architecture specified", .{path});
        for (fat_archs) |arch| {
            try err.addNote("universal file built for {s}", .{@tagName(arch.tag)});
        }
        return error.NoArchSpecified;
    };
    const offset = for (fat_archs) |arch| {
        if (arch.tag == cpu_arch) break arch.offset;
    } else {
        self.base.fatal("{s}: missing arch in universal file: expected {s}", .{ path, @tagName(cpu_arch) });
        return error.MissingArch;
    };
    return offset;
}

fn parseArchive(self: *MachO, path: []const u8, fat_offset: u64, must_link: bool) !void {
    const gpa = self.base.allocator;
    const self_cpu_arch = self.options.cpu_arch orelse
        return self.base.fatal("{s}: ignoring library as no architecture specified", .{path});

    const file = try std.fs.cwd().openFile(path, .{});
    errdefer file.close();
    try file.seekTo(fat_offset);

    var archive = Archive{
        .file = file,
        .fat_offset = fat_offset,
        .name = try gpa.dupe(u8, path),
    };
    errdefer archive.deinit(gpa);

    try archive.parse(gpa, file.reader(), self);

    // Verify arch and platform
    if (archive.toc.values().len > 0) {
        const offsets = archive.toc.values()[0].items;
        assert(offsets.len > 0);
        const off = offsets[0];
        var object = try archive.parseObject(gpa, off); // TODO we are doing all this work to pull the header only!
        defer object.deinit(gpa);

        const cpu_arch: std.Target.Cpu.Arch = switch (object.header.cputype) {
            macho.CPU_TYPE_ARM64 => .aarch64,
            macho.CPU_TYPE_X86_64 => .x86_64,
            else => unreachable,
        };
        if (self_cpu_arch != cpu_arch) {
            return self.base.fatal("{s}: invalid architecture in archive '{s}', expected '{s}'", .{
                path,
                @tagName(cpu_arch),
                @tagName(self_cpu_arch),
            });
        }
    }

    if (must_link) {
        // Get all offsets from the ToC
        var offsets = std.AutoArrayHashMap(u32, void).init(gpa);
        defer offsets.deinit();
        for (archive.toc.values()) |offs| {
            for (offs.items) |off| {
                _ = try offsets.getOrPut(off);
            }
        }
        for (offsets.keys()) |off| {
            const object = try archive.parseObject(gpa, off);
            try self.objects.append(gpa, object);
        }
    } else {
        try self.archives.append(gpa, archive);
    }
}

const DylibOpts = struct {
    syslibroot: ?[]const u8,
    id: ?Dylib.Id = null,
    dependent: bool = false,
    needed: bool = false,
    weak: bool = false,
};

fn parseDylib(self: *MachO, path: []const u8, file: std.fs.File, offset: u64, dependent_libs: anytype, opts: DylibOpts) !void {
    const gpa = self.base.allocator;

    const self_cpu_arch = self.options.cpu_arch orelse
        return self.base.fatal("{s}: ignoring library as no architecture specified", .{path});

    const file_stat = try file.stat();
    var file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;

    file_size -= offset;

    const contents = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);
    defer gpa.free(contents);

    var dylib = Dylib{ .weak = opts.weak };
    errdefer dylib.deinit(gpa);

    try dylib.parseFromBinary(
        gpa,
        @intCast(self.dylibs.items.len),
        dependent_libs,
        path,
        contents,
    );

    const cpu_arch: std.Target.Cpu.Arch = switch (dylib.header.?.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => unreachable,
    };
    if (self_cpu_arch != cpu_arch) {
        return self.base.fatal("{s}: invalid architecture '{s}', expected '{s}'", .{
            path,
            @tagName(cpu_arch),
            @tagName(self_cpu_arch),
        });
    }

    if (self.options.platform) |self_platform| {
        if (dylib.getPlatform(contents)) |platform| {
            if (self_platform.platform != platform.platform) {
                return self.base.fatal(
                    "{s}: dylib file was built for different platform: expected {s}, got {s}",
                    .{ path, @tagName(self_platform.platform), @tagName(platform.platform) },
                );
            }
        }
    }

    self.addDylib(dylib, .{
        .syslibroot = self.options.syslibroot,
        .needed = opts.needed,
        .weak = opts.weak,
    }) catch |err| switch (err) {
        error.DylibAlreadyExists => dylib.deinit(gpa),
        else => |e| return e,
    };
}

fn parseTbd(self: *MachO, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    var lib_stub = LibStub.loadFromFile(gpa, file) catch return false; // TODO actually handle different errors
    defer lib_stub.deinit();

    if (lib_stub.inner.len == 0) return false;

    const cpu_arch = self.options.cpu_arch orelse {
        self.base.fatal("{s}: ignoring library as no architecture specified", .{obj.path});
        return false;
    };

    // if (self.options.platform) |platform| {
    //     var matcher = try Dylib.TargetMatcher.init(self.base.allocator, cpu_arch, platform.platform);
    //     defer matcher.deinit();

    //     for (lib_stub.inner) |elem| {
    //         if (try matcher.matchesTargetTbd(elem)) break;
    //     } else {
    //         const target = try Dylib.TargetMatcher.targetToAppleString(self.base.allocator, cpu_arch, platform.platform);
    //         defer self.base.allocator.free(target);
    //         return self.base.fatal("{s}: missing target in stub file: expected {s}", .{ path, target });
    //     }
    // }

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .dylib = .{
        .path = obj.path,
        .data = &[0]u8{},
        .index = index,
        .needed = obj.needed,
        .weak = obj.weak,
    } });
    const dylib = &self.files.items(.data)[index].dylib;
    try dylib.parseTbd(cpu_arch, self.options.platform, lib_stub, self);
    try self.dylibs.append(gpa, index);

    return true;
}

fn addDylib(self: *MachO, dylib: Dylib, opts: DylibOpts) !void {
    const gpa = self.base.allocator;

    if (opts.id) |id| {
        if (dylib.id.?.current_version < id.compatibility_version) {
            log.warn("found dylib is incompatible with the required minimum version", .{});
            log.warn("  dylib: {s}", .{id.name});
            log.warn("  required minimum version: {}", .{id.compatibility_version});
            log.warn("  dylib version: {}", .{dylib.id.?.current_version});
            return error.IncompatibleDylibVersion;
        }
    }

    const gop = try self.dylibs_map.getOrPut(gpa, dylib.id.?.name);
    if (gop.found_existing) return error.DylibAlreadyExists;

    gop.value_ptr.* = @as(u16, @intCast(self.dylibs.items.len));
    try self.dylibs.append(gpa, dylib);

    const should_link_dylib_even_if_unreachable = blk: {
        if (self.options.dead_strip_dylibs and !opts.needed) break :blk false;
        break :blk !(opts.dependent or self.referenced_dylibs.contains(gop.value_ptr.*));
    };

    if (should_link_dylib_even_if_unreachable) {
        try self.referenced_dylibs.putNoClobber(gpa, gop.value_ptr.*, {});
    }
}

fn parseDependentLibs(self: *MachO, syslibroot: ?[]const u8, dependent_libs: anytype) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // At this point, we can now parse dependents of dylibs preserving the inclusion order of:
    // 1) anything on the linker line is parsed first
    // 2) afterwards, we parse dependents of the included dylibs
    // TODO this should not be performed if the user specifies `-flat_namespace` flag.
    // See ld64 manpages.
    var arena_alloc = std.heap.ArenaAllocator.init(self.base.allocator);
    const arena = arena_alloc.allocator();
    defer arena_alloc.deinit();

    outer: while (dependent_libs.readItem()) |dep_id| {
        defer dep_id.id.deinit(self.base.allocator);

        if (self.dylibs_map.contains(dep_id.id.name)) continue;

        const weak = self.dylibs.items[dep_id.parent].weak;
        const has_ext = blk: {
            const basename = fs.path.basename(dep_id.id.name);
            break :blk mem.lastIndexOfScalar(u8, basename, '.') != null;
        };
        const extension = if (has_ext) fs.path.extension(dep_id.id.name) else "";
        const without_ext = if (has_ext) blk: {
            const index = mem.lastIndexOfScalar(u8, dep_id.id.name, '.') orelse unreachable;
            break :blk dep_id.id.name[0..index];
        } else dep_id.id.name;

        for (&[_][]const u8{ extension, ".tbd" }) |ext| {
            const with_ext = try std.fmt.allocPrint(arena, "{s}{s}", .{ without_ext, ext });
            const full_path = if (syslibroot) |root| try fs.path.join(arena, &.{ root, with_ext }) else with_ext;

            const file = std.fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            defer file.close();

            log.debug("trying dependency at fully resolved path {s}", .{full_path});

            const offset: u64 = if (fat.isFatLibrary(file)) blk: {
                const offset = self.parseFatLibrary(full_path, file) catch |err| switch (err) {
                    error.NoArchSpecified, error.MissingArch => break,
                    else => |e| return e,
                };
                try file.seekTo(offset);
                break :blk offset;
            } else 0;

            if (Dylib.isDylib(file, offset)) {
                try self.parseDylib(full_path, file, offset, dependent_libs, .{
                    .syslibroot = self.options.syslibroot,
                    .dependent = true,
                    .weak = weak,
                });
            } else {
                self.parseLibStub(full_path, file, dependent_libs, .{
                    .syslibroot = self.options.syslibroot,
                    .dependent = true,
                    .weak = weak,
                }) catch |err| switch (err) {
                    error.NotLibStub, error.UnexpectedToken => continue,
                    else => |e| return e,
                };
            }
            continue :outer;
        }

        self.base.fatal("{s}: unable to resolve dependency", .{dep_id.id.name});
    }
}

/// When resolving symbols, we approach the problem similarly to `mold`.
/// 1. Resolve symbols across all objects (including those preemptively extracted archives).
/// 2. Resolve symbols across all shared objects.
/// 3. Mark live objects (see `MachO.markLive`)
/// 4. Reset state of all resolved globals since we will redo this bit on the pruned set.
/// 5. Remove references to dead objects/shared objects
/// 6. Re-run symbol resolution on pruned objects and shared objects sets.
pub fn resolveSymbols(self: *MachO) !void {
    // Resolve symbols on the set of all objects and shared objects (even if some are unneeded).
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.dylibs.items) |index| self.getFile(index).?.resolveSymbols(self);

    // Mark live objects.
    self.markLive();

    // Reset state of all globals after marking live objects.
    for (self.objects.items) |index| self.getFile(index).?.resetGlobals(self);
    for (self.dylibs.items) |index| self.getFile(index).?.resetGlobals(self);

    // Prune dead objects and dylibs.
    var i: usize = 0;
    while (i < self.objects.items.len) {
        const index = self.objects.items[i];
        if (!self.getFile(index).?.isAlive()) {
            _ = self.objects.orderedRemove(i);
        } else i += 1;
    }

    i = 0;
    while (i < self.dylibs.items.len) {
        const index = self.dylibs.items[i];
        if (!self.getFile(index).?.isAlive()) {
            _ = self.dylibs.orderedRemove(i);
        } else i += 1;
    }

    // Re-resolve the symbols.
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.dylibs.items) |index| self.getFile(index).?.resolveSymbols(self);
}

/// Traverses all objects and dylibs marking any object referenced by
/// a live object/dylib as alive itself.
/// This routine will prune unneeded objects extracted from archives and
/// unneeded dylibs.
fn markLive(self: *MachO) void {
    for (self.objects.items) |index| {
        const file = self.getFile(index).?;
        if (file.isAlive()) file.markLive(self);
    }
    for (self.dylibs.items) |index| {
        const file = self.getFile(index).?;
        if (file.isAlive()) file.markLive(self);
    }
}

fn markImportsAndExports(self: *MachO) void {
    if (!self.options.dylib)
        for (self.dylibs.items) |index| {
            for (self.getFile(index).?.getGlobals()) |global_index| {
                const global = self.getSymbol(global_index);
                const file = global.getFile(self) orelse continue;
                if (file != .dylib and !global.getNlist(self).pext()) global.flags.@"export" = true;
            }
        };

    for (self.objects.items) |index| {
        self.markImportsAndExportsInFile(index);
    }
}

fn markImportsAndExportsInFile(self: *MachO, index: File.Index) void {
    for (self.getFile(index).?.getGlobals()) |global_index| {
        const global = self.getSymbol(global_index);
        const file = global.getFile(self) orelse continue;
        if (global.getNlist(self).pext()) continue;
        if (file == .dylib and !global.isAbs(self)) {
            global.flags.import = true;
            continue;
        }
        if (file.getIndex() == index) {
            global.flags.@"export" = true;

            if (self.options.dylib) {
                global.flags.import = true;
            }
        }
    }
}

fn initOutputSections(self: *MachO) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.initOutputSection(atom.getInputSection(self), self);
        }
    }
    if (self.getInternalObject()) |internal| {
        for (internal.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.initOutputSection(atom.getInputSection(self), self);
        }
    }
}

fn resolveSyntheticSymbols(self: *MachO) !void {
    const internal = self.getInternalObject() orelse return;
    try internal.init(self);
    internal.resolveSymbols(self);
    self.markImportsAndExportsInFile(internal.index);
}

fn claimUnresolved(self: *MachO) void {
    for (self.objects.items) |index| {
        self.getFile(index).?.object.claimUnresolved(self);
    }
    if (self.getInternalObject()) |internal| {
        internal.claimUnresolved(self);
    }
}

fn scanRelocs(self: *MachO) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.scanRelocs(self);
    }
    if (self.getInternalObject()) |internal| {
        try internal.scanRelocs(self);
    }

    try self.reportUndefs();
    self.base.reportWarningsAndErrorsAndExit();

    for (self.symbols.items, 0..) |*symbol, i| {
        const index = @as(Symbol.Index, @intCast(i));
        if (symbol.flags.got) {
            log.debug("'{s}' needs GOT", .{symbol.getName(self)});
            try self.got.addSymbol(index, self);
        }
        if (symbol.flags.stubs) {
            log.debug("'{s}' needs STUBS", .{symbol.getName(self)});
            try self.stubs.addSymbol(index, self);
        }
        if (symbol.flags.tlv) {
            assert(!symbol.flags.import); // TODO
            log.debug("'{s}' needs TLV", .{symbol.getName(self)});
            try self.tlv.addSymbol(index, self);
        }
    }
}

fn reportUndefs(self: *MachO) !void {
    if (self.undefs.count() == 0) return;
    if (self.options.undefined_treatment == .suppress) return;

    const addFn = switch (self.options.undefined_treatment) {
        .dynamic_lookup => unreachable, // all undefs are treated as load-time bound symbols
        .suppress => unreachable, // handled above
        .@"error" => &Zld.addErrorWithNotes,
        .warn => &Zld.addWarningWithNotes,
    };

    const max_notes = 4;

    var it = self.undefs.iterator();
    while (it.next()) |entry| {
        const undef_sym = self.getSymbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @intFromBool(notes.items.len > max_notes);

        const err = try addFn(&self.base, nnotes);
        try err.addMsg("undefined symbol: {s}", .{undef_sym.getName(self)});

        var inote: usize = 0;
        while (inote < @min(notes.items.len, max_notes)) : (inote += 1) {
            const atom = self.getAtom(notes.items[inote]).?;
            const file = atom.getFile(self);
            try err.addNote("referenced by {}:{s}", .{ file.fmtPath(), atom.getName(self) });
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            try err.addNote("referenced {d} more times", .{remaining});
        }
    }
}

fn initSyntheticSections(self: *MachO) !void {
    const cpu_arch = self.options.cpu_arch.?;

    if (self.got.symbols.items.len > 0) {
        self.got_sect_index = try self.addSection("__DATA_CONST", "__got", .{
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
        });
    }
    if (self.stubs.symbols.items.len > 0) {
        self.stubs_sect_index = try self.addSection("__TEXT", "__stubs", .{
            .flags = macho.S_SYMBOL_STUBS |
                macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved2 = switch (cpu_arch) {
                .x86_64 => 6,
                .aarch64 => 3 * @sizeOf(u32),
                else => 0,
            },
        });
        self.stubs_helper_sect_index = try self.addSection("__TEXT", "__stub_helper", .{
            .flags = macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
        self.la_symbol_ptr_sect_index = try self.addSection("__DATA", "__la_symbol_ptr", .{
            .flags = macho.S_LAZY_SYMBOL_POINTERS,
        });
    }
    if (self.tlv.symbols.items.len > 0) {
        self.tlv_sect_index = try self.addSection("__DATA", "__thread_vars", .{
            .flags = macho.S_THREAD_LOCAL_VARIABLES,
        });
    }
}

fn getSegmentRank(segname: []const u8) u4 {
    if (mem.eql(u8, segname, "__PAGEZERO")) return 0x0;
    if (mem.eql(u8, segname, "__TEXT")) return 0x1;
    if (mem.eql(u8, segname, "__DATA_CONST")) return 0x2;
    if (mem.eql(u8, segname, "__DATA")) return 0x3;
    if (mem.eql(u8, segname, "__LINKEDIT")) return 0x5;
    return 0x4;
}

fn getSectionRank(self: *MachO, sect_index: u8) u8 {
    const header = self.sections.items(.header)[sect_index];
    const segment_rank = getSegmentRank(header.segName());
    const section_rank: u4 = blk: {
        if (header.isCode()) {
            if (mem.eql(u8, "__text", header.sectName())) break :blk 0x0;
            if (header.type() == macho.S_SYMBOL_STUBS) break :blk 0x1;
            break :blk 0x2;
        }
        switch (header.type()) {
            macho.S_NON_LAZY_SYMBOL_POINTERS,
            macho.S_LAZY_SYMBOL_POINTERS,
            => break :blk 0x0,

            macho.S_MOD_INIT_FUNC_POINTERS => break :blk 0x1,
            macho.S_MOD_TERM_FUNC_POINTERS => break :blk 0x2,
            macho.S_ZEROFILL => break :blk 0xf,
            macho.S_THREAD_LOCAL_REGULAR => break :blk 0xd,
            macho.S_THREAD_LOCAL_ZEROFILL => break :blk 0xe,

            else => {
                if (mem.eql(u8, "__unwind_info", header.sectName())) break :blk 0xe;
                if (mem.eql(u8, "__eh_frame", header.sectName())) break :blk 0xf;
                break :blk 0x3;
            },
        }
    };
    return (@as(u8, @intCast(segment_rank)) << 4) + section_rank;
}

fn sortSections(self: *MachO) !void {
    const Entry = struct {
        index: u8,

        pub fn lessThan(macho_file: *MachO, lhs: @This(), rhs: @This()) bool {
            return macho_file.getSectionRank(lhs.index) < macho_file.getSectionRank(rhs.index);
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
            atom.out_n_sect = backlinks[atom.out_n_sect];
        }
    }
    if (self.getInternalObject()) |internal| {
        for (internal.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = backlinks[atom.out_n_sect];
        }
    }

    for (&[_]*?u8{
        &self.got_sect_index,
        &self.stubs_sect_index,
        &self.stubs_helper_sect_index,
        &self.la_symbol_ptr_sect_index,
        &self.tlv_sect_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }
}

pub fn addAtomsToSections(self: *MachO) !void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_n_sect];
            try atoms.append(self.base.allocator, atom_index);
        }
    }
    if (self.getInternalObject()) |internal| {
        for (internal.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_n_sect];
            try atoms.append(self.base.allocator, atom_index);
        }
    }
}

pub inline fn getPageSize(self: MachO) u16 {
    return switch (self.options.cpu_arch.?) {
        .aarch64 => 0x4000,
        .x86_64 => 0x1000,
        else => unreachable,
    };
}

pub fn requiresCodeSig(self: MachO) bool {
    if (self.options.entitlements) |_| return true;
    if (self.options.cpu_arch.? == .aarch64) {
        const platform = if (self.options.platform) |platform| platform.platform else .MACOS;
        switch (platform) {
            .MACOS, .IOSSIMULATOR, .WATCHOSSIMULATOR, .TVOSSIMULATOR => return true,
            else => {},
        }
    }
    return false;
}

inline fn requiresThunks(self: MachO) bool {
    return self.options.cpu_arch.? == .aarch64;
}

const AddSectionOpts = struct {
    flags: u32 = macho.S_REGULAR,
    reserved1: u32 = 0,
    reserved2: u32 = 0,
};

pub fn addSection(
    self: *MachO,
    segname: []const u8,
    sectname: []const u8,
    opts: AddSectionOpts,
) !u8 {
    const gpa = self.base.allocator;
    const index = @as(u8, @intCast(try self.sections.addOne(gpa)));
    self.sections.set(index, .{
        .segment_index = undefined, // Segments will be created automatically later down the pipeline.
        .header = .{
            .sectname = makeStaticString(sectname),
            .segname = makeStaticString(segname),
            .flags = opts.flags,
            .reserved1 = opts.reserved1,
            .reserved2 = opts.reserved2,
        },
    });
    return index;
}

pub fn makeStaticString(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    assert(bytes.len <= buf.len);
    mem.copy(u8, &buf, bytes);
    return buf;
}

pub fn getSectionByName(self: MachO, segname: []const u8, sectname: []const u8) ?u8 {
    for (self.sections.items(.header), 0..) |header, i| {
        if (mem.eql(u8, header.segName(), segname) and mem.eql(u8, header.sectName(), sectname))
            return @as(u8, @intCast(i));
    } else return null;
}

pub fn getFile(self: *MachO, index: File.Index) ?File {
    const tag = self.files.items(.tags)[index];
    return switch (tag) {
        .null => null,
        .internal => .{ .internal = &self.files.items(.data)[index].internal },
        .object => .{ .object = &self.files.items(.data)[index].object },
        .dylib => .{ .dylib = &self.files.items(.data)[index].dylib },
    };
}

pub fn getInternalObject(self: *MachO) ?*InternalObject {
    const index = self.internal_object_index orelse return null;
    return self.getFile(index).?.internal;
}

pub fn addAtom(self: *MachO) !Atom.Index {
    const index = @as(Atom.Index, @intCast(self.atoms.items.len));
    const atom = try self.atoms.addOne(self.base.allocator);
    atom.* = .{};
    return index;
}

pub fn getAtom(self: *MachO, atom_index: Atom.Index) ?*Atom {
    if (atom_index == 0) return null;
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn addSymbol(self: *MachO) !Symbol.Index {
    const index = @as(Symbol.Index, @intCast(self.symbols.items.len));
    const symbol = try self.symbols.addOne(self.base.allocator);
    symbol.* = .{};
    return index;
}

pub fn getSymbol(self: *MachO, index: Symbol.Index) *Symbol {
    assert(index < self.symbols.items.len);
    return &self.symbols.items[index];
}

pub fn addSymbolExtra(self: *MachO, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    try self.symbols_extra.ensureUnusedCapacity(self.base.allocator, fields.len);
    return self.addSymbolExtraAssumeCapacity(extra);
}

pub fn addSymbolExtraAssumeCapacity(self: *MachO, extra: Symbol.Extra) u32 {
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

pub fn getSymbolExtra(self: MachO, index: u32) ?Symbol.Extra {
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

pub fn setSymbolExtra(self: *MachO, index: u32, extra: Symbol.Extra) void {
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

pub fn getOrCreateGlobal(self: *MachO, off: u32) !GetOrCreateGlobalResult {
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

pub fn getGlobalByName(self: *MachO, name: []const u8) ?Symbol.Index {
    const off = self.string_intern.getOffset(name) orelse return null;
    return self.globals.get(off);
}

pub fn dumpState(self: *MachO) std.fmt.Formatter(fmtDumpState) {
    return .{ .data = self };
}

fn fmtDumpState(
    self: *MachO,
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
            object.fmtSymtab(self),
        });
    }
    for (self.dylibs.items) |index| {
        const dylib = self.getFile(index).?.dylib;
        try writer.print("dylib({d}) : {s} : needed({}) : weak({})", .{ index, dylib.path, dylib.needed, dylib.weak });
        if (!dylib.alive) try writer.writeAll(" : [*]");
        try writer.writeByte('\n');
        try writer.print("{}\n", .{dylib.fmtSymtab(self)});
    }
    if (self.getInternalObject()) |internal| {
        try writer.print("internal({d}) : internal\n", .{internal.index});
        try writer.print("{}\n", .{internal.fmtSymtab(self)});
    }
    try writer.print("stubs\n{}\n", .{self.stubs.fmt(self)});
    try writer.print("got\n{}\n", .{self.got.fmt(self)});
    try writer.print("tlv\n{}\n", .{self.tlv.fmt(self)});
    try writer.writeByte('\n');
    try writer.writeAll("Output sections\n");
    try writer.print("{}\n", .{self.fmtSections()});
}

fn fmtSections(self: *MachO) std.fmt.Formatter(formatSections) {
    return .{ .data = self };
}

fn formatSections(
    self: *MachO,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.sections.items(.header), 0..) |header, i| {
        try writer.print("sect({d}) : {s},{s} : @{x} ({x}) : align({x}) : size({x})\n", .{
            i,               header.segName(), header.sectName(), header.offset, header.addr,
            header.@"align", header.size,
        });
    }
}

pub fn fmtSectType(tt: u8) std.fmt.Formatter(formatSectType) {
    return .{ .data = tt };
}

fn formatSectType(
    tt: u8,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const name = switch (tt) {
        macho.S_REGULAR => "REGULAR",
        macho.S_ZEROFILL => "ZEROFILL",
        macho.S_CSTRING_LITERALS => "CSTRING_LITERALS",
        macho.S_4BYTE_LITERALS => "4BYTE_LITERALS",
        macho.S_8BYTE_LITERALS => "8BYTE_LITERALS",
        macho.S_16BYTE_LITERALS => "16BYTE_LITERALS",
        macho.S_LITERAL_POINTERS => "LITERAL_POINTERS",
        macho.S_NON_LAZY_SYMBOL_POINTERS => "NON_LAZY_SYMBOL_POINTERS",
        macho.S_LAZY_SYMBOL_POINTERS => "LAZY_SYMBOL_POINTERS",
        macho.S_SYMBOL_STUBS => "SYMBOL_STUBS",
        macho.S_MOD_INIT_FUNC_POINTERS => "MOD_INIT_FUNC_POINTERS",
        macho.S_MOD_TERM_FUNC_POINTERS => "MOD_TERM_FUNC_POINTERS",
        macho.S_COALESCED => "COALESCED",
        macho.S_GB_ZEROFILL => "GB_ZEROFILL",
        macho.S_INTERPOSING => "INTERPOSING",
        macho.S_DTRACE_DOF => "DTRACE_DOF",
        macho.S_THREAD_LOCAL_REGULAR => "THREAD_LOCAL_REGULAR",
        macho.S_THREAD_LOCAL_ZEROFILL => "THREAD_LOCAL_ZEROFILL",
        macho.S_THREAD_LOCAL_VARIABLES => "THREAD_LOCAL_VARIABLES",
        macho.S_THREAD_LOCAL_VARIABLE_POINTERS => "THREAD_LOCAL_VARIABLE_POINTERS",
        macho.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => "THREAD_LOCAL_INIT_FUNCTION_POINTERS",
        macho.S_INIT_FUNC_OFFSETS => "INIT_FUNC_OFFSETS",
        else => |x| return writer.print("UNKNOWN({x})", .{x}),
    };
    try writer.print("{s}", .{name});
}

pub const LinkObject = struct {
    path: []const u8 = "",
    tag: enum { obj, lib, framework },
    needed: bool = false,
    weak: bool = false,
    must_link: bool = false,

    pub fn format(
        self: LinkObject,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        if (self.needed) {
            try writer.print("-needed_{s}", .{@tagName(self.tag)});
        }
        if (self.weak) {
            try writer.print("-weak_{s}", .{@tagName(self.tag)});
        }
        if (self.must_link and self.tag == .obj) {
            try writer.writeAll("-force_load");
        }
        try writer.print(" {s}", .{self.path});
    }
};

/// Default path to dyld
const default_dyld_path: [*:0]const u8 = "/usr/lib/dyld";

/// Default implicit entrypoint symbol name.
const default_entry_point: []const u8 = "_main";

/// Default virtual memory offset corresponds to the size of __PAGEZERO segment and
/// start of __TEXT segment.
const default_pagezero_vmsize: u64 = 0x100000000;

/// We commit 0x1000 = 4096 bytes of space to the header and
/// the table of load commands. This should be plenty for any
/// potential future extensions.
const default_headerpad_size: u32 = 0x1000;

const Section = struct {
    header: macho.section_64,
    segment_index: u8,
    atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
};

pub const null_sym = macho.nlist_64{
    .n_strx = 0,
    .n_type = 0,
    .n_sect = 0,
    .n_desc = 0,
    .n_value = 0,
};

pub const base_tag = Zld.Tag.macho;

const aarch64 = @import("aarch64.zig");
const assert = std.debug.assert;
const build_options = @import("build_options");
const builtin = @import("builtin");
const calcUuid = @import("MachO/uuid.zig").calcUuid;
const dead_strip = @import("MachO/dead_strip.zig");
const dwarf = std.dwarf;
const eh_frame = @import("MachO/eh_frame.zig");
const fat = @import("MachO/fat.zig");
const fmt = std.fmt;
const fs = std.fs;
const load_commands = @import("MachO/load_commands.zig");
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const thunks = @import("MachO/thunks.zig");
const trace = @import("tracy.zig").trace;
const synthetic = @import("MachO/synthetic.zig");
const state_log = std.log.scoped(.state);
const std = @import("std");

const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Archive = @import("MachO/Archive.zig");
const Atom = @import("MachO/Atom.zig");
const Bind = @import("MachO/dyld_info/bind.zig").Bind(*const MachO, MachO.SymbolWithLoc);
const CodeSignature = @import("MachO/CodeSignature.zig");
const Dylib = @import("MachO/Dylib.zig");
const DwarfInfo = @import("MachO/DwarfInfo.zig");
const File = @import("MachO/file.zig").File;
const GotSection = synthetic.GotSection;
const InternalObject = @import("MachO/InternalObject.zig");
const MachO = @This();
const Md5 = std.crypto.hash.Md5;
const Object = @import("MachO/Object.zig");
pub const Options = @import("MachO/Options.zig");
const LazyBind = @import("MachO/dyld_info/bind.zig").LazyBind(*const MachO, MachO.SymbolWithLoc);
const LaSymbolPtrSection = synthetic.LaSymbolPtrSection;
const LibStub = @import("tapi.zig").LibStub;
const Rebase = @import("MachO/dyld_info/Rebase.zig");
const Symbol = @import("MachO/Symbol.zig");
const StringTable = @import("strtab.zig").StringTable;
const StubsSection = synthetic.StubsSection;
const StubsHelperSection = synthetic.StubsHelperSection;
const ThreadPool = std.Thread.Pool;
const TlvSection = synthetic.TlvSection;
const Trie = @import("MachO/Trie.zig");
const UnwindInfo = @import("MachO/UnwindInfo.zig");
const Zld = @import("Zld.zig");
