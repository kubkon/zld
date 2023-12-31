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
/// Global symbols we need to resolve for the link to succeed.
undefined_symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
boundary_symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

pagezero_seg_index: ?u8 = null,
text_seg_index: ?u8 = null,
linkedit_seg_index: ?u8 = null,
data_sect_index: ?u8 = null,
got_sect_index: ?u8 = null,
stubs_sect_index: ?u8 = null,
stubs_helper_sect_index: ?u8 = null,
la_symbol_ptr_sect_index: ?u8 = null,
tlv_ptr_sect_index: ?u8 = null,
eh_frame_sect_index: ?u8 = null,
unwind_info_sect_index: ?u8 = null,
objc_stubs_sect_index: ?u8 = null,

mh_execute_header_index: ?Symbol.Index = null,
mh_dylib_header_index: ?Symbol.Index = null,
dyld_private_index: ?Symbol.Index = null,
dyld_stub_binder_index: ?Symbol.Index = null,
dso_handle_index: ?Symbol.Index = null,
objc_msg_send_index: ?Symbol.Index = null,

entry_index: ?Symbol.Index = null,

string_intern: StringTable(.string_intern) = .{},

symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
indsymtab: Indsymtab = .{},
got: GotSection = .{},
stubs: StubsSection = .{},
stubs_helper: StubsHelperSection = .{},
objc_stubs: ObjcStubsSection = .{},
la_symbol_ptr: LaSymbolPtrSection = .{},
tlv_ptr: TlvPtrSection = .{},
rebase: RebaseSection = .{},
bind: BindSection = .{},
weak_bind: WeakBindSection = .{},
lazy_bind: LazyBindSection = .{},
export_trie: ExportTrieSection = .{},
unwind_info: UnwindInfo = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},
thunks: std.ArrayListUnmanaged(Thunk) = .{},
unwind_records: std.ArrayListUnmanaged(UnwindInfo.Record) = .{},

has_tlv: bool = false,
binds_to_weak: bool = false,
weak_defines: bool = false,

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
    self.undefined_symbols.deinit(gpa);
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
    self.thunks.deinit(gpa);

    self.symtab.deinit(gpa);
    self.strtab.deinit(gpa);
    self.got.deinit(gpa);
    self.stubs.deinit(gpa);
    self.objc_stubs.deinit(gpa);
    self.tlv_ptr.deinit(gpa);
    self.rebase.deinit(gpa);
    self.bind.deinit(gpa);
    self.weak_bind.deinit(gpa);
    self.lazy_bind.deinit(gpa);
    self.export_trie.deinit(gpa);
    self.unwind_info.deinit(gpa);
    self.unwind_records.deinit(gpa);

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
    try self.strtab.append(gpa, 0);
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

    // Resolve link objects
    var resolved_objects = std.ArrayList(LinkObject).init(arena);
    try resolved_objects.ensureTotalCapacityPrecise(self.options.positionals.len);
    for (self.options.positionals) |obj| {
        const full_path = blk: {
            switch (obj.tag) {
                .obj => {
                    var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
                    const full_path = std.fs.realpath(obj.path, &buffer) catch |err| switch (err) {
                        error.FileNotFound => {
                            self.base.fatal("file not found {}", .{obj});
                            continue;
                        },
                        else => |e| return e,
                    };
                    break :blk try arena.dupe(u8, full_path);
                },
                .lib => {
                    const full_path = (try self.resolveLib(arena, lib_dirs.items, obj.path)) orelse {
                        const err = try self.base.addErrorWithNotes(lib_dirs.items.len);
                        try err.addMsg("library not found for {}", .{obj});
                        for (lib_dirs.items) |dir| try err.addNote("tried {s}", .{dir});
                        continue;
                    };
                    break :blk full_path;
                },
                .framework => {
                    const full_path = (try self.resolveFramework(arena, framework_dirs.items, obj.path)) orelse {
                        const err = try self.base.addErrorWithNotes(framework_dirs.items.len);
                        try err.addMsg("framework not found for {}", .{obj});
                        for (framework_dirs.items) |dir| try err.addNote("tried {s}", .{dir});
                        continue;
                    };
                    break :blk full_path;
                },
            }
        };
        resolved_objects.appendAssumeCapacity(.{
            .path = full_path,
            .tag = obj.tag,
            .needed = obj.needed,
            .weak = obj.weak,
            .hidden = obj.hidden,
            .reexport = obj.reexport,
            .must_link = obj.must_link,
        });
    }

    if (self.options.cpu_arch == null) {
        var has_parse_error = false;
        var platforms = std.ArrayList(struct { std.Target.Cpu.Arch, ?Options.Platform }).init(self.base.allocator);
        defer platforms.deinit();
        try platforms.ensureUnusedCapacity(resolved_objects.items.len);

        for (resolved_objects.items) |obj| {
            self.inferCpuArchAndPlatform(obj, &platforms) catch |err| {
                has_parse_error = true;
                switch (err) {
                    error.UnhandledCpuArch => {}, // already reported
                    else => |e| {
                        self.base.fatal("{s}: unexpected error occurred while parsing input file: {s}", .{
                            obj.path, @errorName(e),
                        });
                        return e;
                    },
                }
            };
        }
        if (has_parse_error) return error.ParseFailed;
        if (platforms.items.len == 0) {
            self.base.fatal("could not infer CPU architecture", .{});
            return error.InferCpuFailed;
        }

        self.options.cpu_arch = platforms.items[0][0];
        self.options.platform = for (platforms.items) |platform| {
            if (platform[1]) |p| break p;
        } else null;
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
                std.os.sysctlbynameZ("kern.osrelease", &ver_str, &size, null, 0) catch break :blk;
                const kern_ver = Options.Version.parse(ver_str[0 .. size - 1]) orelse break :blk;
                // According to Apple, kernel major version is 4 ahead of x in 10.
                const minor = @as(u8, @truncate((kern_ver.value >> 16) - 4));
                self.options.sdk_version = Options.Version.new(10, minor, 0);
            }
        }
    }

    var has_parse_error = false;
    for (resolved_objects.items) |obj| {
        self.parsePositional(arena, obj) catch |err| {
            has_parse_error = true;
            switch (err) {
                error.ParseFailed => {}, // already reported
                else => |e| {
                    self.base.fatal("{s}: unexpected error occurred while parsing input file: {s}", .{
                        obj.path, @errorName(e),
                    });
                    return e;
                },
            }
        };
    }
    if (has_parse_error) return error.ParseFailed;

    for (self.dylibs.items) |index| {
        self.getFile(index).?.dylib.umbrella = index;
    }

    try self.parseDependentDylibs(arena, lib_dirs.items, framework_dirs.items);

    for (self.dylibs.items) |index| {
        const dylib = self.getFile(index).?.dylib;
        if (!dylib.explicit and !dylib.hoisted) continue;
        try dylib.initSymbols(self);
    }

    {
        const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object_index = index;
    }

    try self.addUndefinedGlobals();
    try self.resolveSymbols();

    if (self.options.relocatable) return relocatable.flush(self);

    try self.resolveSyntheticSymbols();

    try self.convertTentativeDefinitions();
    try self.createObjcSections();
    try self.claimUnresolved();

    if (self.options.dead_strip) {
        try dead_strip.gcAtoms(self);
    }

    self.markImportsAndExports();
    self.deadStripDylibs();

    for (self.dylibs.items, 1..) |index, ord| {
        const dylib = self.getFile(index).?.dylib;
        dylib.ordinal = @intCast(ord);
    }

    try self.scanRelocs();

    try self.initOutputSections();
    try self.initSyntheticSections();
    try self.sortSections();
    try self.addAtomsToSections();
    try self.calcSectionSizes();
    try self.generateUnwindInfo();
    try self.initSegments();

    try self.allocateSections();
    self.allocateSegments();
    self.allocateAtoms();
    self.allocateSyntheticSymbols();

    state_log.debug("{}", .{self.dumpState()});

    try self.initDyldInfoSections();
    try self.writeAtoms();
    try self.writeUnwindInfo();
    try self.finalizeDyldInfoSections();
    try self.writeSyntheticSections();
    try self.writeDyldInfoSections();
    try self.writeFunctionStarts();
    try self.writeDataInCode();
    try self.calcSymtabSize();
    try self.writeSymtab();
    try self.writeIndsymtab();
    try self.writeStrtab();

    var codesig: ?CodeSignature = if (self.requiresCodeSig()) blk: {
        // Preallocate space for the code signature.
        // We need to do this at this stage so that we have the load commands with proper values
        // written out to the file.
        // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
        // where the code signature goes into.
        var codesig = CodeSignature.init(self.getPageSize());
        codesig.code_directory.ident = self.options.emit.sub_path;
        if (self.options.entitlements) |path| try codesig.addEntitlements(gpa, path);
        try self.writeCodeSignaturePadding(&codesig);
        break :blk codesig;
    } else null;
    defer if (codesig) |*csig| csig.deinit(gpa);

    self.getLinkeditSegment().vmsize = mem.alignForward(
        u64,
        self.getLinkeditSegment().filesize,
        self.getPageSize(),
    );

    const ncmds, const sizeofcmds, const uuid_cmd_offset = try self.writeLoadCommands();
    try self.writeHeader(ncmds, sizeofcmds);
    try self.writeUuid(uuid_cmd_offset, self.requiresCodeSig());

    if (codesig) |*csig| {
        try self.writeCodeSignature(csig); // code signing always comes last
        const emit = self.options.emit;
        try invalidateKernelCache(emit.directory, emit.sub_path);
    }
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
        if (try accessPath(candidate)) return candidate;
    }

    return null;
}

fn resolvePathsFirst(arena: Allocator, dirs: []const []const u8, path: []const u8) !?[]const u8 {
    for (dirs) |dir| {
        for (&[_][]const u8{ ".tbd", ".dylib", ".a" }) |ext| {
            const with_ext = try std.fmt.allocPrint(arena, "{s}{s}", .{ path, ext });
            const full_path = try std.fs.path.join(arena, &[_][]const u8{ dir, with_ext });
            if (try accessPath(full_path)) return full_path;
        }
    }
    return null;
}

fn resolveDylibsFirst(arena: Allocator, dirs: []const []const u8, path: []const u8) !?[]const u8 {
    for (dirs) |dir| {
        for (&[_][]const u8{ ".tbd", ".dylib" }) |ext| {
            const with_ext = try std.fmt.allocPrint(arena, "{s}{s}", .{ path, ext });
            const full_path = try std.fs.path.join(arena, &[_][]const u8{ dir, with_ext });
            if (try accessPath(full_path)) return full_path;
        }
    }
    for (dirs) |dir| {
        const with_ext = try std.fmt.allocPrint(arena, "{s}.a", .{path});
        const full_path = try std.fs.path.join(arena, &[_][]const u8{ dir, with_ext });
        if (try accessPath(full_path)) return full_path;
    }
    return null;
}

fn accessPath(path: []const u8) !bool {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return true;
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

fn inferCpuArchAndPlatform(self: *MachO, obj: LinkObject, platforms: anytype) !void {
    const gpa = self.base.allocator;

    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    const header = file.reader().readStruct(macho.mach_header_64) catch return;
    if (header.filetype != macho.MH_OBJECT) return;

    const cpu_arch: std.Target.Cpu.Arch = switch (header.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => {
            self.base.fatal("{s}: unhandled CPU architecture: {d}", .{
                obj.path,
                header.cputype,
            });
            return error.UnhandledCpuArch;
        },
    };

    const out = platforms.addOneAssumeCapacity();
    out.* = .{ cpu_arch, null };

    const cmds_buffer = try gpa.alloc(u8, header.sizeofcmds);
    defer gpa.free(cmds_buffer);
    const amt = file.reader().readAll(cmds_buffer) catch return;
    if (amt != header.sizeofcmds) return;

    var it = macho.LoadCommandIterator{
        .ncmds = header.ncmds,
        .buffer = cmds_buffer,
    };
    out[1] = while (it.next()) |cmd| switch (cmd.cmd()) {
        .BUILD_VERSION,
        .VERSION_MIN_MACOSX,
        .VERSION_MIN_IPHONEOS,
        .VERSION_MIN_TVOS,
        .VERSION_MIN_WATCHOS,
        => break Options.Platform.fromLoadCommand(cmd),
        else => {},
    } else null;
}

fn validateCpuArch(self: *MachO, index: File.Index) void {
    const file = self.getFile(index).?;
    const cputype = switch (file) {
        .object => |x| x.header.?.cputype,
        .dylib => |x| x.header.?.cputype,
        else => unreachable,
    };
    const cpu_arch: std.Target.Cpu.Arch = switch (cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => unreachable,
    };
    if (self.options.cpu_arch) |self_cpu_arch| {
        if (self_cpu_arch != cpu_arch) {
            return self.base.fatal("{}: invalid architecture '{s}', expected '{s}'", .{
                file.fmtPath(),
                @tagName(cpu_arch),
                @tagName(self_cpu_arch),
            });
        }
    }
}

fn validatePlatform(self: *MachO, index: File.Index) void {
    const self_platform = self.options.platform orelse return;
    const file = self.getFile(index).?;
    const other_platform: ?Options.Platform = switch (file) {
        .object => |x| x.platform,
        .dylib => |x| x.platform,
        else => null,
    };
    if (other_platform) |platform| {
        if (self_platform.platform != platform.platform) {
            return self.base.fatal(
                "{}: object file was built for different platform: expected {s}, got {s}",
                .{ file.fmtPath(), @tagName(self_platform.platform), @tagName(platform.platform) },
            );
        }
        if (self_platform.version.value < platform.version.value) {
            return self.base.warn(
                "{}: object file was built for newer platform version: expected {}, got {}",
                .{
                    file.fmtPath(),
                    self_platform.version,
                    platform.version,
                },
            );
        }
    }
}

fn addUndefinedGlobals(self: *MachO) !void {
    const gpa = self.base.allocator;

    try self.undefined_symbols.ensureUnusedCapacity(gpa, self.options.force_undefined_symbols.len);
    for (self.options.force_undefined_symbols) |name| {
        const off = try self.string_intern.insert(gpa, name);
        const gop = try self.getOrCreateGlobal(off);
        self.undefined_symbols.appendAssumeCapacity(gop.index);
    }

    if (!self.options.dylib) {
        const name = self.options.entry orelse "_main";
        const off = try self.string_intern.insert(gpa, name);
        const gop = try self.getOrCreateGlobal(off);
        self.entry_index = gop.index;
    }

    {
        const off = try self.string_intern.insert(gpa, "dyld_stub_binder");
        const gop = try self.getOrCreateGlobal(off);
        self.dyld_stub_binder_index = gop.index;
    }

    {
        const off = try self.string_intern.insert(gpa, "_objc_msgSend");
        const gop = try self.getOrCreateGlobal(off);
        self.objc_msg_send_index = gop.index;
    }
}

fn parsePositional(self: *MachO, arena: Allocator, obj: LinkObject) !void {
    log.debug("parsing positional {}", .{obj});

    if (try self.parseObject(arena, obj)) return;
    if (try self.parseArchive(arena, obj)) return;
    if (try self.parseDylib(arena, obj, true)) |_| return;
    if (try self.parseTbd(obj, true)) |_| return;

    self.base.fatal("unknown filetype for positional argument: '{s}'", .{obj.path});
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
    self.validateCpuArch(index);
    self.validatePlatform(index);

    return true;
}

fn parseArchive(self: *MachO, arena: Allocator, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    var offset: u64 = 0;
    var size: u64 = (try file.stat()).size;
    if (fat.isFatLibrary(file)) {
        const fat_arch = self.parseFatLibrary(obj.path, file) catch |err| switch (err) {
            error.NoArchSpecified, error.MissingArch => return false,
            else => |e| return e,
        };
        offset = fat_arch.offset;
        size = fat_arch.size;
        try file.seekTo(offset);
    }

    const magic = file.reader().readBytesNoEof(Archive.SARMAG) catch return false;
    if (!mem.eql(u8, &magic, Archive.ARMAG)) return false;

    const data = try arena.alloc(u8, size - Archive.SARMAG);
    const nread = try file.readAll(data);
    if (nread != size - Archive.SARMAG) return error.InputOutput;

    var archive = Archive{ .path = obj.path, .data = data };
    defer archive.deinit(gpa);
    try archive.parse(arena, self);

    var has_parse_error = false;
    for (archive.objects.items) |extracted| {
        const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
        self.files.set(index, .{ .object = extracted });
        const object = &self.files.items(.data)[index].object;
        object.index = index;
        object.alive = obj.must_link or obj.needed or self.options.all_load;
        object.hidden = obj.hidden;
        object.parse(self) catch |err| switch (err) {
            error.ParseFailed => {
                has_parse_error = true;
                continue;
            },
            else => |e| return e,
        };
        try self.objects.append(gpa, index);
        self.validateCpuArch(index);
        self.validatePlatform(index);

        // Finally, we do a post-parse check for -ObjC to see if we need to force load this member
        // anyhow.
        object.alive = object.alive or (self.options.force_load_objc and object.hasObjc());
    }
    if (has_parse_error) return error.ParseFailed;

    return true;
}

fn parseFatLibrary(self: *MachO, path: []const u8, file: fs.File) !fat.Arch {
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
    for (fat_archs) |arch| {
        if (arch.tag == cpu_arch) return arch;
    }
    self.base.fatal("{s}: missing arch in universal file: expected {s}", .{ path, @tagName(cpu_arch) });
    return error.MissingArch;
}

const DylibOpts = struct {
    syslibroot: ?[]const u8,
    id: ?Dylib.Id = null,
    needed: bool = false,
    weak: bool = false,
    reexport: bool = false,
};

fn parseDylib(self: *MachO, arena: Allocator, obj: LinkObject, explicit: bool) anyerror!?File.Index {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    if (self.options.cpu_arch == null) {
        self.base.fatal("{s}: ignoring library as no architecture specified", .{obj.path});
        return null;
    }

    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    var offset: u64 = 0;
    var size: u64 = (try file.stat()).size;
    if (fat.isFatLibrary(file)) {
        const fat_arch = self.parseFatLibrary(obj.path, file) catch |err| switch (err) {
            error.NoArchSpecified, error.MissingArch => return null,
            else => |e| return e,
        };
        offset = fat_arch.offset;
        size = fat_arch.size;
        try file.seekTo(offset);
    }

    const header = file.reader().readStruct(macho.mach_header_64) catch return null;
    try file.seekTo(offset);

    if (header.filetype != macho.MH_DYLIB) return null;

    const data = try arena.alloc(u8, size);
    const nread = try file.readAll(data);
    if (nread != size) return error.InputOutput;

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .dylib = .{
        .path = obj.path,
        .data = data,
        .index = index,
        .needed = obj.needed,
        .weak = obj.weak,
        .reexport = obj.reexport,
        .explicit = explicit,
    } });
    const dylib = &self.files.items(.data)[index].dylib;
    try dylib.parse(self);

    try self.dylibs.append(gpa, index);
    self.validateCpuArch(index);
    self.validatePlatform(index);

    return index;
}

fn parseTbd(self: *MachO, obj: LinkObject, explicit: bool) anyerror!?File.Index {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    var lib_stub = LibStub.loadFromFile(gpa, file) catch return null; // TODO actually handle different errors
    defer lib_stub.deinit();

    if (lib_stub.inner.len == 0) return null;

    const cpu_arch = self.options.cpu_arch orelse {
        self.base.fatal("{s}: ignoring library as no architecture specified", .{obj.path});
        return null;
    };

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .dylib = .{
        .path = obj.path,
        .data = &[0]u8{},
        .index = index,
        .needed = obj.needed,
        .weak = obj.weak,
        .reexport = obj.reexport,
        .explicit = explicit,
    } });
    const dylib = &self.files.items(.data)[index].dylib;
    try dylib.parseTbd(cpu_arch, self.options.platform, lib_stub, self);
    try self.dylibs.append(gpa, index);
    self.validatePlatform(index);

    return index;
}

/// According to ld64's manual, public (i.e., system) dylibs/frameworks are hoisted into the final
/// image unless overriden by -no_implicit_dylibs.
fn isHoisted(self: *MachO, install_name: []const u8) bool {
    if (self.options.no_implicit_dylibs) return true;
    if (std.fs.path.dirname(install_name)) |dirname| {
        if (mem.startsWith(u8, dirname, "/usr/lib")) return true;
        if (eatPrefix(dirname, "/System/Library/Frameworks/")) |path| {
            const basename = std.fs.path.basename(install_name);
            if (mem.indexOfScalar(u8, path, '.')) |index| {
                if (mem.eql(u8, basename, path[0..index])) return true;
            }
        }
    }
    return false;
}

fn parseDependentDylibs(
    self: *MachO,
    arena: Allocator,
    lib_dirs: []const []const u8,
    framework_dirs: []const []const u8,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    if (self.dylibs.items.len == 0) return;

    // TODO handle duplicate dylibs - it is not uncommon to have the same dylib loaded multiple times
    // in which case we should track that and return File.Index immediately instead re-parsing paths.

    var index: usize = 0;
    while (index < self.dylibs.items.len) : (index += 1) {
        const dylib_index = self.dylibs.items[index];

        var dependents = std.ArrayList(File.Index).init(gpa);
        defer dependents.deinit();
        try dependents.ensureTotalCapacityPrecise(self.getFile(dylib_index).?.dylib.dependents.items.len);

        const is_weak = self.getFile(dylib_index).?.dylib.weak;
        for (self.getFile(dylib_index).?.dylib.dependents.items) |id| {
            // We will search for the dependent dylibs in the following order:
            // 1. Basename is in search lib directories or framework directories
            // 2. If name is an absolute path, search as-is optionally prepending a syslibroot
            //    if specified.
            // 3. If name is a relative path, substitute @rpath, @loader_path, @executable_path with
            //    dependees list of rpaths, and search there.
            // 4. Finally, just search the provided relative path directly in CWD.
            const full_path = full_path: {
                fail: {
                    const stem = std.fs.path.stem(id.name);
                    const framework_name = try std.fmt.allocPrint(gpa, "{s}.framework" ++ std.fs.path.sep_str ++ "{s}", .{
                        stem,
                        stem,
                    });
                    defer gpa.free(framework_name);

                    if (mem.endsWith(u8, id.name, framework_name)) {
                        // Framework
                        const full_path = (try self.resolveFramework(arena, framework_dirs, stem)) orelse break :fail;
                        break :full_path full_path;
                    }

                    // Library
                    const lib_name = eatPrefix(stem, "lib") orelse stem;
                    const full_path = (try self.resolveLib(arena, lib_dirs, lib_name)) orelse break :fail;
                    break :full_path full_path;
                }

                if (std.fs.path.isAbsolute(id.name)) {
                    const path = if (self.options.syslibroot) |root|
                        try std.fs.path.join(arena, &.{ root, id.name })
                    else
                        id.name;
                    for (&[_][]const u8{ "", ".tbd", ".dylib" }) |ext| {
                        const full_path = try std.fmt.allocPrint(arena, "{s}{s}", .{ path, ext });
                        if (try accessPath(full_path)) break :full_path full_path;
                    }
                }

                if (eatPrefix(id.name, "@rpath/")) |path| {
                    const dylib = self.getFile(dylib_index).?.dylib;
                    for (self.getFile(dylib.umbrella).?.dylib.rpaths.keys()) |rpath| {
                        const prefix = eatPrefix(rpath, "@loader_path/") orelse rpath;
                        const rel_path = try std.fs.path.join(arena, &.{ prefix, path });
                        var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                        const full_path = std.fs.realpath(rel_path, &buffer) catch continue;
                        break :full_path full_path;
                    }
                } else if (eatPrefix(id.name, "@loader_path/")) |_| {
                    return self.base.fatal("{s}: TODO handle install_name '{s}'", .{
                        self.getFile(dylib_index).?.dylib.path, id.name,
                    });
                } else if (eatPrefix(id.name, "@executable_path/")) |_| {
                    return self.base.fatal("{s}: TODO handle install_name '{s}'", .{
                        self.getFile(dylib_index).?.dylib.path, id.name,
                    });
                }

                var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                const full_path = std.fs.realpath(id.name, &buffer) catch {
                    dependents.appendAssumeCapacity(0);
                    continue;
                };
                break :full_path full_path;
            };
            const link_obj = LinkObject{
                .path = full_path,
                .tag = .obj,
                .weak = is_weak,
            };
            const file_index = file_index: {
                if (try self.parseDylib(arena, link_obj, false)) |file| break :file_index file;
                if (try self.parseTbd(link_obj, false)) |file| break :file_index file;
                break :file_index @as(File.Index, 0);
            };
            dependents.appendAssumeCapacity(file_index);
        }

        const dylib = self.getFile(dylib_index).?.dylib;
        for (dylib.dependents.items, dependents.items) |id, file_index| {
            if (self.getFile(file_index)) |file| {
                const dep_dylib = file.dylib;
                dep_dylib.hoisted = self.isHoisted(id.name);
                if (self.getFile(dep_dylib.umbrella) == null) {
                    dep_dylib.umbrella = dylib.umbrella;
                }
                if (!dep_dylib.hoisted) {
                    const umbrella = dep_dylib.getUmbrella(self);
                    for (dep_dylib.exports.items(.name), dep_dylib.exports.items(.flags)) |off, flags| {
                        try umbrella.addExport(gpa, dep_dylib.getString(off), flags);
                    }
                    try umbrella.rpaths.ensureUnusedCapacity(gpa, dep_dylib.rpaths.keys().len);
                    for (dep_dylib.rpaths.keys()) |rpath| {
                        umbrella.rpaths.putAssumeCapacity(rpath, {});
                    }
                }
            } else self.base.fatal("{s}: unable to resolve dependency {s}", .{ dylib.getUmbrella(self).path, id.name });
        }
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
    const tracy = trace(@src());
    defer tracy.end();

    // Resolve symbols on the set of all objects and shared objects (even if some are unneeded).
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.dylibs.items) |index| self.getFile(index).?.resolveSymbols(self);

    // Mark live objects.
    self.markLive();

    // Reset state of all globals after marking live objects.
    for (self.objects.items) |index| self.getFile(index).?.resetGlobals(self);
    for (self.dylibs.items) |index| self.getFile(index).?.resetGlobals(self);

    // Prune dead objects.
    var i: usize = 0;
    while (i < self.objects.items.len) {
        const index = self.objects.items[i];
        if (!self.getFile(index).?.object.alive) {
            _ = self.objects.orderedRemove(i);
        } else i += 1;
    }

    // Re-resolve the symbols.
    for (self.objects.items) |index| self.getFile(index).?.resolveSymbols(self);
    for (self.dylibs.items) |index| self.getFile(index).?.resolveSymbols(self);
}

fn markLive(self: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.undefined_symbols.items) |index| {
        if (self.getSymbol(index).getFile(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }
    if (self.entry_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        if (object.alive) object.markLive(self);
    }
}

fn deadStripDylibs(self: *MachO) void {
    for (&[_]?Symbol.Index{
        self.entry_index,
        self.dyld_stub_binder_index,
        self.objc_msg_send_index,
    }) |index| {
        if (index) |idx| {
            const sym = self.getSymbol(idx);
            if (sym.getFile(self)) |file| {
                if (file == .dylib) file.dylib.referenced = true;
            }
        }
    }

    for (self.dylibs.items) |index| {
        self.getFile(index).?.dylib.markReferenced(self);
    }

    var i: usize = 0;
    while (i < self.dylibs.items.len) {
        const index = self.dylibs.items[i];
        if (!self.getFile(index).?.dylib.isAlive(self)) {
            _ = self.dylibs.orderedRemove(i);
        } else i += 1;
    }
}

fn convertTentativeDefinitions(self: *MachO) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.convertTentativeDefinitions(self);
    }
}

fn markImportsAndExports(self: *MachO) void {
    for (self.objects.items) |index| {
        for (self.getFile(index).?.getSymbols()) |sym_index| {
            const sym = self.getSymbol(sym_index);
            const file = sym.getFile(self) orelse continue;
            if (sym.visibility != .global) continue;
            if (file == .dylib and !sym.flags.abs) {
                sym.flags.import = true;
                continue;
            }
            if (file.getIndex() == index) {
                sym.flags.@"export" = true;
            }
        }
    }

    for (self.undefined_symbols.items) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self)) |file| {
            if (sym.visibility != .global) continue;
            if (file == .dylib and !sym.flags.abs) sym.flags.import = true;
        }
    }

    for (&[_]?Symbol.Index{
        self.entry_index,
        self.dyld_stub_binder_index,
        self.objc_msg_send_index,
    }) |index| {
        if (index) |idx| {
            const sym = self.getSymbol(idx);
            if (sym.getFile(self)) |file| {
                if (file == .dylib) sym.flags.import = true;
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
    if (self.getInternalObject()) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.initOutputSection(atom.getInputSection(self), self);
        }
    }
    if (self.data_sect_index == null) {
        self.data_sect_index = try self.addSection("__DATA", "__data", .{});
    }
}

fn resolveSyntheticSymbols(self: *MachO) !void {
    const internal = self.getInternalObject() orelse return;

    if (!self.options.dylib) {
        self.mh_execute_header_index = try internal.addSymbol("__mh_execute_header", self);
        const sym = self.getSymbol(self.mh_execute_header_index.?);
        sym.flags.@"export" = true;
        sym.flags.dyn_ref = true;
        sym.visibility = .global;
    } else if (self.options.dylib) {
        self.mh_dylib_header_index = try internal.addSymbol("__mh_dylib_header", self);
    }

    self.dso_handle_index = try internal.addSymbol("___dso_handle", self);
    self.dyld_private_index = try internal.addSymbol("dyld_private", self);

    {
        const gpa = self.base.allocator;
        var boundary_symbols = std.AutoHashMap(Symbol.Index, void).init(gpa);
        defer boundary_symbols.deinit();

        for (self.objects.items) |index| {
            const object = self.getFile(index).?.object;
            for (object.symbols.items, 0..) |sym_index, i| {
                const nlist = object.symtab.items(.nlist)[i];
                const name = self.getSymbol(sym_index).getName(self);
                if (!nlist.undf() or !nlist.ext()) continue;
                if (mem.startsWith(u8, name, "segment$start$") or
                    mem.startsWith(u8, name, "segment$stop$") or
                    mem.startsWith(u8, name, "section$start$") or
                    mem.startsWith(u8, name, "section$stop$"))
                {
                    _ = try boundary_symbols.put(sym_index, {});
                }
            }
        }

        try self.boundary_symbols.ensureTotalCapacityPrecise(gpa, boundary_symbols.count());

        var it = boundary_symbols.iterator();
        while (it.next()) |entry| {
            _ = try internal.addSymbol(self.getSymbol(entry.key_ptr.*).getName(self), self);
            self.boundary_symbols.appendAssumeCapacity(entry.key_ptr.*);
        }
    }
}

fn createObjcSections(self: *MachO) !void {
    const gpa = self.base.allocator;
    var objc_msgsend_syms = std.AutoArrayHashMap(Symbol.Index, void).init(gpa);
    defer objc_msgsend_syms.deinit();

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;

        for (object.symbols.items, 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @intCast(i));
            const nlist = object.symtab.items(.nlist)[nlist_idx];
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = self.getSymbol(sym_index);
            if (sym.getFile(self) != null) continue;
            if (mem.startsWith(u8, sym.getName(self), "_objc_msgSend$")) {
                _ = try objc_msgsend_syms.put(sym_index, {});
            }
        }
    }

    for (objc_msgsend_syms.keys()) |sym_index| {
        const sym = self.getSymbol(sym_index);
        sym.value = 0;
        sym.atom = 0;
        sym.nlist_idx = 0;
        sym.file = self.internal_object_index.?;
        sym.flags = .{};
        sym.visibility = .hidden;
        const object = self.getInternalObject().?;
        const name = eatPrefix(sym.getName(self), "_objc_msgSend$").?;
        const selrefs_index = try object.addObjcMsgsendSections(name, self);
        try sym.addExtra(.{ .objc_selrefs = selrefs_index }, self);
        try object.symbols.append(gpa, sym_index);
    }
}

fn claimUnresolved(self: *MachO) error{OutOfMemory}!void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;

        for (object.symbols.items, 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @intCast(i));
            const nlist = object.symtab.items(.nlist)[nlist_idx];
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = self.getSymbol(sym_index);
            if (sym.getFile(self) != null) continue;

            const is_import = switch (self.options.undefined_treatment) {
                .@"error" => false,
                .warn, .suppress => nlist.weakRef(),
                .dynamic_lookup => true,
            };
            if (is_import) {
                sym.value = 0;
                sym.atom = 0;
                sym.nlist_idx = 0;
                sym.file = self.internal_object_index.?;
                sym.flags.weak = false;
                sym.flags.weak_ref = nlist.weakRef();
                sym.flags.import = is_import;
                sym.visibility = .global;
                try self.getInternalObject().?.symbols.append(self.base.allocator, sym_index);
            }
        }
    }
}

fn scanRelocs(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items) |index| {
        try self.getFile(index).?.object.scanRelocs(self);
    }

    try self.reportUndefs();

    if (self.entry_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) != null) {
            if (sym.flags.import) sym.flags.stubs = true;
        }
    }

    if (self.dyld_stub_binder_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) != null) sym.flags.got = true;
    }

    if (self.objc_msg_send_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) != null)
            sym.flags.got = true; // TODO is it always needed, or only if we are synthesising fast stubs?
    }

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
        if (symbol.flags.tlv_ptr) {
            log.debug("'{s}' needs TLV pointer", .{symbol.getName(self)});
            try self.tlv_ptr.addSymbol(index, self);
        }
        if (symbol.flags.objc_stubs) {
            log.debug("'{s}' needs OBJC STUBS", .{symbol.getName(self)});
            try self.objc_stubs.addSymbol(index, self);
        }
    }
}

fn reportUndefs(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    if (self.options.undefined_treatment == .suppress or
        self.options.undefined_treatment == .dynamic_lookup) return;

    const addFn = switch (self.options.undefined_treatment) {
        .dynamic_lookup => unreachable, // handled above
        .suppress => unreachable, // handled above
        .@"error" => &Zld.addErrorWithNotes,
        .warn => &Zld.addWarningWithNotes,
    };

    const max_notes = 4;

    var has_undefs = false;
    var it = self.undefs.iterator();
    while (it.next()) |entry| {
        const undef_sym = self.getSymbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @intFromBool(notes.items.len > max_notes);

        const err = try addFn(&self.base, nnotes);
        try err.addMsg("undefined symbol: {s}", .{undef_sym.getName(self)});
        has_undefs = true;

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

    for (self.undefined_symbols.items) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) != null) continue; // If undefined in an object file, will be reported above
        has_undefs = true;
        const err = try addFn(&self.base, 1);
        try err.addMsg("undefined symbol: {s}", .{sym.getName(self)});
        try err.addNote("-u command line option", .{});
    }

    if (self.entry_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) == null) {
            has_undefs = true;
            const err = try addFn(&self.base, 1);
            try err.addMsg("undefined symbol: {s}", .{sym.getName(self)});
            try err.addNote("implicit entry/start for main executable", .{});
        }
    }

    if (self.dyld_stub_binder_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) == null and self.stubs_sect_index != null) {
            has_undefs = true;
            const err = try addFn(&self.base, 1);
            try err.addMsg("undefined symbol: {s}", .{sym.getName(self)});
            try err.addNote("implicit -u command line option", .{});
        }
    }

    if (self.objc_msg_send_index) |index| {
        const sym = self.getSymbol(index);
        if (sym.getFile(self) == null and self.objc_stubs_sect_index != null) {
            has_undefs = true;
            const err = try addFn(&self.base, 1);
            try err.addMsg("undefined symbol: {s}", .{sym.getName(self)});
            try err.addNote("implicit -u command line option", .{});
        }
    }

    if (has_undefs) return error.UndefinedSymbols;
}

fn initSyntheticSections(self: *MachO) !void {
    const cpu_arch = self.options.cpu_arch.?;

    if (self.got.symbols.items.len > 0) {
        self.got_sect_index = try self.addSection("__DATA_CONST", "__got", .{
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
            .reserved1 = @intCast(self.stubs.symbols.items.len),
        });
    }

    if (self.stubs.symbols.items.len > 0) {
        self.stubs_sect_index = try self.addSection("__TEXT", "__stubs", .{
            .flags = macho.S_SYMBOL_STUBS |
                macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved1 = 0,
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
            .reserved1 = @intCast(self.stubs.symbols.items.len + self.got.symbols.items.len),
        });
    }

    if (self.objc_stubs.symbols.items.len > 0) {
        self.objc_stubs_sect_index = try self.addSection("__TEXT", "__objc_stubs", .{
            .flags = macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
    }

    if (self.tlv_ptr.symbols.items.len > 0) {
        self.tlv_ptr_sect_index = try self.addSection("__DATA", "__thread_ptrs", .{
            .flags = macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
        });
    }

    const needs_unwind_info = for (self.objects.items) |index| {
        if (self.getFile(index).?.object.has_unwind) break true;
    } else false;
    if (needs_unwind_info) {
        self.unwind_info_sect_index = try self.addSection("__TEXT", "__unwind_info", .{});
    }

    const needs_eh_frame = for (self.objects.items) |index| {
        if (self.getFile(index).?.object.has_eh_frame) break true;
    } else false;
    if (needs_eh_frame) {
        assert(needs_unwind_info);
        self.eh_frame_sect_index = try self.addSection("__TEXT", "__eh_frame", .{});
    }

    for (self.boundary_symbols.items) |sym_index| {
        const gpa = self.base.allocator;
        const sym = self.getSymbol(sym_index);
        const name = sym.getName(self);

        if (eatPrefix(name, "segment$start$")) |segname| {
            if (self.getSegmentByName(segname) == null) { // TODO check segname is valid
                const prot = getSegmentProt(segname);
                _ = try self.segments.append(gpa, .{
                    .cmdsize = @sizeOf(macho.segment_command_64),
                    .segname = makeStaticString(segname),
                    .initprot = prot,
                    .maxprot = prot,
                });
            }
        } else if (eatPrefix(name, "segment$stop$")) |segname| {
            if (self.getSegmentByName(segname) == null) { // TODO check segname is valid
                const prot = getSegmentProt(segname);
                _ = try self.segments.append(gpa, .{
                    .cmdsize = @sizeOf(macho.segment_command_64),
                    .segname = makeStaticString(segname),
                    .initprot = prot,
                    .maxprot = prot,
                });
            }
        } else if (eatPrefix(name, "section$start$")) |actual_name| {
            const sep = mem.indexOfScalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep]; // TODO check segname is valid
            const sectname = actual_name[sep + 1 ..]; // TODO check sectname is valid
            if (self.getSectionByName(segname, sectname) == null) {
                _ = try self.addSection(segname, sectname, .{});
            }
        } else if (eatPrefix(name, "section$stop$")) |actual_name| {
            const sep = mem.indexOfScalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep]; // TODO check segname is valid
            const sectname = actual_name[sep + 1 ..]; // TODO check sectname is valid
            if (self.getSectionByName(segname, sectname) == null) {
                _ = try self.addSection(segname, sectname, .{});
            }
        } else unreachable;
    }
}

fn getSegmentProt(segname: []const u8) macho.vm_prot_t {
    if (mem.eql(u8, segname, "__PAGEZERO")) return macho.PROT.NONE;
    if (mem.eql(u8, segname, "__TEXT")) return macho.PROT.READ | macho.PROT.EXEC;
    if (mem.eql(u8, segname, "__LINKEDIT")) return macho.PROT.READ;
    return macho.PROT.READ | macho.PROT.WRITE;
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
                if (mem.eql(u8, "__compact_unwind", header.sectName())) break :blk 0xe;
                if (mem.eql(u8, "__eh_frame", header.sectName())) break :blk 0xf;
                break :blk 0x3;
            },
        }
    };
    return (@as(u8, @intCast(segment_rank)) << 4) + section_rank;
}

pub fn sortSections(self: *MachO) !void {
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
    if (self.getInternalObject()) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = backlinks[atom.out_n_sect];
        }
    }

    for (&[_]*?u8{
        &self.data_sect_index,
        &self.got_sect_index,
        &self.stubs_sect_index,
        &self.stubs_helper_sect_index,
        &self.la_symbol_ptr_sect_index,
        &self.tlv_ptr_sect_index,
        &self.eh_frame_sect_index,
        &self.unwind_info_sect_index,
        &self.objc_stubs_sect_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }
}

pub fn addAtomsToSections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_n_sect];
            try atoms.append(self.base.allocator, atom_index);
        }
        for (object.symbols.items) |sym_index| {
            const sym = self.getSymbol(sym_index);
            const atom = sym.getAtom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (sym.getFile(self).?.getIndex() != index) continue;
            sym.out_n_sect = atom.out_n_sect;
        }
    }
    if (self.getInternalObject()) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_n_sect];
            try atoms.append(self.base.allocator, atom_index);
        }
        for (object.symbols.items) |sym_index| {
            const sym = self.getSymbol(sym_index);
            const atom = sym.getAtom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (sym.getFile(self).?.getIndex() != object.index) continue;
            sym.out_n_sect = atom.out_n_sect;
        }
    }
}

fn generateUnwindInfo(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    if (self.eh_frame_sect_index) |index| {
        const sect = &self.sections.items(.header)[index];
        sect.size = try eh_frame.calcSize(self);
        sect.@"align" = 3;
    }
    if (self.unwind_info_sect_index) |index| {
        const sect = &self.sections.items(.header)[index];
        try self.unwind_info.generate(self);
        sect.size = self.unwind_info.calcSize();
        sect.@"align" = 2;
    }
}

fn calcSectionSizes(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const cpu_arch = self.options.cpu_arch.?;

    if (self.data_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size += @sizeOf(u64);
        header.@"align" = 3;
    }

    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.atoms)) |*header, atoms| {
        if (atoms.items.len == 0) continue;
        if (self.requiresThunks() and header.isCode()) continue;

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            const atom_alignment = try math.powi(u32, 2, atom.alignment);
            const offset = mem.alignForward(u64, header.size, atom_alignment);
            const padding = offset - header.size;
            atom.value = offset;
            header.size += padding + atom.size;
            header.@"align" = @max(header.@"align", atom.alignment);
        }
    }

    if (self.requiresThunks()) {
        for (slice.items(.header), slice.items(.atoms), 0..) |header, atoms, i| {
            if (!header.isCode()) continue;
            if (atoms.items.len == 0) continue;

            // Create jump/branch range extenders if needed.
            try thunks.createThunks(@intCast(i), self);
        }
    }

    if (self.got_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.got.size();
        header.@"align" = 3;
    }

    if (self.stubs_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.stubs.size(self);
        header.@"align" = switch (cpu_arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => 0,
        };
    }

    if (self.stubs_helper_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.stubs_helper.size(self);
        header.@"align" = switch (cpu_arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => 0,
        };
    }

    if (self.la_symbol_ptr_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.la_symbol_ptr.size(self);
        header.@"align" = 3;
    }

    if (self.tlv_ptr_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.tlv_ptr.size();
        header.@"align" = 3;
    }

    if (self.objc_stubs_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.objc_stubs.size(self);
        header.@"align" = switch (cpu_arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => 0,
        };
    }
}

fn initSegments(self: *MachO) !void {
    const gpa = self.base.allocator;
    const slice = self.sections.slice();

    // First, create segments required by sections
    for (slice.items(.header)) |header| {
        const segname = header.segName();
        if (self.getSegmentByName(segname) == null) {
            const prot = getSegmentProt(segname);
            try self.segments.append(gpa, .{
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString(segname),
                .maxprot = prot,
                .initprot = prot,
            });
        }
    }

    // Add __PAGEZERO if required
    const pagezero_vmsize = self.options.pagezero_size orelse default_pagezero_vmsize;
    const aligned_pagezero_vmsize = mem.alignBackward(u64, pagezero_vmsize, self.getPageSize());
    if (!self.options.dylib and aligned_pagezero_vmsize > 0) {
        if (aligned_pagezero_vmsize != pagezero_vmsize) {
            // TODO convert into a warning
            log.warn("requested __PAGEZERO size (0x{x}) is not page aligned", .{pagezero_vmsize});
            log.warn("  rounding down to 0x{x}", .{aligned_pagezero_vmsize});
        }
        try self.segments.append(gpa, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString("__PAGEZERO"),
            .vmsize = aligned_pagezero_vmsize,
        });
    }

    // Add __LINKEDIT
    {
        const protection = getSegmentProt("__LINKEDIT");
        self.linkedit_seg_index = @intCast(self.segments.items.len);
        try self.segments.append(gpa, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString("__LINKEDIT"),
            .maxprot = protection,
            .initprot = protection,
        });
    }

    // __TEXT segment is non-optional
    if (self.getSegmentByName("__TEXT") == null) {
        const protection = getSegmentProt("__TEXT");
        try self.segments.append(gpa, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString("__TEXT"),
            .maxprot = protection,
            .initprot = protection,
        });
    }

    const sortFn = struct {
        fn sortFn(ctx: void, lhs: macho.segment_command_64, rhs: macho.segment_command_64) bool {
            _ = ctx;
            return getSegmentRank(lhs.segName()) < getSegmentRank(rhs.segName());
        }
    }.sortFn;

    // Sort segments
    mem.sort(macho.segment_command_64, self.segments.items, {}, sortFn);

    // Attach sections to segments
    for (slice.items(.header), slice.items(.segment_id)) |header, *seg_id| {
        const segname = header.segName();
        const segment_id = self.getSegmentByName(segname) orelse blk: {
            const segment_id = @as(u8, @intCast(self.segments.items.len));
            const protection = getSegmentProt(segname);
            try self.segments.append(gpa, .{
                .cmdsize = @sizeOf(macho.segment_command_64),
                .segname = makeStaticString(segname),
                .maxprot = protection,
                .initprot = protection,
            });
            break :blk segment_id;
        };
        const segment = &self.segments.items[segment_id];
        segment.cmdsize += @sizeOf(macho.section_64);
        segment.nsects += 1;
        seg_id.* = segment_id;
    }

    self.pagezero_seg_index = self.getSegmentByName("__PAGEZERO");
    self.text_seg_index = self.getSegmentByName("__TEXT").?;
    self.linkedit_seg_index = self.getSegmentByName("__LINKEDIT").?;
}

fn allocateSections(self: *MachO) !void {
    const headerpad = load_commands.calcMinHeaderPadSize(self);
    var vmaddr: u64 = if (self.pagezero_seg_index) |index|
        self.segments.items[index].vmaddr + self.segments.items[index].vmsize
    else
        0;
    vmaddr += headerpad;
    var fileoff = headerpad;

    const page_size = self.getPageSize();
    const slice = self.sections.slice();

    var next_seg_id: u8 = if (self.pagezero_seg_index) |index| index + 1 else 0;
    for (slice.items(.header), slice.items(.segment_id)) |*header, seg_id| {
        if (seg_id != next_seg_id) {
            vmaddr = mem.alignForward(u64, vmaddr, page_size);
            fileoff = mem.alignForward(u32, fileoff, page_size);
        }

        const alignment = try math.powi(u32, 2, header.@"align");

        vmaddr = mem.alignForward(u64, vmaddr, alignment);
        header.addr = vmaddr;
        vmaddr += header.size;

        if (!header.isZerofill()) {
            fileoff = mem.alignForward(u32, fileoff, alignment);
            header.offset = fileoff;
            fileoff += @intCast(header.size);
        }

        next_seg_id = seg_id;
    }
}

fn allocateSegments(self: *MachO) void {
    const page_size = self.getPageSize();
    var vmaddr = if (self.pagezero_seg_index) |index|
        self.segments.items[index].vmaddr + self.segments.items[index].vmsize
    else
        0;
    var fileoff: u64 = 0;
    const index = if (self.pagezero_seg_index) |index| index + 1 else 0;

    const slice = self.sections.slice();
    var next_sect_id: u8 = 0;
    for (self.segments.items[index..], index..) |*seg, seg_id| {
        seg.vmaddr = vmaddr;
        seg.fileoff = fileoff;

        for (
            slice.items(.header)[next_sect_id..],
            slice.items(.segment_id)[next_sect_id..],
        ) |header, sid| {
            if (seg_id != sid) break;

            vmaddr = header.addr + header.size;
            if (!header.isZerofill()) {
                fileoff = header.offset + header.size;
            }

            next_sect_id += 1;
        }

        vmaddr = mem.alignForward(u64, vmaddr, page_size);
        fileoff = mem.alignForward(u64, fileoff, page_size);

        seg.vmsize = vmaddr - seg.vmaddr;
        seg.filesize = fileoff - seg.fileoff;
    }
}

fn allocateAtoms(self: *MachO) void {
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.atoms)) |header, atoms| {
        if (atoms.items.len == 0) continue;
        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.flags.alive);
            atom.value += header.addr;
        }
    }

    for (self.thunks.items) |*thunk| {
        const header = self.sections.items(.header)[thunk.out_n_sect];
        thunk.value += header.addr;
    }
}

fn allocateSyntheticSymbols(self: *MachO) void {
    const text_seg = self.getTextSegment();

    if (self.mh_execute_header_index) |index| {
        const global = self.getSymbol(index);
        global.value = text_seg.vmaddr;
    }

    if (self.data_sect_index) |idx| {
        const sect = self.sections.items(.header)[idx];
        for (&[_]?Symbol.Index{
            self.dso_handle_index,
            self.mh_dylib_header_index,
            self.dyld_private_index,
        }) |maybe_index| {
            if (maybe_index) |index| {
                const global = self.getSymbol(index);
                global.value = sect.addr;
                global.out_n_sect = idx;
            }
        }
    }

    for (self.boundary_symbols.items) |sym_index| {
        const sym = self.getSymbol(sym_index);
        const name = sym.getName(self);

        sym.flags.@"export" = false;
        sym.value = text_seg.vmaddr;

        if (mem.startsWith(u8, name, "segment$start$")) {
            const segname = name["segment$start$".len..];
            if (self.getSegmentByName(segname)) |seg_id| {
                const seg = self.segments.items[seg_id];
                sym.value = seg.vmaddr;
            }
        } else if (mem.startsWith(u8, name, "segment$stop$")) {
            const segname = name["segment$stop$".len..];
            if (self.getSegmentByName(segname)) |seg_id| {
                const seg = self.segments.items[seg_id];
                sym.value = seg.vmaddr + seg.vmsize;
            }
        } else if (mem.startsWith(u8, name, "section$start$")) {
            const actual_name = name["section$start$".len..];
            const sep = mem.indexOfScalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep];
            const sectname = actual_name[sep + 1 ..];
            if (self.getSectionByName(segname, sectname)) |sect_id| {
                const sect = self.sections.items(.header)[sect_id];
                sym.value = sect.addr;
                sym.out_n_sect = sect_id;
            }
        } else if (mem.startsWith(u8, name, "section$stop$")) {
            const actual_name = name["section$stop$".len..];
            const sep = mem.indexOfScalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep];
            const sectname = actual_name[sep + 1 ..];
            if (self.getSectionByName(segname, sectname)) |sect_id| {
                const sect = self.sections.items(.header)[sect_id];
                sym.value = sect.addr + sect.size;
                sym.out_n_sect = sect_id;
            }
        } else unreachable;
    }

    if (self.objc_stubs.symbols.items.len > 0) {
        const addr = self.sections.items(.header)[self.objc_stubs_sect_index.?].addr;

        for (self.objc_stubs.symbols.items, 0..) |sym_index, idx| {
            const sym = self.getSymbol(sym_index);
            sym.value = addr + idx * ObjcStubsSection.entrySize(self.options.cpu_arch.?);
            sym.out_n_sect = self.objc_stubs_sect_index.?;
        }
    }
}

fn initDyldInfoSections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    if (self.got_sect_index != null) try self.got.addDyldRelocs(self);
    if (self.tlv_ptr_sect_index != null) try self.tlv_ptr.addDyldRelocs(self);
    if (self.la_symbol_ptr_sect_index != null) try self.la_symbol_ptr.addDyldRelocs(self);
    try self.initExportTrie();

    var nrebases: usize = 0;
    var nbinds: usize = 0;
    var nweak_binds: usize = 0;
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        nrebases += object.num_rebase_relocs;
        nbinds += object.num_bind_relocs;
        nweak_binds += object.num_weak_bind_relocs;
    }
    try self.rebase.entries.ensureUnusedCapacity(gpa, nrebases);
    try self.bind.entries.ensureUnusedCapacity(gpa, nbinds);
    try self.weak_bind.entries.ensureUnusedCapacity(gpa, nweak_binds);
}

fn initExportTrie(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    try self.export_trie.init(gpa);

    const seg = self.getTextSegment();
    for (self.objects.items) |index| {
        for (self.getFile(index).?.getSymbols()) |sym_index| {
            const sym = self.getSymbol(sym_index);
            if (!sym.flags.@"export") continue;
            if (sym.getAtom(self)) |atom| if (!atom.flags.alive) continue;
            if (sym.getFile(self).?.getIndex() != index) continue;
            var flags: u64 = if (sym.flags.abs)
                macho.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
            else if (sym.flags.tlv)
                macho.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
            else
                macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR;
            if (sym.flags.weak) {
                flags |= macho.EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
                self.weak_defines = true;
                self.binds_to_weak = true;
            }
            try self.export_trie.put(gpa, .{
                .name = sym.getName(self),
                .vmaddr_offset = sym.getAddress(.{ .stubs = false }, self) - seg.vmaddr,
                .export_flags = flags,
            });
        }
    }

    if (self.mh_execute_header_index) |index| {
        const sym = self.getSymbol(index);
        try self.export_trie.put(gpa, .{
            .name = sym.getName(self),
            .vmaddr_offset = sym.getAddress(.{}, self) - seg.vmaddr,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }
}

fn writeAtoms(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const cpu_arch = self.options.cpu_arch.?;
    const slice = self.sections.slice();

    var has_resolve_error = false;
    for (slice.items(.header), slice.items(.atoms)) |header, atoms| {
        if (atoms.items.len == 0) continue;
        if (header.isZerofill()) continue;

        const buffer = try gpa.alloc(u8, header.size);
        defer gpa.free(buffer);
        const padding_byte: u8 = if (header.isCode() and cpu_arch == .x86_64) 0xcc else 0;
        @memset(buffer, padding_byte);

        for (atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index).?;
            assert(atom.flags.alive);
            const off = atom.value - header.addr;
            atom.resolveRelocs(self, buffer[off..][0..atom.size]) catch |err| switch (err) {
                error.ResolveFailed => has_resolve_error = true,
                else => |e| return e,
            };
        }

        try self.base.file.pwriteAll(buffer, header.offset);
    }

    for (self.thunks.items) |thunk| {
        const header = slice.items(.header)[thunk.out_n_sect];
        const offset = thunk.value - header.addr + header.offset;
        const buffer = try gpa.alloc(u8, thunk.size());
        defer gpa.free(buffer);
        var stream = std.io.fixedBufferStream(buffer);
        try thunk.write(self, stream.writer());
        try self.base.file.pwriteAll(buffer, offset);
    }

    if (has_resolve_error) return error.ResolveFailed;
}

fn writeUnwindInfo(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    if (self.eh_frame_sect_index) |index| {
        const header = self.sections.items(.header)[index];
        const buffer = try gpa.alloc(u8, header.size);
        defer gpa.free(buffer);
        eh_frame.write(self, buffer);
        try self.base.file.pwriteAll(buffer, header.offset);
    }

    if (self.unwind_info_sect_index) |index| {
        const header = self.sections.items(.header)[index];
        const buffer = try gpa.alloc(u8, header.size);
        defer gpa.free(buffer);
        try self.unwind_info.write(self, buffer);
        try self.base.file.pwriteAll(buffer, header.offset);
    }
}

fn finalizeDyldInfoSections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.base.allocator;

    try self.rebase.finalize(gpa);
    try self.bind.finalize(gpa, self);
    try self.weak_bind.finalize(gpa, self);
    try self.lazy_bind.finalize(gpa, self);
    try self.export_trie.finalize(gpa);
}

fn writeSyntheticSections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    if (self.got_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, header.size);
        defer buffer.deinit();
        try self.got.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.pwriteAll(buffer.items, header.offset);
    }

    if (self.stubs_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, header.size);
        defer buffer.deinit();
        try self.stubs.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.pwriteAll(buffer.items, header.offset);
    }

    if (self.stubs_helper_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, header.size);
        defer buffer.deinit();
        try self.stubs_helper.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.pwriteAll(buffer.items, header.offset);
    }

    if (self.la_symbol_ptr_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, header.size);
        defer buffer.deinit();
        try self.la_symbol_ptr.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.pwriteAll(buffer.items, header.offset);
    }

    if (self.tlv_ptr_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, header.size);
        defer buffer.deinit();
        try self.tlv_ptr.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.pwriteAll(buffer.items, header.offset);
    }

    if (self.objc_stubs_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        var buffer = try std.ArrayList(u8).initCapacity(gpa, header.size);
        defer buffer.deinit();
        try self.objc_stubs.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.pwriteAll(buffer.items, header.offset);
    }
}

fn getNextLinkeditOffset(self: *MachO, alignment: u64) !u64 {
    const seg = self.getLinkeditSegment();
    const off = seg.fileoff + seg.filesize;
    const aligned = mem.alignForward(u64, off, alignment);
    const padding = aligned - off;

    if (padding > 0) {
        try self.base.file.pwriteAll(&[1]u8{0}, aligned);
        seg.filesize += padding;
    }

    return aligned;
}

fn writeDyldInfoSections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const cmd = &self.dyld_info_cmd;
    var needed_size: u32 = 0;

    cmd.rebase_off = needed_size;
    cmd.rebase_size = mem.alignForward(u32, @intCast(self.rebase.size()), @alignOf(u64));
    needed_size += cmd.rebase_size;

    cmd.bind_off = needed_size;
    cmd.bind_size = mem.alignForward(u32, @intCast(self.bind.size()), @alignOf(u64));
    needed_size += cmd.bind_size;

    cmd.weak_bind_off = needed_size;
    cmd.weak_bind_size = mem.alignForward(u32, @intCast(self.weak_bind.size()), @alignOf(u64));
    needed_size += cmd.weak_bind_size;

    cmd.lazy_bind_off = needed_size;
    cmd.lazy_bind_size = mem.alignForward(u32, @intCast(self.lazy_bind.size()), @alignOf(u64));
    needed_size += cmd.lazy_bind_size;

    cmd.export_off = needed_size;
    cmd.export_size = mem.alignForward(u32, @intCast(self.export_trie.size), @alignOf(u64));
    needed_size += cmd.export_size;

    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);
    @memset(buffer, 0);

    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();

    try self.rebase.write(writer);
    try stream.seekTo(cmd.bind_off);
    try self.bind.write(writer);
    try stream.seekTo(cmd.weak_bind_off);
    try self.weak_bind.write(writer);
    try stream.seekTo(cmd.lazy_bind_off);
    try self.lazy_bind.write(writer);
    try stream.seekTo(cmd.export_off);
    try self.export_trie.write(writer);

    const off = try self.getNextLinkeditOffset(@alignOf(u64));
    cmd.rebase_off += @intCast(off);
    cmd.bind_off += @intCast(off);
    cmd.weak_bind_off += @intCast(off);
    cmd.lazy_bind_off += @intCast(off);
    cmd.export_off += @intCast(off);

    try self.base.file.pwriteAll(buffer, off);

    self.getLinkeditSegment().filesize += needed_size;
}

fn writeFunctionStarts(self: *MachO) !void {
    const off = try self.getNextLinkeditOffset(@alignOf(u64));
    const cmd = &self.function_starts_cmd;
    cmd.dataoff = @intCast(off);
}

fn writeDataInCode(self: *MachO) !void {
    const cmd = &self.data_in_code_cmd;
    const off = try self.getNextLinkeditOffset(@alignOf(u64));
    cmd.dataoff = @intCast(off);

    const base = self.getTextSegment().vmaddr;

    const gpa = self.base.allocator;
    var dices = std.ArrayList(macho.data_in_code_entry).init(gpa);
    defer dices.deinit();

    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        const in_dices = object.getDataInCode();

        try dices.ensureUnusedCapacity(in_dices.len);

        var next_dice: usize = 0;
        for (object.atoms.items) |atom_index| {
            if (next_dice >= in_dices.len) break;
            const atom = self.getAtom(atom_index) orelse continue;
            const start_off = atom.getInputAddress(self);
            const end_off = start_off + atom.size;
            const start_dice = next_dice;

            if (end_off < in_dices[next_dice].offset) continue;

            while (next_dice < in_dices.len and
                in_dices[next_dice].offset < end_off) : (next_dice += 1)
            {}

            if (atom.flags.alive) for (in_dices[start_dice..next_dice]) |dice| {
                dices.appendAssumeCapacity(.{
                    .offset = @intCast(atom.value + dice.offset - start_off - base),
                    .length = dice.length,
                    .kind = dice.kind,
                });
            };
        }
    }

    const needed_size = dices.items.len * @sizeOf(macho.data_in_code_entry);
    cmd.datasize = @intCast(needed_size);

    try self.base.file.pwriteAll(mem.sliceAsBytes(dices.items), cmd.dataoff);

    self.getLinkeditSegment().filesize += needed_size;
}

fn calcSymtabSize(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.base.allocator;

    var nlocals: u32 = 0;
    var nstabs: u32 = 0;
    var nexports: u32 = 0;
    var nimports: u32 = 0;
    var strsize: u32 = 0;

    var files = std.ArrayList(File.Index).init(gpa);
    defer files.deinit();
    try files.ensureTotalCapacityPrecise(self.objects.items.len + self.dylibs.items.len + 1);
    for (self.objects.items) |index| files.appendAssumeCapacity(index);
    for (self.dylibs.items) |index| files.appendAssumeCapacity(index);
    if (self.internal_object_index) |index| files.appendAssumeCapacity(index);

    for (files.items) |index| {
        const file = self.getFile(index).?;
        const ctx = switch (file) {
            inline else => |x| &x.output_symtab_ctx,
        };
        ctx.ilocal = nlocals;
        ctx.istab = nstabs;
        ctx.iexport = nexports;
        ctx.iimport = nimports;
        try file.calcSymtabSize(self);
        nlocals += ctx.nlocals;
        nstabs += ctx.nstabs;
        nexports += ctx.nexports;
        nimports += ctx.nimports;
        strsize += ctx.strsize;
    }

    for (files.items) |index| {
        const file = self.getFile(index).?;
        const ctx = switch (file) {
            inline else => |x| &x.output_symtab_ctx,
        };
        ctx.istab += nlocals;
        ctx.iexport += nlocals + nstabs;
        ctx.iimport += nlocals + nstabs + nexports;
    }

    {
        const cmd = &self.symtab_cmd;
        cmd.nsyms = nlocals + nstabs + nexports + nimports;
        cmd.strsize = strsize + 1;
    }

    {
        const cmd = &self.dysymtab_cmd;
        cmd.ilocalsym = 0;
        cmd.nlocalsym = nlocals + nstabs;
        cmd.iextdefsym = nlocals + nstabs;
        cmd.nextdefsym = nexports;
        cmd.iundefsym = nlocals + nstabs + nexports;
        cmd.nundefsym = nimports;
    }
}

fn writeSymtab(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.base.allocator;
    const cmd = &self.symtab_cmd;
    const off = try self.getNextLinkeditOffset(@alignOf(u64));
    cmd.symoff = @intCast(off);

    try self.symtab.resize(gpa, cmd.nsyms);
    try self.strtab.ensureUnusedCapacity(gpa, cmd.strsize - 1);

    for (self.objects.items) |index| {
        self.getFile(index).?.writeSymtab(self);
    }
    for (self.dylibs.items) |index| {
        self.getFile(index).?.writeSymtab(self);
    }
    if (self.getInternalObject()) |internal| {
        internal.writeSymtab(self);
    }

    assert(self.strtab.items.len == cmd.strsize);

    try self.base.file.pwriteAll(mem.sliceAsBytes(self.symtab.items), cmd.symoff);

    self.getLinkeditSegment().filesize += cmd.nsyms * @sizeOf(macho.nlist_64);
}

fn writeIndsymtab(self: *MachO) !void {
    const gpa = self.base.allocator;
    const cmd = &self.dysymtab_cmd;
    const off = try self.getNextLinkeditOffset(@alignOf(u32));
    cmd.indirectsymoff = @intCast(off);
    cmd.nindirectsyms = self.indsymtab.nsyms(self);

    const needed_size = cmd.nindirectsyms * @sizeOf(u32);
    var buffer = try std.ArrayList(u8).initCapacity(gpa, needed_size);
    defer buffer.deinit();
    try self.indsymtab.write(self, buffer.writer());

    try self.base.file.pwriteAll(buffer.items, cmd.indirectsymoff);
    assert(buffer.items.len == needed_size);

    self.getLinkeditSegment().filesize += needed_size;
}

fn writeStrtab(self: *MachO) !void {
    const cmd = &self.symtab_cmd;
    const off = try self.getNextLinkeditOffset(@alignOf(u64));
    cmd.stroff = @intCast(off);
    try self.base.file.pwriteAll(self.strtab.items, cmd.stroff);
    self.getLinkeditSegment().filesize += cmd.strsize;
}

fn writeLoadCommands(self: *MachO) !struct { usize, usize, usize } {
    const gpa = self.base.allocator;
    const needed_size = load_commands.calcLoadCommandsSize(self, false);
    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    var cwriter = std.io.countingWriter(stream.writer());
    const writer = cwriter.writer();

    var ncmds: usize = 0;

    // Segment and section load commands
    {
        const slice = self.sections.slice();
        var sect_id: usize = 0;
        for (self.segments.items) |seg| {
            try writer.writeStruct(seg);
            for (slice.items(.header)[sect_id..][0..seg.nsects]) |header| {
                try writer.writeStruct(header);
            }
            sect_id += seg.nsects;
        }
        ncmds += self.segments.items.len;
    }

    try writer.writeStruct(self.dyld_info_cmd);
    ncmds += 1;
    try writer.writeStruct(self.function_starts_cmd);
    ncmds += 1;
    try writer.writeStruct(self.data_in_code_cmd);
    ncmds += 1;
    try writer.writeStruct(self.symtab_cmd);
    ncmds += 1;
    try writer.writeStruct(self.dysymtab_cmd);
    ncmds += 1;
    try load_commands.writeDylinkerLC(writer);
    ncmds += 1;

    if (self.entry_index) |global_index| {
        const sym = self.getSymbol(global_index);
        const seg = self.getTextSegment();
        const entryoff: u32 = if (sym.getFile(self) == null)
            0
        else
            @as(u32, @intCast(sym.getAddress(.{ .stubs = true }, self) - seg.vmaddr));
        try writer.writeStruct(macho.entry_point_command{
            .entryoff = entryoff,
            .stacksize = self.options.stack_size orelse 0,
        });
        ncmds += 1;
    }

    if (self.options.dylib) {
        try load_commands.writeDylibIdLC(&self.options, writer);
        ncmds += 1;
    }

    try load_commands.writeRpathLCs(self.options.rpath_list, writer);
    ncmds += self.options.rpath_list.len;

    try writer.writeStruct(macho.source_version_command{ .version = 0 });
    ncmds += 1;

    if (self.options.platform) |platform| {
        if (platform.isBuildVersionCompatible()) {
            try load_commands.writeBuildVersionLC(platform, self.options.sdk_version, writer);
            ncmds += 1;
        } else {
            try load_commands.writeVersionMinLC(platform, self.options.sdk_version, writer);
            ncmds += 1;
        }
    }

    const uuid_cmd_offset = @sizeOf(macho.mach_header_64) + cwriter.bytes_written;
    try writer.writeStruct(self.uuid_cmd);
    ncmds += 1;

    for (self.dylibs.items) |index| {
        const dylib = self.getFile(index).?.dylib;
        assert(dylib.isAlive(self));
        const dylib_id = dylib.id.?;
        try load_commands.writeDylibLC(.{
            .cmd = if (dylib.weak)
                .LOAD_WEAK_DYLIB
            else if (dylib.reexport)
                .REEXPORT_DYLIB
            else
                .LOAD_DYLIB,
            .name = dylib_id.name,
            .timestamp = dylib_id.timestamp,
            .current_version = dylib_id.current_version,
            .compatibility_version = dylib_id.compatibility_version,
        }, writer);
        ncmds += 1;
    }

    if (self.requiresCodeSig()) {
        try writer.writeStruct(self.codesig_cmd);
        ncmds += 1;
    }

    assert(cwriter.bytes_written == needed_size);

    try self.base.file.pwriteAll(buffer, @sizeOf(macho.mach_header_64));

    return .{ ncmds, buffer.len, uuid_cmd_offset };
}

fn writeHeader(self: *MachO, ncmds: usize, sizeofcmds: usize) !void {
    var header: macho.mach_header_64 = .{};
    header.flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK;

    if (self.options.namespace == .two_level) {
        header.flags |= macho.MH_TWOLEVEL;
    }

    switch (self.options.cpu_arch.?) {
        .aarch64 => {
            header.cputype = macho.CPU_TYPE_ARM64;
            header.cpusubtype = macho.CPU_SUBTYPE_ARM_ALL;
        },
        .x86_64 => {
            header.cputype = macho.CPU_TYPE_X86_64;
            header.cpusubtype = macho.CPU_SUBTYPE_X86_64_ALL;
        },
        else => {},
    }

    if (self.options.dylib) {
        header.filetype = macho.MH_DYLIB;
    } else {
        header.filetype = macho.MH_EXECUTE;
        header.flags |= macho.MH_PIE;
    }

    const has_reexports = for (self.dylibs.items) |index| {
        if (self.getFile(index).?.dylib.reexport) break true;
    } else false;
    if (!has_reexports) {
        header.flags |= macho.MH_NO_REEXPORTED_DYLIBS;
    }

    if (self.has_tlv) {
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
    }
    if (self.binds_to_weak) {
        header.flags |= macho.MH_BINDS_TO_WEAK;
    }
    if (self.weak_defines) {
        header.flags |= macho.MH_WEAK_DEFINES;
    }

    header.ncmds = @intCast(ncmds);
    header.sizeofcmds = @intCast(sizeofcmds);

    log.debug("writing Mach-O header {}", .{header});

    try self.base.file.pwriteAll(mem.asBytes(&header), 0);
}

fn writeUuid(self: *MachO, uuid_cmd_offset: usize, has_codesig: bool) !void {
    const file_size = if (!has_codesig) blk: {
        const seg = self.getLinkeditSegment();
        break :blk seg.fileoff + seg.filesize;
    } else self.codesig_cmd.dataoff;
    try calcUuid(self.base.allocator, self.base.thread_pool, self.base.file, file_size, &self.uuid_cmd.uuid);
    const offset = uuid_cmd_offset + @sizeOf(macho.load_command);
    try self.base.file.pwriteAll(&self.uuid_cmd.uuid, offset);
}

pub fn writeCodeSignaturePadding(self: *MachO, code_sig: *CodeSignature) !void {
    const seg = self.getLinkeditSegment();
    // Code signature data has to be 16-bytes aligned for Apple tools to recognize the file
    // https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/libstuff/checkout.c#L271
    const offset = mem.alignForward(u64, seg.fileoff + seg.filesize, 16);
    const needed_size = code_sig.estimateSize(offset);
    seg.filesize = offset + needed_size - seg.fileoff;
    seg.vmsize = mem.alignForward(u64, seg.filesize, self.getPageSize());
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ offset, offset + needed_size });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.base.file.pwriteAll(&[_]u8{0}, offset + needed_size - 1);

    self.codesig_cmd.dataoff = @as(u32, @intCast(offset));
    self.codesig_cmd.datasize = @as(u32, @intCast(needed_size));
}

pub fn writeCodeSignature(self: *MachO, code_sig: *CodeSignature) !void {
    const seg = self.getTextSegment();
    const offset = self.codesig_cmd.dataoff;

    var buffer = std.ArrayList(u8).init(self.base.allocator);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(code_sig.size());
    try code_sig.writeAdhocSignature(self, .{
        .file = self.base.file,
        .exec_seg_base = seg.fileoff,
        .exec_seg_limit = seg.filesize,
        .file_size = offset,
        .dylib = self.options.dylib,
    }, buffer.writer());
    assert(buffer.items.len == code_sig.size());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{
        offset,
        offset + buffer.items.len,
    });

    try self.base.file.pwriteAll(buffer.items, offset);
}

/// XNU starting with Big Sur running on arm64 is caching inodes of running binaries.
/// Any change to the binary will effectively invalidate the kernel's cache
/// resulting in a SIGKILL on each subsequent run. Since when doing incremental
/// linking we're modifying a binary in-place, this will end up with the kernel
/// killing it on every subsequent run. To circumvent it, we will copy the file
/// into a new inode, remove the original file, and rename the copy to match
/// the original file. This is super messy, but there doesn't seem any other
/// way to please the XNU.
pub fn invalidateKernelCache(dir: std.fs.Dir, sub_path: []const u8) !void {
    if (comptime builtin.target.isDarwin() and builtin.target.cpu.arch == .aarch64) {
        try dir.copyFile(sub_path, dir, sub_path, .{});
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
    if (self.options.adhoc_codesign) |cs| return cs;
    return switch (self.options.cpu_arch.?) {
        .aarch64 => true,
        else => false,
    };
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
        .segment_id = undefined, // Segments will be created automatically later down the pipeline.
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
    @memcpy(buf[0..bytes.len], bytes);
    return buf;
}

pub fn getSegmentByName(self: MachO, segname: []const u8) ?u8 {
    for (self.segments.items, 0..) |seg, i| {
        if (mem.eql(u8, segname, seg.segName())) return @as(u8, @intCast(i));
    } else return null;
}

pub fn getSectionByName(self: MachO, segname: []const u8, sectname: []const u8) ?u8 {
    for (self.sections.items(.header), 0..) |header, i| {
        if (mem.eql(u8, header.segName(), segname) and mem.eql(u8, header.sectName(), sectname))
            return @as(u8, @intCast(i));
    } else return null;
}

pub fn getTlsAddress(self: MachO) u64 {
    for (self.sections.items(.header)) |header| switch (header.type()) {
        macho.S_THREAD_LOCAL_REGULAR,
        macho.S_THREAD_LOCAL_ZEROFILL,
        => return header.addr,
        else => {},
    };
    return 0;
}

pub inline fn getTextSegment(self: *MachO) *macho.segment_command_64 {
    return &self.segments.items[self.text_seg_index.?];
}

pub inline fn getLinkeditSegment(self: *MachO) *macho.segment_command_64 {
    return &self.segments.items[self.linkedit_seg_index.?];
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

pub fn addUnwindRecord(self: *MachO) !UnwindInfo.Record.Index {
    const index = @as(UnwindInfo.Record.Index, @intCast(self.unwind_records.items.len));
    const rec = try self.unwind_records.addOne(self.base.allocator);
    rec.* = .{};
    return index;
}

pub fn getUnwindRecord(self: *MachO, index: UnwindInfo.Record.Index) *UnwindInfo.Record {
    assert(index < self.unwind_records.items.len);
    return &self.unwind_records.items[index];
}

pub fn addThunk(self: *MachO) !Thunk.Index {
    const index = @as(Thunk.Index, @intCast(self.thunks.items.len));
    const thunk = try self.thunks.addOne(self.base.allocator);
    thunk.* = .{};
    return index;
}

pub fn getThunk(self: *MachO, index: Thunk.Index) *Thunk {
    assert(index < self.thunks.items.len);
    return &self.thunks.items[index];
}

pub fn eatPrefix(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (mem.startsWith(u8, path, prefix)) return path[prefix.len..];
    return null;
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
        try writer.print("object({d}) : {} : has_debug({})", .{
            index,
            object.fmtPath(),
            object.hasDebugInfo(),
        });
        if (!object.alive) try writer.writeAll(" : ([*])");
        try writer.writeByte('\n');
        try writer.print("{}{}{}{}{}\n", .{
            object.fmtAtoms(self),
            object.fmtCies(self),
            object.fmtFdes(self),
            object.fmtUnwindRecords(self),
            object.fmtSymtab(self),
        });
    }
    for (self.dylibs.items) |index| {
        const dylib = self.getFile(index).?.dylib;
        try writer.print("dylib({d}) : {s} : needed({}) : weak({})", .{
            index,
            dylib.path,
            dylib.needed,
            dylib.weak,
        });
        if (!dylib.isAlive(self)) try writer.writeAll(" : ([*])");
        try writer.writeByte('\n');
        try writer.print("{}\n", .{dylib.fmtSymtab(self)});
    }
    if (self.getInternalObject()) |internal| {
        try writer.print("internal({d}) : internal\n", .{internal.index});
        try writer.print("{}{}\n", .{ internal.fmtAtoms(self), internal.fmtSymtab(self) });
    }
    try writer.writeAll("thunks\n");
    for (self.thunks.items, 0..) |thunk, index| {
        try writer.print("thunk({d}) : {}\n", .{ index, thunk.fmt(self) });
    }
    try writer.print("stubs\n{}\n", .{self.stubs.fmt(self)});
    try writer.print("objc_stubs\n{}\n", .{self.objc_stubs.fmt(self)});
    try writer.print("got\n{}\n", .{self.got.fmt(self)});
    try writer.print("tlv_ptr\n{}\n", .{self.tlv_ptr.fmt(self)});
    try writer.writeByte('\n');
    try writer.print("sections\n{}\n", .{self.fmtSections()});
    try writer.print("segments\n{}\n", .{self.fmtSegments()});
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
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.segment_id), 0..) |header, seg_id, i| {
        try writer.print("sect({d}) : seg({d}) : {s},{s} : @{x} ({x}) : align({x}) : size({x})\n", .{
            i,               seg_id,      header.segName(), header.sectName(), header.offset, header.addr,
            header.@"align", header.size,
        });
    }
}

fn fmtSegments(self: *MachO) std.fmt.Formatter(formatSegments) {
    return .{ .data = self };
}

fn formatSegments(
    self: *MachO,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.segments.items, 0..) |seg, i| {
        try writer.print("seg({d}) : {s} : @{x}-{x} ({x}-{x})\n", .{
            i,           seg.segName(),              seg.vmaddr, seg.vmaddr + seg.vmsize,
            seg.fileoff, seg.fileoff + seg.filesize,
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
    hidden: bool = false,
    reexport: bool = false,
    must_link: bool = false,

    pub fn format(
        self: LinkObject,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        switch (self.tag) {
            .lib => if (self.needed) {
                try writer.writeAll("-needed-l");
            } else if (self.weak) {
                try writer.writeAll("-weak-l");
            } else if (self.hidden) {
                try writer.writeAll("-hidden-l");
            } else if (self.reexport) {
                try writer.writeAll("-reexport-l");
            } else try writer.writeAll("-l"),

            .framework => if (self.needed) {
                try writer.writeAll("-needed_framework ");
            } else if (self.weak) {
                try writer.writeAll("-weak_framework ");
            } else try writer.writeAll("-framework "),

            .obj => if (self.must_link) {
                try writer.writeAll("-force_load ");
            } else if (self.hidden) {
                try writer.writeAll("-load_hidden ");
            },
        }
        try writer.writeAll(self.path);
    }
};

/// Default virtual memory offset corresponds to the size of __PAGEZERO segment and
/// start of __TEXT segment.
const default_pagezero_vmsize: u64 = 0x100000000;

const Section = struct {
    header: macho.section_64,
    segment_id: u8,
    atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
};

pub const SymtabCtx = struct {
    ilocal: u32 = 0,
    istab: u32 = 0,
    iexport: u32 = 0,
    iimport: u32 = 0,
    nlocals: u32 = 0,
    nstabs: u32 = 0,
    nexports: u32 = 0,
    nimports: u32 = 0,
    strsize: u32 = 0,
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
const relocatable = @import("MachO/relocatable.zig");
const synthetic = @import("MachO/synthetic.zig");
const state_log = std.log.scoped(.state);
const std = @import("std");
const thunks = @import("MachO/thunks.zig");
const trace = @import("tracy.zig").trace;

const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Archive = @import("MachO/Archive.zig");
const Atom = @import("MachO/Atom.zig");
const BindSection = synthetic.BindSection;
const CodeSignature = @import("MachO/CodeSignature.zig");
const Dylib = @import("MachO/Dylib.zig");
const DwarfInfo = @import("MachO/DwarfInfo.zig");
const ExportTrieSection = synthetic.ExportTrieSection;
const File = @import("MachO/file.zig").File;
const GotSection = synthetic.GotSection;
const Indsymtab = synthetic.Indsymtab;
const InternalObject = @import("MachO/InternalObject.zig");
const MachO = @This();
const Md5 = std.crypto.hash.Md5;
const Object = @import("MachO/Object.zig");
const ObjcStubsSection = synthetic.ObjcStubsSection;
pub const Options = @import("MachO/Options.zig");
const LazyBindSection = synthetic.LazyBindSection;
const LaSymbolPtrSection = synthetic.LaSymbolPtrSection;
const LibStub = @import("tapi.zig").LibStub;
const RebaseSection = synthetic.RebaseSection;
const Symbol = @import("MachO/Symbol.zig");
const StringTable = @import("strtab.zig").StringTable;
const StubsSection = synthetic.StubsSection;
const StubsHelperSection = synthetic.StubsHelperSection;
const Thunk = thunks.Thunk;
const ThreadPool = std.Thread.Pool;
const TlvPtrSection = synthetic.TlvPtrSection;
const UnwindInfo = @import("MachO/UnwindInfo.zig");
const WeakBindSection = synthetic.WeakBindSection;
const Zld = @import("Zld.zig");
