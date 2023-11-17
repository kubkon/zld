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

mh_execute_header_index: ?Symbol.Index = null,
dso_handle_index: ?Symbol.Index = null,

entry_index: ?Symbol.Index = null,

string_intern: StringTable(.string_intern) = .{},

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

    try self.markImportsAndExports();

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

    // TODO do we claim unresolved symbols here like we do for ELF?

    try self.scanRelocs();

    state_log.debug("{}", .{self.dumpState()});

    // try self.createDyldPrivateAtom();
    // try self.createTentativeDefAtoms();
    // try self.createStubHelperPreambleAtom();

    // if (!self.options.dylib) {
    //     const global = self.getEntryPoint();
    //     if (self.getSymbol(global).undf()) {
    //         // We do one additional check here in case the entry point was found in one of the dylibs.
    //         // (I actually have no idea what this would imply but it is a possible outcome and so we
    //         // support it.)
    //         try Atom.addStub(self, global);
    //     }
    // }

    // for (self.objects.items) |object| {
    //     for (object.atoms.items) |atom_index| {
    //         const atom = self.getAtom(atom_index);
    //         const sym = self.getSymbol(atom.getSymbolWithLoc());
    //         const header = self.sections.items(.header)[sym.n_sect - 1];
    //         if (header.isZerofill()) continue;

    //         const relocs = Atom.getAtomRelocs(self, atom_index);
    //         try Atom.scanAtomRelocs(self, atom_index, relocs);
    //     }
    // }

    // try eh_frame.scanRelocs(self);
    // try UnwindInfo.scanRelocs(self);

    // self.base.reportWarningsAndErrorsAndExit();

    // try self.createDyldStubBinderGotAtom();

    // try self.calcSectionSizes();

    // var unwind_info = UnwindInfo{ .gpa = self.base.allocator };
    // defer unwind_info.deinit();
    // try unwind_info.collect(self);

    // try eh_frame.calcSectionSize(self, &unwind_info);
    // try unwind_info.calcSectionSize(self);

    // try self.pruneAndSortSections();
    // try self.createSegments();
    // try self.allocateSegments();

    // try self.allocateSpecialSymbols();

    // if (build_options.enable_logging) {
    //     self.logSymtab();
    //     self.logSegments();
    //     self.logSections();
    //     self.logAtoms();
    // }

    // try self.writeAtoms();
    // try eh_frame.write(self, &unwind_info);
    // try unwind_info.write(self);
    // try self.writeLinkeditSegmentData();

    // // If the last section of __DATA segment is zerofill section, we need to ensure
    // // that the free space between the end of the last non-zerofill section of __DATA
    // // segment and the beginning of __LINKEDIT segment is zerofilled as the loader will
    // // copy-paste this space into memory for quicker zerofill operation.
    // if (self.getSegmentByName("__DATA")) |data_seg_id| blk: {
    //     var physical_zerofill_start: ?u64 = null;
    //     const section_indexes = self.getSectionIndexes(data_seg_id);
    //     for (self.sections.items(.header)[section_indexes.start..section_indexes.end]) |header| {
    //         if (header.isZerofill() and header.size > 0) break;
    //         physical_zerofill_start = header.offset + header.size;
    //     } else break :blk;
    //     const start = physical_zerofill_start orelse break :blk;
    //     const linkedit = self.getLinkeditSegmentPtr();
    //     const size = linkedit.fileoff - start;
    //     if (size > 0) {
    //         log.debug("zeroing out zerofill area of length {x} at {x}", .{ size, start });
    //         var padding = try self.base.allocator.alloc(u8, size);
    //         defer self.base.allocator.free(padding);
    //         @memset(padding, 0);
    //         try self.base.file.pwriteAll(padding, start);
    //     }
    // }

    // var codesig: ?CodeSignature = if (self.requiresCodeSig()) blk: {
    //     // Preallocate space for the code signature.
    //     // We need to do this at this stage so that we have the load commands with proper values
    //     // written out to the file.
    //     // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
    //     // where the code signature goes into.
    //     var codesig = CodeSignature.init(self.getPageSize());
    //     codesig.code_directory.ident = fs.path.basename(self.options.emit.sub_path);
    //     if (self.options.entitlements) |path| {
    //         try codesig.addEntitlements(gpa, path);
    //     }
    //     try self.writeCodeSignaturePadding(&codesig);
    //     break :blk codesig;
    // } else null;
    // defer if (codesig) |*csig| csig.deinit(gpa);

    // // Write load commands
    // var lc_buffer = std.ArrayList(u8).init(arena);
    // const lc_writer = lc_buffer.writer();

    // try self.writeSegmentHeaders(lc_writer);
    // try lc_writer.writeStruct(self.dyld_info_cmd);
    // try lc_writer.writeStruct(self.function_starts_cmd);
    // try lc_writer.writeStruct(self.data_in_code_cmd);
    // try lc_writer.writeStruct(self.symtab_cmd);
    // try lc_writer.writeStruct(self.dysymtab_cmd);
    // try load_commands.writeDylinkerLC(lc_writer);

    // if (!self.options.dylib) {
    //     const seg_id = self.getSegmentByName("__TEXT").?;
    //     const seg = self.segments.items[seg_id];
    //     const global = self.getEntryPoint();
    //     const sym = self.getSymbol(global);

    //     const addr: u64 = if (sym.undf()) blk: {
    //         // In this case, the symbol has been resolved in one of dylibs and so we point
    //         // to the stub as its vmaddr value.
    //         const stub_atom_index = self.getStubsAtomIndexForSymbol(global).?;
    //         const stub_atom = self.getAtom(stub_atom_index);
    //         const stub_sym = self.getSymbol(stub_atom.getSymbolWithLoc());
    //         break :blk stub_sym.n_value;
    //     } else sym.n_value;

    //     try lc_writer.writeStruct(macho.entry_point_command{
    //         .entryoff = @as(u32, @intCast(addr - seg.vmaddr)),
    //         .stacksize = self.options.stack_size orelse 0,
    //     });
    // } else {
    //     assert(self.options.dylib);
    //     try load_commands.writeDylibIdLC(&self.options, lc_writer);
    // }

    // try load_commands.writeRpathLCs(self.base.allocator, &self.options, lc_writer);
    // try lc_writer.writeStruct(macho.source_version_command{
    //     .version = 0,
    // });

    // if (self.options.platform) |platform| {
    //     if (platform.isBuildVersionCompatible()) {
    //         try load_commands.writeBuildVersionLC(platform, self.options.sdk_version, lc_writer);
    //     } else {
    //         try load_commands.writeVersionMinLC(platform, self.options.sdk_version, lc_writer);
    //     }
    // }

    // const uuid_cmd_offset = @sizeOf(macho.mach_header_64) + @as(u32, @intCast(lc_buffer.items.len));
    // try lc_writer.writeStruct(self.uuid_cmd);

    // try load_commands.writeLoadDylibLCs(self.dylibs.items, self.referenced_dylibs.keys(), lc_writer);

    // if (self.requiresCodeSig()) {
    //     try lc_writer.writeStruct(self.codesig_cmd);
    // }

    // const ncmds = load_commands.calcNumOfLCs(lc_buffer.items);
    // try self.base.file.pwriteAll(lc_buffer.items, @sizeOf(macho.mach_header_64));
    // try self.writeHeader(ncmds, @as(u32, @intCast(lc_buffer.items.len)));

    // try self.writeUuid(uuid_cmd_offset, self.requiresCodeSig());

    // if (codesig) |*csig| {
    //     try self.writeCodeSignature(csig); // code signing always comes last

    //     if (comptime builtin.target.isDarwin()) {
    //         const dir = self.options.emit.directory;
    //         const path = self.options.emit.sub_path;
    //         try dir.copyFile(path, dir, path, .{});
    //     }
    // }

    // self.base.reportWarningsAndErrorsAndExit();
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

fn markImportsAndExports(self: *MachO) !void {
    if (!self.options.dylib)
        for (self.dylibs.items) |index| {
            for (self.getFile(index).?.getGlobals()) |global_index| {
                const global = self.getSymbol(global_index);
                const file = global.getFile(self) orelse continue;
                if (file != .dylib and !global.getNlist(self).pext()) global.flags.@"export" = true;
            }
        };

    for (self.objects.items) |index| {
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
}

fn initOutputSections(self: *MachO) !void {
    for (self.objects.items) |index| {
        const object = self.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try object.initOutputSection(atom.getInputSection(self), self);
        }
    }
}

fn resolveSyntheticSymbols(self: *MachO) !void {
    const internal_index = self.internal_object_index orelse return;
    const internal = self.getFile(internal_index).?.internal;
    self.mh_execute_header_index = try internal.addGlobal("__mh_execute_header", self);

    if (self.getGlobalByName("__dso_handle")) |index| {
        if (self.getSymbol(index).getFile(self) == null)
            self.dso_handle_index = try internal.addGlobal("__dso_handle", self);
    }

    internal.resolveSymbols(self);
}

fn scanRelocs(self: *MachO) !void {
    for (self.objects.items) |index| {
        try self.getFile(index).?.object.scanRelocs(self);
    }

    try self.reportUndefs();
    self.base.reportWarningsAndErrorsAndExit();

    for (self.symbols.items, 0..) |*symbol, i| {
        const index = @as(Symbol.Index, @intCast(i));
        _ = index;
        if (symbol.flags.got) {
            log.debug("'{s}' needs GOT", .{symbol.getName(self)});
        }
        if (symbol.flags.stubs) {
            log.debug("'{s}' needs STUBS", .{symbol.getName(self)});
        }
    }
}

fn reportUndefs(self: *MachO) !void {
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
        while (inote < nnotes) : (inote += 1) {
            const atom = self.getAtom(notes.items[inote]).?;
            const object = atom.getObject(self);
            try err.addNote("referenced by {}:{s}", .{ object.fmtPath(), atom.getName(self) });
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            try err.addNote("referenced {d} more times", .{remaining});
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

fn makeStaticString(bytes: []const u8) [16]u8 {
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
    if (self.internal_object_index) |index| {
        const internal = self.getFile(index).?.internal;
        try writer.print("internal({d}) : internal\n", .{index});
        try writer.print("{}\n", .{internal.fmtSymtab(self)});
    }
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
const MachO = @This();
const Md5 = std.crypto.hash.Md5;
const Object = @import("MachO/Object.zig");
pub const Options = @import("MachO/Options.zig");
const LazyBind = @import("MachO/dyld_info/bind.zig").LazyBind(*const MachO, MachO.SymbolWithLoc);
const LibStub = @import("tapi.zig").LibStub;
const Rebase = @import("MachO/dyld_info/Rebase.zig");
const Symbol = @import("MachO/Symbol.zig");
const StringTable = @import("strtab.zig").StringTable;
const ThreadPool = std.Thread.Pool;
const Trie = @import("MachO/Trie.zig");
const UnwindInfo = @import("MachO/UnwindInfo.zig");
const Zld = @import("Zld.zig");
