const MachO = @This();

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.macho);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const aarch64 = @import("aarch64.zig");
const bind = @import("MachO/bind.zig");
const dead_strip = @import("MachO/dead_strip.zig");
const fat = @import("MachO/fat.zig");

const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Archive = @import("MachO/Archive.zig");
const Atom = @import("MachO/Atom.zig");
const CodeSignature = @import("MachO/CodeSignature.zig");
const Dylib = @import("MachO/Dylib.zig");
const Object = @import("MachO/Object.zig");
pub const Options = @import("MachO/Options.zig");
const LibStub = @import("tapi.zig").LibStub;
const StringTable = @import("strtab.zig").StringTable;
const Trie = @import("MachO/Trie.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.macho;

pub const N_DESC_GCED: u16 = @bitCast(u16, @as(i16, -1));

const Section = struct {
    header: macho.section_64,
    segment_index: u8,
    first_atom_index: AtomIndex,
    last_atom_index: AtomIndex,
};

base: Zld,
options: Options,

/// Page size is dependent on the target cpu architecture.
/// For x86_64 that's 4KB, whereas for aarch64, that's 16KB.
page_size: u16,

objects: std.ArrayListUnmanaged(Object) = .{},
archives: std.ArrayListUnmanaged(Archive) = .{},
dylibs: std.ArrayListUnmanaged(Dylib) = .{},
dylibs_map: std.StringHashMapUnmanaged(u16) = .{},
referenced_dylibs: std.AutoArrayHashMapUnmanaged(u16, void) = .{},

segments: std.ArrayListUnmanaged(macho.segment_command_64) = .{},
sections: std.MultiArrayList(Section) = .{},

locals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
globals: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
unresolved: std.AutoArrayHashMapUnmanaged(u32, void) = .{},

dyld_stub_binder_index: ?u32 = null,
dyld_private_sym_index: ?u32 = null,
stub_helper_preamble_sym_index: ?u32 = null,

strtab: StringTable(.strtab) = .{},

tlv_ptr_entries: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, u32) = .{},
got_entries: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, u32) = .{},
stubs: std.AutoArrayHashMapUnmanaged(SymbolWithLoc, u32) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},
atom_by_index_table: std.AutoHashMapUnmanaged(u32, AtomIndex) = .{},

relocs: RelocationTable = .{},
rebases: RebaseTable = .{},
bindings: BindingTable = .{},

pub const AtomIndex = u32;

const BindingTable = std.AutoHashMapUnmanaged(AtomIndex, std.ArrayListUnmanaged(Atom.Binding));
const RebaseTable = std.AutoHashMapUnmanaged(AtomIndex, std.ArrayListUnmanaged(u32));
const RelocationTable = std.AutoHashMapUnmanaged(AtomIndex, std.ArrayListUnmanaged(Atom.Relocation));

pub const SymbolWithLoc = struct {
    // Index into the respective symbol table.
    sym_index: u32,

    // null means it's a synthetic global.
    file: ?u32 = null,
};

/// Default path to dyld
const default_dyld_path: [*:0]const u8 = "/usr/lib/dyld";

/// Default virtual memory offset corresponds to the size of __PAGEZERO segment and
/// start of __TEXT segment.
const default_pagezero_vmsize: u64 = 0x100000000;

/// We commit 0x1000 = 4096 bytes of space to the header and
/// the table of load commands. This should be plenty for any
/// potential future extensions.
const default_headerpad_size: u32 = 0x1000;

pub fn openPath(allocator: Allocator, options: Options) !*MachO {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = if (builtin.os.tag == .windows) 0 else 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer self.base.destroy();

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: Allocator, options: Options) !*MachO {
    const self = try gpa.create(MachO);
    const cpu_arch = options.target.cpu_arch.?;
    const page_size: u16 = if (cpu_arch == .aarch64) 0x4000 else 0x1000;

    self.* = .{
        .base = .{
            .tag = .macho,
            .allocator = gpa,
            .file = undefined,
        },
        .options = options,
        .page_size = page_size,
    };

    return self;
}

pub fn flush(self: *MachO) !void {
    const gpa = self.base.allocator;
    var arena_allocator = ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const syslibroot = self.options.syslibroot;
    const cpu_arch = self.options.target.cpu_arch.?;
    const os_tag = self.options.target.os_tag.?;
    const abi = self.options.target.abi.?;

    try self.strtab.buffer.append(gpa, 0);

    var lib_not_found = false;
    var framework_not_found = false;

    // Positional arguments to the linker such as object files and static archives.
    var positionals = std.ArrayList([]const u8).init(arena);
    try positionals.ensureUnusedCapacity(self.options.positionals.len);

    var must_link_archives = std.StringArrayHashMap(void).init(arena);
    try must_link_archives.ensureUnusedCapacity(self.options.positionals.len);

    for (self.options.positionals) |obj| {
        if (must_link_archives.contains(obj.path)) continue;
        if (obj.must_link) {
            _ = must_link_archives.getOrPutAssumeCapacity(obj.path);
        } else {
            positionals.appendAssumeCapacity(obj.path);
        }
    }

    // Shared and static libraries passed via `-l` flag.
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.lib_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try lib_dirs.append(search_dir);
        } else {
            log.warn("directory not found for '-L{s}'", .{dir});
        }
    }

    var libs = std.StringArrayHashMap(Zld.SystemLib).init(arena);

    // Assume ld64 default -search_paths_first if no strategy specified.
    const search_strategy = self.options.search_strategy orelse .paths_first;
    outer: for (self.options.libs.keys()) |lib_name| {
        switch (search_strategy) {
            .paths_first => {
                // Look in each directory for a dylib (stub first), and then for archive
                for (lib_dirs.items) |dir| {
                    for (&[_][]const u8{ ".tbd", ".dylib", ".a" }) |ext| {
                        if (try resolveLib(arena, dir, lib_name, ext)) |full_path| {
                            try libs.put(full_path, self.options.libs.get(lib_name).?);
                            continue :outer;
                        }
                    }
                } else {
                    log.warn("library not found for '-l{s}'", .{lib_name});
                    lib_not_found = true;
                }
            },
            .dylibs_first => {
                // First, look for a dylib in each search dir
                for (lib_dirs.items) |dir| {
                    for (&[_][]const u8{ ".tbd", ".dylib" }) |ext| {
                        if (try resolveLib(arena, dir, lib_name, ext)) |full_path| {
                            try libs.put(full_path, self.options.libs.get(lib_name).?);
                            continue :outer;
                        }
                    }
                } else for (lib_dirs.items) |dir| {
                    if (try resolveLib(arena, dir, lib_name, ".a")) |full_path| {
                        try libs.put(full_path, self.options.libs.get(lib_name).?);
                    } else {
                        log.warn("library not found for '-l{s}'", .{lib_name});
                        lib_not_found = true;
                    }
                }
            },
        }
    }

    if (lib_not_found) {
        log.warn("Library search paths:", .{});
        for (lib_dirs.items) |dir| {
            log.warn("  {s}", .{dir});
        }
    }

    // frameworks
    var framework_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.framework_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try framework_dirs.append(search_dir);
        } else {
            log.warn("directory not found for '-F{s}'", .{dir});
        }
    }

    outer: for (self.options.frameworks.keys()) |f_name| {
        for (framework_dirs.items) |dir| {
            for (&[_][]const u8{ ".tbd", ".dylib", "" }) |ext| {
                if (try resolveFramework(arena, dir, f_name, ext)) |full_path| {
                    const info = self.options.frameworks.get(f_name).?;
                    try libs.put(full_path, .{
                        .needed = info.needed,
                        .weak = info.weak,
                    });
                    continue :outer;
                }
            }
        } else {
            log.warn("framework not found for '-framework {s}'", .{f_name});
            framework_not_found = true;
        }
    }

    if (framework_not_found) {
        log.warn("Framework search paths:", .{});
        for (framework_dirs.items) |dir| {
            log.warn("  {s}", .{dir});
        }
    }

    var dependent_libs = std.fifo.LinearFifo(struct {
        id: Dylib.Id,
        parent: u16,
    }, .Dynamic).init(arena);

    try self.parsePositionals(positionals.items, syslibroot, &dependent_libs);
    try self.parseAndForceLoadStaticArchives(must_link_archives.keys());
    try self.parseLibs(libs.keys(), libs.values(), syslibroot, &dependent_libs);
    try self.parseDependentLibs(syslibroot, &dependent_libs);

    for (self.objects.items) |_, object_id| {
        try self.resolveSymbolsInObject(@intCast(u16, object_id));
    }

    try self.resolveSymbolsInArchives();
    try self.resolveDyldStubBinder();
    try self.resolveSymbolsInDylibs();
    try self.createMhExecuteHeaderSymbol();
    try self.createDsoHandleSymbol();
    try self.resolveSymbolsAtLoading();

    if (self.unresolved.count() > 0) {
        return error.UndefinedSymbolReference;
    }
    if (lib_not_found) {
        return error.LibraryNotFound;
    }
    if (framework_not_found) {
        return error.FrameworkNotFound;
    }

    try self.createPagezeroSegment();

    for (self.objects.items) |object| {
        try object.scanInputSections(self);
    }

    try self.createDyldPrivateAtom();
    try self.createTentativeDefAtoms();
    try self.createStubHelperPreambleAtom();

    for (self.objects.items) |*object, object_id| {
        try object.splitIntoAtoms(self, @intCast(u32, object_id));
    }

    try self.createDyldStubBinderGotAtom();

    if (self.options.dead_strip) {
        try dead_strip.gcAtoms(self);
    }

    try self.allocateSegments();
    try self.allocateAtoms();

    try self.allocateSpecialSymbols();

    if (build_options.enable_logging) {
        self.logSymtab();
        self.logSegments();
        self.logSections();
        self.logAtoms();
    }

    try self.writeAtoms();

    var lc_buffer = std.ArrayList(u8).init(arena);
    const lc_writer = lc_buffer.writer();
    var ncmds: u32 = 0;

    try self.writeLinkeditSegmentData(&ncmds, lc_writer);

    // If the last section of __DATA segment is zerofill section, we need to ensure
    // that the free space between the end of the last non-zerofill section of __DATA
    // segment and the beginning of __LINKEDIT segment is zerofilled as the loader will
    // copy-paste this space into memory for quicker zerofill operation.
    if (self.getSegmentByName("__DATA")) |data_seg_id| blk: {
        var physical_zerofill_start: u64 = 0;
        const section_indexes = self.getSectionIndexes(data_seg_id);
        for (self.sections.items(.header)[section_indexes.start..section_indexes.end]) |header| {
            if (header.isZerofill() and header.size > 0) break;
            physical_zerofill_start = header.offset + header.size;
        } else break :blk;
        const linkedit = self.getLinkeditSegmentPtr();
        const physical_zerofill_size = linkedit.fileoff - physical_zerofill_start;
        if (physical_zerofill_size > 0) {
            var padding = try self.base.allocator.alloc(u8, physical_zerofill_size);
            defer self.base.allocator.free(padding);
            mem.set(u8, padding, 0);
            try self.base.file.pwriteAll(padding, physical_zerofill_start);
        }
    }

    try writeDylinkerLC(&ncmds, lc_writer);
    try self.writeMainLC(&ncmds, lc_writer);
    try self.writeDylibIdLC(&ncmds, lc_writer);
    try self.writeRpathLCs(&ncmds, lc_writer);

    {
        try lc_writer.writeStruct(macho.source_version_command{
            .cmdsize = @sizeOf(macho.source_version_command),
            .version = 0x0,
        });
        ncmds += 1;
    }

    try self.writeBuildVersionLC(&ncmds, lc_writer);

    {
        var uuid_lc = macho.uuid_command{
            .cmdsize = @sizeOf(macho.uuid_command),
            .uuid = undefined,
        };
        std.crypto.random.bytes(&uuid_lc.uuid);
        try lc_writer.writeStruct(uuid_lc);
        ncmds += 1;
    }

    try self.writeLoadDylibLCs(&ncmds, lc_writer);

    const requires_codesig = blk: {
        if (self.options.entitlements) |_| break :blk true;
        if (cpu_arch == .aarch64 and (os_tag == .macos or abi == .simulator)) break :blk true;
        break :blk false;
    };
    var codesig_offset: ?u32 = null;
    var codesig: ?CodeSignature = if (requires_codesig) blk: {
        // Preallocate space for the code signature.
        // We need to do this at this stage so that we have the load commands with proper values
        // written out to the file.
        // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
        // where the code signature goes into.
        var codesig = CodeSignature.init(self.page_size);
        codesig.code_directory.ident = self.options.emit.sub_path;
        if (self.options.entitlements) |path| {
            try codesig.addEntitlements(gpa, path);
        }
        codesig_offset = try self.writeCodeSignaturePadding(&codesig, &ncmds, lc_writer);
        break :blk codesig;
    } else null;
    defer if (codesig) |*csig| csig.deinit(gpa);

    var headers_buf = std.ArrayList(u8).init(arena);
    try self.writeSegmentHeaders(&ncmds, headers_buf.writer());

    try self.base.file.pwriteAll(headers_buf.items, @sizeOf(macho.mach_header_64));
    try self.base.file.pwriteAll(lc_buffer.items, @sizeOf(macho.mach_header_64) + headers_buf.items.len);
    try self.writeHeader(ncmds, @intCast(u32, lc_buffer.items.len + headers_buf.items.len));

    if (codesig) |*csig| {
        try self.writeCodeSignature(csig, codesig_offset.?); // code signing always comes last

        if (comptime builtin.target.isDarwin()) {
            const dir = self.options.emit.directory;
            const path = self.options.emit.sub_path;
            try dir.copyFile(path, dir, path, .{});
        }
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

fn resolveSearchDirs(arena: Allocator, dirs: []const []const u8, syslibroot: ?[]const u8, out_dirs: anytype) !void {
    for (dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try out_dirs.append(search_dir);
        } else {
            log.warn("directory not found for '-L{s}'", .{dir});
        }
    }
}

fn resolveLib(
    arena: Allocator,
    search_dir: []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "lib{s}{s}", .{ name, ext });
    const full_path = try fs.path.join(arena, &[_][]const u8{ search_dir, search_name });

    // Check if the file exists.
    const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer tmp.close();

    return full_path;
}

fn resolveFramework(
    arena: Allocator,
    search_dir: []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "{s}{s}", .{ name, ext });
    const prefix_path = try std.fmt.allocPrint(arena, "{s}.framework", .{name});
    const full_path = try fs.path.join(arena, &[_][]const u8{ search_dir, prefix_path, search_name });

    // Check if the file exists.
    const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer tmp.close();

    return full_path;
}

fn parseObject(self: *MachO, path: []const u8) !bool {
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    defer file.close();

    const name = try gpa.dupe(u8, path);
    const cpu_arch = self.options.target.cpu_arch.?;
    const mtime: u64 = mtime: {
        const stat = file.stat() catch break :mtime 0;
        break :mtime @intCast(u64, @divFloor(stat.mtime, 1_000_000_000));
    };
    const file_stat = try file.stat();
    const file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;
    const contents = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);

    var object = Object{
        .name = name,
        .mtime = mtime,
        .contents = contents,
    };

    object.parse(gpa, cpu_arch) catch |err| switch (err) {
        error.EndOfStream, error.NotObject => {
            object.deinit(gpa);
            return false;
        },
        else => |e| return e,
    };

    try self.objects.append(gpa, object);

    return true;
}

fn parseArchive(self: *MachO, path: []const u8, force_load: bool) !bool {
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try gpa.dupe(u8, path);
    const cpu_arch = self.options.target.cpu_arch.?;
    const reader = file.reader();
    const fat_offset = try fat.getLibraryOffset(reader, cpu_arch);
    try reader.context.seekTo(fat_offset);

    var archive = Archive{
        .file = file,
        .fat_offset = fat_offset,
        .name = name,
    };

    archive.parse(gpa, reader) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(gpa);
            return false;
        },
        else => |e| return e,
    };

    if (force_load) {
        // Get all offsets from the ToC
        var offsets = std.AutoArrayHashMap(u32, void).init(gpa);
        defer offsets.deinit();
        for (archive.toc.values()) |offs| {
            for (offs.items) |off| {
                _ = try offsets.getOrPut(off);
            }
        }
        for (offsets.keys()) |off| {
            const object = try archive.parseObject(gpa, cpu_arch, off);
            try self.objects.append(gpa, object);
        }
    } else {
        try self.archives.append(gpa, archive);
    }

    return true;
}

const ParseDylibError = error{
    OutOfMemory,
    EmptyStubFile,
    MismatchedCpuArchitecture,
    UnsupportedCpuArchitecture,
    EndOfStream,
} || fs.File.OpenError || std.os.PReadError || Dylib.Id.ParseError;

const DylibCreateOpts = struct {
    syslibroot: ?[]const u8,
    id: ?Dylib.Id = null,
    dependent: bool = false,
    needed: bool = false,
    weak: bool = false,
};

pub fn parseDylib(
    self: *MachO,
    path: []const u8,
    dependent_libs: anytype,
    opts: DylibCreateOpts,
) ParseDylibError!bool {
    const gpa = self.base.allocator;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    defer file.close();

    const cpu_arch = self.options.target.cpu_arch.?;
    const file_stat = try file.stat();
    var file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;

    const reader = file.reader();
    const lib_offset = try fat.getLibraryOffset(reader, cpu_arch);
    try file.seekTo(lib_offset);
    file_size -= lib_offset;

    const contents = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);
    defer gpa.free(contents);

    const dylib_id = @intCast(u16, self.dylibs.items.len);
    var dylib = Dylib{ .weak = opts.weak };

    dylib.parseFromBinary(
        gpa,
        cpu_arch,
        dylib_id,
        dependent_libs,
        path,
        contents,
    ) catch |err| switch (err) {
        error.EndOfStream, error.NotDylib => {
            try file.seekTo(0);

            var lib_stub = LibStub.loadFromFile(gpa, file) catch {
                dylib.deinit(gpa);
                return false;
            };
            defer lib_stub.deinit();

            try dylib.parseFromStub(
                gpa,
                self.options.target,
                lib_stub,
                dylib_id,
                dependent_libs,
                path,
            );
        },
        else => |e| return e,
    };

    if (opts.id) |id| {
        if (dylib.id.?.current_version < id.compatibility_version) {
            log.warn("found dylib is incompatible with the required minimum version", .{});
            log.warn("  dylib: {s}", .{id.name});
            log.warn("  required minimum version: {}", .{id.compatibility_version});
            log.warn("  dylib version: {}", .{dylib.id.?.current_version});

            // TODO maybe this should be an error and facilitate auto-cleanup?
            dylib.deinit(gpa);
            return false;
        }
    }

    const gop = try self.dylibs_map.getOrPut(gpa, dylib.id.?.name);
    if (gop.found_existing) {
        dylib.deinit(gpa);
        return true;
    }
    gop.value_ptr.* = dylib_id;
    try self.dylibs.append(gpa, dylib);

    const should_link_dylib_even_if_unreachable = blk: {
        if (self.options.dead_strip_dylibs and !opts.needed) break :blk false;
        break :blk !(opts.dependent or self.referenced_dylibs.contains(dylib_id));
    };

    if (should_link_dylib_even_if_unreachable) {
        try self.referenced_dylibs.putNoClobber(gpa, dylib_id, {});
    }

    return true;
}

fn parsePositionals(self: *MachO, files: []const []const u8, syslibroot: ?[]const u8, dependent_libs: anytype) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            break :full_path try std.fs.realpath(file_name, &buffer);
        };
        log.debug("parsing input file path '{s}'", .{full_path});

        if (try self.parseObject(full_path)) continue;
        if (try self.parseArchive(full_path, false)) continue;
        if (try self.parseDylib(full_path, dependent_libs, .{
            .syslibroot = syslibroot,
        })) continue;

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseAndForceLoadStaticArchives(self: *MachO, files: []const []const u8) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            break :full_path try fs.realpath(file_name, &buffer);
        };
        log.debug("parsing and force loading static archive '{s}'", .{full_path});

        if (try self.parseArchive(full_path, true)) continue;
        log.debug("unknown filetype: expected static archive: '{s}'", .{file_name});
    }
}

fn parseLibs(
    self: *MachO,
    lib_names: []const []const u8,
    lib_infos: []const Zld.SystemLib,
    syslibroot: ?[]const u8,
    dependent_libs: anytype,
) !void {
    for (lib_names) |lib, i| {
        const lib_info = lib_infos[i];
        log.debug("parsing lib path '{s}'", .{lib});
        if (try self.parseDylib(lib, dependent_libs, .{
            .syslibroot = syslibroot,
            .needed = lib_info.needed,
            .weak = lib_info.weak,
        })) continue;
        if (try self.parseArchive(lib, false)) continue;

        log.warn("unknown filetype for a library: '{s}'", .{lib});
    }
}

fn parseDependentLibs(self: *MachO, syslibroot: ?[]const u8, dependent_libs: anytype) !void {
    // At this point, we can now parse dependents of dylibs preserving the inclusion order of:
    // 1) anything on the linker line is parsed first
    // 2) afterwards, we parse dependents of the included dylibs
    // TODO this should not be performed if the user specifies `-flat_namespace` flag.
    // See ld64 manpages.
    var arena_alloc = std.heap.ArenaAllocator.init(self.base.allocator);
    const arena = arena_alloc.allocator();
    defer arena_alloc.deinit();

    while (dependent_libs.readItem()) |dep_id| {
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

            log.debug("trying dependency at fully resolved path {s}", .{full_path});

            const did_parse_successfully = try self.parseDylib(full_path, dependent_libs, .{
                .id = dep_id.id,
                .syslibroot = syslibroot,
                .dependent = true,
                .weak = weak,
            });
            if (did_parse_successfully) break;
        } else {
            log.warn("unable to resolve dependency {s}", .{dep_id.id.name});
        }
    }
}

pub fn getOutputSection(self: *MachO, sect: macho.section_64) !?u8 {
    const segname = sect.segName();
    const sectname = sect.sectName();
    const res: ?u8 = blk: {
        if (mem.eql(u8, "__LLVM", segname)) {
            log.debug("TODO LLVM section: type 0x{x}, name '{s},{s}'", .{
                sect.flags, segname, sectname,
            });
            break :blk null;
        }

        if (sect.isCode()) {
            break :blk self.getSectionByName("__TEXT", "__text") orelse try self.initSection(
                "__TEXT",
                "__text",
                .{
                    .flags = macho.S_REGULAR |
                        macho.S_ATTR_PURE_INSTRUCTIONS |
                        macho.S_ATTR_SOME_INSTRUCTIONS,
                },
            );
        }

        if (sect.isDebug()) {
            // TODO debug attributes
            if (mem.eql(u8, "__LD", segname) and mem.eql(u8, "__compact_unwind", sectname)) {
                log.debug("TODO compact unwind section: type 0x{x}, name '{s},{s}'", .{
                    sect.flags, segname, sectname,
                });
            }
            break :blk null;
        }

        switch (sect.@"type"()) {
            macho.S_4BYTE_LITERALS,
            macho.S_8BYTE_LITERALS,
            macho.S_16BYTE_LITERALS,
            => {
                break :blk self.getSectionByName("__TEXT", "__const") orelse try self.initSection(
                    "__TEXT",
                    "__const",
                    .{},
                );
            },
            macho.S_CSTRING_LITERALS => {
                if (mem.startsWith(u8, sectname, "__objc")) {
                    break :blk self.getSectionByName(segname, sectname) orelse try self.initSection(
                        segname,
                        sectname,
                        .{},
                    );
                }
                break :blk self.getSectionByName("__TEXT", "__cstring") orelse try self.initSection(
                    "__TEXT",
                    "__cstring",
                    .{ .flags = macho.S_CSTRING_LITERALS },
                );
            },
            macho.S_MOD_INIT_FUNC_POINTERS,
            macho.S_MOD_TERM_FUNC_POINTERS,
            => {
                break :blk self.getSectionByName("__DATA_CONST", sectname) orelse try self.initSection(
                    "__DATA_CONST",
                    sectname,
                    .{ .flags = sect.flags },
                );
            },
            macho.S_LITERAL_POINTERS,
            macho.S_ZEROFILL,
            macho.S_THREAD_LOCAL_VARIABLES,
            macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
            macho.S_THREAD_LOCAL_REGULAR,
            macho.S_THREAD_LOCAL_ZEROFILL,
            => {
                break :blk self.getSectionByName(segname, sectname) orelse try self.initSection(
                    segname,
                    sectname,
                    .{ .flags = sect.flags },
                );
            },
            macho.S_COALESCED => {
                break :blk self.getSectionByName(segname, sectname) orelse try self.initSection(
                    segname,
                    sectname,
                    .{},
                );
            },
            macho.S_REGULAR => {
                if (mem.eql(u8, segname, "__TEXT")) {
                    if (mem.eql(u8, sectname, "__rodata") or
                        mem.eql(u8, sectname, "__typelink") or
                        mem.eql(u8, sectname, "__itablink") or
                        mem.eql(u8, sectname, "__gosymtab") or
                        mem.eql(u8, sectname, "__gopclntab"))
                    {
                        break :blk self.getSectionByName("__DATA_CONST", "__const") orelse try self.initSection(
                            "__DATA_CONST",
                            "__const",
                            .{},
                        );
                    }
                }
                if (mem.eql(u8, segname, "__DATA")) {
                    if (mem.eql(u8, sectname, "__const") or
                        mem.eql(u8, sectname, "__cfstring") or
                        mem.eql(u8, sectname, "__objc_classlist") or
                        mem.eql(u8, sectname, "__objc_imageinfo"))
                    {
                        break :blk self.getSectionByName("__DATA_CONST", sectname) orelse
                            try self.initSection(
                            "__DATA_CONST",
                            sectname,
                            .{},
                        );
                    } else if (mem.eql(u8, sectname, "__data")) {
                        break :blk self.getSectionByName("__DATA", "__data") orelse
                            try self.initSection(
                            "__DATA",
                            "__data",
                            .{},
                        );
                    }
                }
                break :blk self.getSectionByName(segname, sectname) orelse try self.initSection(
                    segname,
                    sectname,
                    .{},
                );
            },
            else => break :blk null,
        }
    };
    return res;
}

fn allocateAtom(self: *MachO, atom_index: AtomIndex, sect_id: u8) !void {
    const atom = self.getAtom(atom_index);
    const sym = self.getSymbolPtr(atom.getSymbolWithLoc());
    try self.addAtomToSection(atom_index, sect_id);
    sym.n_sect = sect_id + 1;
}

pub fn addAtomToSection(self: *MachO, atom_index: AtomIndex, sect_id: u8) !void {
    var section = self.sections.get(sect_id);
    if (section.header.size > 0) {
        const atom = self.getAtomPtr(atom_index);
        const last_atom = self.getAtomPtr(section.last_atom_index);
        last_atom.next_index = atom_index;
        atom.prev_index = section.last_atom_index;
    } else {
        section.first_atom_index = atom_index;
    }
    section.last_atom_index = atom_index;
    const atom = self.getAtom(atom_index);
    const atom_alignment = try math.powi(u32, 2, atom.alignment);
    const aligned_end_addr = mem.alignForwardGeneric(u64, section.header.size, atom_alignment);
    const padding = aligned_end_addr - section.header.size;
    section.header.size += padding + atom.size;
    section.header.@"align" = @maximum(section.header.@"align", atom.alignment);
    self.sections.set(sect_id, section);
}

pub fn createEmptyAtom(self: *MachO, sym_index: u32, size: u64, alignment: u32) !AtomIndex {
    const gpa = self.base.allocator;
    const index = @intCast(AtomIndex, self.atoms.items.len);
    const atom = try self.atoms.addOne(gpa);
    atom.* = Atom.empty;
    atom.sym_index = sym_index;
    atom.size = size;
    atom.alignment = alignment;

    log.debug("creating ATOM(%{d}) at index {d}", .{ sym_index, index });

    return index;
}

pub fn createGotAtom(self: *MachO) !AtomIndex {
    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;

    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);

    const sect_id = self.getSectionByName("__DATA_CONST", "__got") orelse
        try self.initSection("__DATA_CONST", "__got", .{
        .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
    });
    try self.allocateAtom(atom_index, sect_id);

    return atom_index;
}

fn writeGotPointer(self: *MachO, got_index: u32, writer: anytype) !void {
    const target_addr = blk: {
        const sym_loc = self.got_entries.keys()[got_index];
        const sym = self.getSymbol(sym_loc);
        break :blk sym.n_value;
    };
    try writer.writeIntLittle(u64, target_addr);
}

pub fn createTlvPtrAtom(self: *MachO) !AtomIndex {
    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;

    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);

    const match = (try self.getOutputSection(.{
        .segname = makeStaticString("__DATA"),
        .sectname = makeStaticString("__thread_ptrs"),
        .flags = macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
    })).?;
    try self.allocateAtom(atom_index, match);

    return atom_index;
}

fn createDyldStubBinderGotAtom(self: *MachO) !void {
    const sym_index = self.dyld_stub_binder_index orelse return;

    const gpa = self.base.allocator;

    const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    const got_atom_index = try self.createGotAtom();
    const got_atom = self.getAtom(got_atom_index);
    try self.got_entries.putNoClobber(gpa, sym_loc, got_atom.sym_index);
}

fn createDyldPrivateAtom(self: *MachO) !void {
    if (self.dyld_stub_binder_index == null) return;

    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;
    self.dyld_private_sym_index = sym_index;

    const sect_id = self.getSectionByName("__DATA", "__data") orelse try self.initSection("__DATA", "__data", .{});
    try self.allocateAtom(atom_index, sect_id);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);
}

fn createStubHelperPreambleAtom(self: *MachO) !void {
    if (self.dyld_stub_binder_index == null) return;

    const gpa = self.base.allocator;
    const cpu_arch = self.options.target.cpu_arch.?;
    const size: u64 = switch (cpu_arch) {
        .x86_64 => 15,
        .aarch64 => 6 * @sizeOf(u32),
        else => unreachable,
    };
    const alignment: u32 = switch (cpu_arch) {
        .x86_64 => 0,
        .aarch64 => 2,
        else => unreachable,
    };
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, size, alignment);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;
    self.stub_helper_preamble_sym_index = sym_index;

    const sect_id = self.getSectionByName("__TEXT", "__stub_helper") orelse
        try self.initSection("__TEXT", "__stub_helper", .{
        .flags = macho.S_REGULAR |
            macho.S_ATTR_PURE_INSTRUCTIONS |
            macho.S_ATTR_SOME_INSTRUCTIONS,
    });
    try self.allocateAtom(atom_index, sect_id);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);
}

fn writeStubHelperPreambleCode(self: *MachO, writer: anytype) !void {
    const cpu_arch = self.options.target.cpu_arch.?;
    const source_addr = blk: {
        const sym = self.getSymbol(.{ .sym_index = self.stub_helper_preamble_sym_index.?, .file = null });
        break :blk sym.n_value;
    };
    const dyld_private_addr = blk: {
        const sym = self.getSymbol(.{ .sym_index = self.dyld_private_sym_index.?, .file = null });
        break :blk sym.n_value;
    };
    const dyld_stub_binder_got_addr = blk: {
        const got_entry = self.got_entries.get(.{ .sym_index = self.dyld_stub_binder_index.?, .file = null }).?;
        const sym = self.getSymbol(.{ .sym_index = got_entry, .file = null });
        break :blk sym.n_value;
    };
    switch (cpu_arch) {
        .x86_64 => {
            try writer.writeAll(&.{ 0x4c, 0x8d, 0x1d });
            {
                const disp = try Atom.calcPcRelativeDisplacementX86(source_addr + 3, dyld_private_addr, 0);
                try writer.writeIntLittle(i32, disp);
            }
            try writer.writeAll(&.{ 0x41, 0x53, 0xff, 0x25 });
            {
                const disp = try Atom.calcPcRelativeDisplacementX86(source_addr + 11, dyld_stub_binder_got_addr, 0);
                try writer.writeIntLittle(i32, disp);
            }
        },
        .aarch64 => {
            {
                const pages = Atom.calcNumberOfPages(source_addr, dyld_private_addr);
                try writer.writeIntLittle(u32, aarch64.Instruction.adrp(.x17, pages).toU32());
            }
            {
                const off = try Atom.calcPageOffset(dyld_private_addr, .arithmetic);
                try writer.writeIntLittle(u32, aarch64.Instruction.add(.x17, .x17, off, false).toU32());
            }
            try writer.writeIntLittle(u32, aarch64.Instruction.stp(
                .x16,
                .x17,
                aarch64.Register.sp,
                aarch64.Instruction.LoadStorePairOffset.pre_index(-16),
            ).toU32());
            {
                const pages = Atom.calcNumberOfPages(source_addr + 12, dyld_stub_binder_got_addr);
                try writer.writeIntLittle(u32, aarch64.Instruction.adrp(.x16, pages).toU32());
            }
            {
                const off = try Atom.calcPageOffset(dyld_stub_binder_got_addr, .load_store_64);
                try writer.writeIntLittle(u32, aarch64.Instruction.ldr(
                    .x16,
                    .x16,
                    aarch64.Instruction.LoadStoreOffset.imm(off),
                ).toU32());
            }
            try writer.writeIntLittle(u32, aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }
}

pub fn createStubHelperAtom(self: *MachO) !AtomIndex {
    const gpa = self.base.allocator;
    const cpu_arch = self.options.target.cpu_arch.?;
    const stub_size: u4 = switch (cpu_arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const alignment: u2 = switch (cpu_arch) {
        .x86_64 => 0,
        .aarch64 => 2,
        else => unreachable,
    };

    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, stub_size, alignment);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_sect = macho.N_SECT;

    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);
    try self.allocateAtom(atom_index, self.getSectionByName("__TEXT", "__stub_helper").?);

    return atom_index;
}

fn writeStubHelperCode(self: *MachO, atom_index: AtomIndex, writer: anytype) !void {
    const cpu_arch = self.options.target.cpu_arch.?;
    const source_addr = blk: {
        const atom = self.getAtom(atom_index);
        const sym = self.getSymbol(atom.getSymbolWithLoc());
        break :blk sym.n_value;
    };
    const target_addr = blk: {
        const sym = self.getSymbol(.{ .sym_index = self.stub_helper_preamble_sym_index.?, .file = null });
        break :blk sym.n_value;
    };
    switch (cpu_arch) {
        .x86_64 => {
            try writer.writeAll(&.{ 0x68, 0x0, 0x0, 0x0, 0x0, 0xe9 });
            {
                const disp = try Atom.calcPcRelativeDisplacementX86(source_addr + 6, target_addr, 0);
                try writer.writeIntLittle(i32, disp);
            }
        },
        .aarch64 => {
            const stub_size: u4 = 3 * @sizeOf(u32);
            const literal = blk: {
                const div_res = try math.divExact(u64, stub_size - @sizeOf(u32), 4);
                break :blk math.cast(u18, div_res) orelse return error.Overflow;
            };
            try writer.writeIntLittle(u32, aarch64.Instruction.ldrLiteral(
                .w16,
                literal,
            ).toU32());
            {
                const disp = try Atom.calcPcRelativeDisplacementArm64(source_addr + 4, target_addr);
                try writer.writeIntLittle(u32, aarch64.Instruction.b(disp).toU32());
            }
            try writer.writeAll(&.{ 0x0, 0x0, 0x0, 0x0 });
        },
        else => unreachable,
    }
}

pub fn createLazyPointerAtom(self: *MachO) !AtomIndex {
    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;

    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);

    const sect_id = self.getSectionByName("__DATA", "__la_symbol_ptr") orelse
        try self.initSection("__DATA", "__la_symbol_ptr", .{
        .flags = macho.S_LAZY_SYMBOL_POINTERS,
    });
    try self.allocateAtom(atom_index, sect_id);

    return atom_index;
}

fn writeLazyPointer(self: *MachO, stub_index: u32, writer: anytype) !void {
    const target_addr = blk: {
        const sym_index = self.stubs.values()[stub_index];
        const sym = self.getSymbol(.{ .sym_index = sym_index, .file = null });
        break :blk sym.n_value;
    };
    try writer.writeIntLittle(u64, target_addr);
}

pub fn createStubAtom(self: *MachO) !AtomIndex {
    const gpa = self.base.allocator;
    const cpu_arch = self.options.target.cpu_arch.?;
    const alignment: u2 = switch (cpu_arch) {
        .x86_64 => 0,
        .aarch64 => 2,
        else => unreachable, // unhandled architecture type
    };
    const stub_size: u4 = switch (cpu_arch) {
        .x86_64 => 6,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable, // unhandled architecture type
    };
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, stub_size, alignment);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;

    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);

    const sect_id = self.getSectionByName("__TEXT", "__stubs") orelse
        try self.initSection("__TEXT", "__stubs", .{
        .flags = macho.S_SYMBOL_STUBS |
            macho.S_ATTR_PURE_INSTRUCTIONS |
            macho.S_ATTR_SOME_INSTRUCTIONS,
        .reserved2 = stub_size,
    });
    try self.allocateAtom(atom_index, sect_id);

    return atom_index;
}

fn writeStubCode(self: *MachO, atom_index: AtomIndex, stub_index: u32, writer: anytype) !void {
    const cpu_arch = self.options.target.cpu_arch.?;
    const source_addr = blk: {
        const atom = self.getAtom(atom_index);
        const sym = self.getSymbol(atom.getSymbolWithLoc());
        break :blk sym.n_value;
    };
    const target_addr = blk: {
        // TODO: cache this at stub atom creation; they always go in pairs anyhow
        const la_sect_id = self.getSectionByName("__DATA", "__la_symbol_ptr").?;
        var la_atom_index = self.sections.items(.first_atom_index)[la_sect_id];
        var count: u32 = 0;
        while (count < stub_index) : (count += 1) {
            const la_atom = self.getAtom(la_atom_index);
            la_atom_index = la_atom.next_index.?;
        }
        const atom = self.getAtom(la_atom_index);
        const sym = self.getSymbol(atom.getSymbolWithLoc());
        break :blk sym.n_value;
    };
    switch (cpu_arch) {
        .x86_64 => {
            try writer.writeAll(&.{ 0xff, 0x25 });
            {
                const disp = try Atom.calcPcRelativeDisplacementX86(source_addr + 2, target_addr, 0);
                try writer.writeIntLittle(i32, disp);
            }
        },
        .aarch64 => {
            {
                const pages = Atom.calcNumberOfPages(source_addr, target_addr);
                try writer.writeIntLittle(u32, aarch64.Instruction.adrp(.x16, pages).toU32());
            }
            {
                const off = try Atom.calcPageOffset(target_addr, .load_store_64);
                try writer.writeIntLittle(u32, aarch64.Instruction.ldr(
                    .x16,
                    .x16,
                    aarch64.Instruction.LoadStoreOffset.imm(off),
                ).toU32());
            }
            try writer.writeIntLittle(u32, aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }
}

fn createTentativeDefAtoms(self: *MachO) !void {
    const gpa = self.base.allocator;

    for (self.globals.values()) |global| {
        const sym = self.getSymbolPtr(global);
        if (!sym.tentative()) continue;

        log.debug("creating tentative definition for ATOM(%{d}, '{s}') in object({?})", .{
            global.sym_index, self.getSymbolName(global), global.file,
        });

        // Convert any tentative definition into a regular symbol and allocate
        // text blocks for each tentative definition.
        const size = sym.n_value;
        const alignment = (sym.n_desc >> 8) & 0x0f;
        const n_sect = (try self.getOutputSection(.{
            .segname = makeStaticString("__DATA"),
            .sectname = makeStaticString("__bss"),
            .flags = macho.S_ZEROFILL,
        })).?;

        sym.* = .{
            .n_strx = sym.n_strx,
            .n_type = macho.N_SECT | macho.N_EXT,
            .n_sect = n_sect,
            .n_desc = 0,
            .n_value = 0,
        };

        const atom_index = try self.createEmptyAtom(global.sym_index, size, alignment);
        const atom = self.getAtomPtr(atom_index);
        atom.file = global.file;

        try self.allocateAtom(atom_index, n_sect);

        if (global.file) |file| {
            const object = &self.objects.items[file];
            try object.atoms.append(gpa, atom_index);
            try object.atom_by_index_table.putNoClobber(gpa, global.sym_index, atom_index);
        } else {
            try self.atom_by_index_table.putNoClobber(gpa, global.sym_index, atom_index);
        }
    }
}

fn resolveSymbolsInObject(self: *MachO, object_id: u16) !void {
    const object = &self.objects.items[object_id];
    log.debug("resolving symbols in '{s}'", .{object.name});

    for (object.symtab.items) |sym, index| {
        const sym_index = @intCast(u32, index);
        const sym_name = object.getString(sym.n_strx);

        if (sym.stab()) {
            log.err("unhandled symbol type: stab", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name});
            return error.UnhandledSymbolType;
        }

        if (sym.indr()) {
            log.err("unhandled symbol type: indirect", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name});
            return error.UnhandledSymbolType;
        }

        if (sym.abs()) {
            log.err("unhandled symbol type: absolute", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name});
            return error.UnhandledSymbolType;
        }

        if (sym.sect() and !sym.ext()) {
            log.debug("symbol '{s}' local to object {s}; skipping...", .{
                sym_name,
                object.name,
            });
            continue;
        }

        const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = object_id };

        const gpa = self.base.allocator;
        const name = try gpa.dupe(u8, sym_name);
        const global_index = @intCast(u32, self.globals.values().len);
        const gop = try self.globals.getOrPut(gpa, name);
        defer if (gop.found_existing) gpa.free(name);

        if (!gop.found_existing) {
            gop.value_ptr.* = sym_loc;
            if (sym.undf() and !sym.tentative()) {
                try self.unresolved.putNoClobber(gpa, global_index, {});
            }
            continue;
        }

        const global = gop.value_ptr.*;
        const global_sym = self.getSymbol(global);

        // Cases to consider: sym vs global_sym
        // 1.  strong(sym) and strong(global_sym) => error
        // 2.  strong(sym) and weak(global_sym) => sym
        // 3.  strong(sym) and tentative(global_sym) => sym
        // 4.  strong(sym) and undf(global_sym) => sym
        // 5.  weak(sym) and strong(global_sym) => global_sym
        // 6.  weak(sym) and tentative(global_sym) => sym
        // 7.  weak(sym) and undf(global_sym) => sym
        // 8.  tentative(sym) and strong(global_sym) => global_sym
        // 9.  tentative(sym) and weak(global_sym) => global_sym
        // 10. tentative(sym) and tentative(global_sym) => pick larger
        // 11. tentative(sym) and undf(global_sym) => sym
        // 12. undf(sym) and * => global_sym
        //
        // Reduces to:
        // 1. strong(sym) and strong(global_sym) => error
        // 2. * and strong(global_sym) => global_sym
        // 3. weak(sym) and weak(global_sym) => global_sym
        // 4. tentative(sym) and tentative(global_sym) => pick larger
        // 5. undf(sym) and * => global_sym
        // 6. else => sym

        const sym_is_strong = sym.sect() and !(sym.weakDef() or sym.pext());
        const global_is_strong = global_sym.sect() and !(global_sym.weakDef() or global_sym.pext());
        const sym_is_weak = sym.sect() and (sym.weakDef() or sym.pext());
        const global_is_weak = global_sym.sect() and (global_sym.weakDef() or global_sym.pext());

        if (sym_is_strong and global_is_strong) {
            log.err("symbol '{s}' defined multiple times", .{sym_name});
            if (global.file) |file| {
                log.err("  first definition in '{s}'", .{self.objects.items[file].name});
            }
            log.err("  next definition in '{s}'", .{self.objects.items[object_id].name});
            return error.MultipleSymbolDefinitions;
        }
        if (global_is_strong) continue;
        if (sym_is_weak and global_is_weak) continue;
        if (sym.tentative() and global_sym.tentative()) {
            if (global_sym.n_value >= sym.n_value) continue;
        }
        if (sym.undf() and !sym.tentative()) continue;

        _ = self.unresolved.swapRemove(@intCast(u32, self.globals.getIndex(name).?));

        gop.value_ptr.* = sym_loc;
    }
}

fn resolveSymbolsInArchives(self: *MachO) !void {
    if (self.archives.items.len == 0) return;

    const gpa = self.base.allocator;
    const cpu_arch = self.options.target.cpu_arch.?;
    var next_sym: usize = 0;
    loop: while (next_sym < self.unresolved.count()) {
        const global = self.globals.values()[self.unresolved.keys()[next_sym]];
        const sym_name = self.getSymbolName(global);

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(sym_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @intCast(u16, self.objects.items.len);
            const object = try archive.parseObject(gpa, cpu_arch, offsets.items[0]);
            try self.objects.append(gpa, object);
            try self.resolveSymbolsInObject(object_id);

            continue :loop;
        }

        next_sym += 1;
    }
}

fn resolveSymbolsInDylibs(self: *MachO) !void {
    if (self.dylibs.items.len == 0) return;

    var next_sym: usize = 0;
    loop: while (next_sym < self.unresolved.count()) {
        const global_index = self.unresolved.keys()[next_sym];
        const global = self.globals.values()[global_index];
        const sym = self.getSymbolPtr(global);
        const sym_name = self.getSymbolName(global);

        for (self.dylibs.items) |dylib, id| {
            if (!dylib.symbols.contains(sym_name)) continue;

            const dylib_id = @intCast(u16, id);
            if (!self.referenced_dylibs.contains(dylib_id)) {
                try self.referenced_dylibs.putNoClobber(self.base.allocator, dylib_id, {});
            }

            const ordinal = self.referenced_dylibs.getIndex(dylib_id) orelse unreachable;
            sym.n_type |= macho.N_EXT;
            sym.n_desc = @intCast(u16, ordinal + 1) * macho.N_SYMBOL_RESOLVER;

            if (dylib.weak) {
                sym.n_desc |= macho.N_WEAK_REF;
            }

            assert(self.unresolved.swapRemove(global_index));
            continue :loop;
        }

        next_sym += 1;
    }
}

fn resolveSymbolsAtLoading(self: *MachO) !void {
    var next_sym: usize = 0;
    while (next_sym < self.unresolved.count()) {
        const global_index = self.unresolved.keys()[next_sym];
        const global = self.globals.values()[global_index];
        const sym = self.getSymbolPtr(global);
        const sym_name = self.getSymbolName(global);

        if (sym.discarded()) {
            sym.* = .{
                .n_strx = 0,
                .n_type = macho.N_UNDF,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            _ = self.unresolved.swapRemove(global_index);
            continue;
        } else if (self.options.allow_undef) {
            const n_desc = @bitCast(
                u16,
                macho.BIND_SPECIAL_DYLIB_FLAT_LOOKUP * @intCast(i16, macho.N_SYMBOL_RESOLVER),
            );
            sym.n_type = macho.N_EXT;
            sym.n_desc = n_desc;
            _ = self.unresolved.swapRemove(global_index);
            continue;
        }

        log.err("undefined reference to symbol '{s}'", .{sym_name});
        if (global.file) |file| {
            log.err("  first referenced in '{s}'", .{self.objects.items[file].name});
        }

        next_sym += 1;
    }
}

fn createMhExecuteHeaderSymbol(self: *MachO) !void {
    if (self.options.output_mode != .exe) return;
    if (self.globals.get("__mh_execute_header")) |global| {
        const sym = self.getSymbol(global);
        if (!sym.undf() and !(sym.pext() or sym.weakDef())) return;
    }

    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(gpa, "__mh_execute_header");
    sym.n_type = macho.N_SECT | macho.N_EXT;
    sym.n_desc = macho.REFERENCED_DYNAMICALLY;

    const name = try gpa.dupe(u8, "__mh_execute_header");
    const gop = try self.globals.getOrPut(gpa, name);
    defer if (gop.found_existing) gpa.free(name);
    gop.value_ptr.* = sym_loc;
}

fn createDsoHandleSymbol(self: *MachO) !void {
    const global = self.globals.getPtr("___dso_handle") orelse return;
    if (!self.getSymbol(global.*).undf()) return;

    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(gpa, "___dso_handle");
    sym.n_type = macho.N_SECT | macho.N_EXT;
    sym.n_desc = macho.N_WEAK_DEF;
    global.* = sym_loc;
    _ = self.unresolved.swapRemove(@intCast(u32, self.globals.getIndex("___dso_handle").?));
}

fn resolveDyldStubBinder(self: *MachO) !void {
    if (self.dyld_stub_binder_index != null) return;
    if (self.unresolved.count() == 0) return; // no need for a stub binder if we don't have any imports

    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(gpa, "dyld_stub_binder");
    sym.n_type = macho.N_UNDF;

    const sym_name = try gpa.dupe(u8, "dyld_stub_binder");
    const global = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    try self.globals.putNoClobber(gpa, sym_name, global);

    for (self.dylibs.items) |dylib, id| {
        if (!dylib.symbols.contains(sym_name)) continue;

        const dylib_id = @intCast(u16, id);
        if (!self.referenced_dylibs.contains(dylib_id)) {
            try self.referenced_dylibs.putNoClobber(self.base.allocator, dylib_id, {});
        }

        const ordinal = self.referenced_dylibs.getIndex(dylib_id) orelse unreachable;
        sym.n_type |= macho.N_EXT;
        sym.n_desc = @intCast(u16, ordinal + 1) * macho.N_SYMBOL_RESOLVER;
        self.dyld_stub_binder_index = sym_index;

        break;
    }

    if (self.dyld_stub_binder_index == null) {
        log.err("undefined reference to symbol '{s}'", .{sym_name});
        return error.UndefinedSymbolReference;
    }
}

fn writeDylinkerLC(ncmds: *u32, lc_writer: anytype) !void {
    const name_len = mem.sliceTo(default_dyld_path, 0).len;
    const cmdsize = @intCast(u32, mem.alignForwardGeneric(
        u64,
        @sizeOf(macho.dylinker_command) + name_len,
        @sizeOf(u64),
    ));
    try lc_writer.writeStruct(macho.dylinker_command{
        .cmd = .LOAD_DYLINKER,
        .cmdsize = cmdsize,
        .name = @sizeOf(macho.dylinker_command),
    });
    try lc_writer.writeAll(mem.sliceTo(default_dyld_path, 0));
    const padding = cmdsize - @sizeOf(macho.dylinker_command) - name_len;
    if (padding > 0) {
        try lc_writer.writeByteNTimes(0, padding);
    }
    ncmds.* += 1;
}

fn writeMainLC(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    if (self.options.output_mode != .exe) return;
    const seg_id = self.getSegmentByName("__TEXT").?;
    const seg = self.segments.items[seg_id];
    const global = try self.getEntryPoint();
    const sym = self.getSymbol(global);
    try lc_writer.writeStruct(macho.entry_point_command{
        .cmd = .MAIN,
        .cmdsize = @sizeOf(macho.entry_point_command),
        .entryoff = @intCast(u32, sym.n_value - seg.vmaddr),
        .stacksize = self.options.stack_size orelse 0,
    });
    ncmds.* += 1;
}

const WriteDylibLCCtx = struct {
    cmd: macho.LC,
    name: []const u8,
    timestamp: u32 = 2,
    current_version: u32 = 0x10000,
    compatibility_version: u32 = 0x10000,
};

fn writeDylibLC(ctx: WriteDylibLCCtx, ncmds: *u32, lc_writer: anytype) !void {
    const name_len = ctx.name.len + 1;
    const cmdsize = @intCast(u32, mem.alignForwardGeneric(
        u64,
        @sizeOf(macho.dylib_command) + name_len,
        @sizeOf(u64),
    ));
    try lc_writer.writeStruct(macho.dylib_command{
        .cmd = ctx.cmd,
        .cmdsize = cmdsize,
        .dylib = .{
            .name = @sizeOf(macho.dylib_command),
            .timestamp = ctx.timestamp,
            .current_version = ctx.current_version,
            .compatibility_version = ctx.compatibility_version,
        },
    });
    try lc_writer.writeAll(ctx.name);
    try lc_writer.writeByte(0);
    const padding = cmdsize - @sizeOf(macho.dylib_command) - name_len;
    if (padding > 0) {
        try lc_writer.writeByteNTimes(0, padding);
    }
    ncmds.* += 1;
}

fn writeDylibIdLC(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    if (self.options.output_mode != .lib) return;
    const install_name = self.options.install_name orelse self.options.emit.sub_path;
    const curr = self.options.current_version orelse std.builtin.Version{
        .major = 1,
        .minor = 0,
        .patch = 0,
    };
    const compat = self.options.compatibility_version orelse std.builtin.Version{
        .major = 1,
        .minor = 0,
        .patch = 0,
    };
    try writeDylibLC(.{
        .cmd = .ID_DYLIB,
        .name = install_name,
        .current_version = curr.major << 16 | curr.minor << 8 | curr.patch,
        .compatibility_version = compat.major << 16 | compat.minor << 8 | compat.patch,
    }, ncmds, lc_writer);
}

const RpathIterator = struct {
    buffer: []const []const u8,
    table: std.StringHashMap(void),
    count: usize = 0,

    fn init(gpa: Allocator, rpaths: []const []const u8) RpathIterator {
        return .{ .buffer = rpaths, .table = std.StringHashMap(void).init(gpa) };
    }

    fn deinit(it: *RpathIterator) void {
        it.table.deinit();
    }

    fn next(it: *RpathIterator) !?[]const u8 {
        while (true) {
            if (it.count >= it.buffer.len) return null;
            const rpath = it.buffer[it.count];
            it.count += 1;
            const gop = try it.table.getOrPut(rpath);
            if (gop.found_existing) continue;
            return rpath;
        }
    }
};

fn writeRpathLCs(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    const gpa = self.base.allocator;

    var it = RpathIterator.init(gpa, self.options.rpath_list);
    defer it.deinit();

    while (try it.next()) |rpath| {
        const rpath_len = rpath.len + 1;
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.rpath_command) + rpath_len,
            @sizeOf(u64),
        ));
        try lc_writer.writeStruct(macho.rpath_command{
            .cmdsize = cmdsize,
            .path = @sizeOf(macho.rpath_command),
        });
        try lc_writer.writeAll(rpath);
        try lc_writer.writeByte(0);
        const padding = cmdsize - @sizeOf(macho.rpath_command) - rpath_len;
        if (padding > 0) {
            try lc_writer.writeByteNTimes(0, padding);
        }
        ncmds.* += 1;
    }
}

fn writeBuildVersionLC(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    const cmdsize = @sizeOf(macho.build_version_command) + @sizeOf(macho.build_tool_version);
    const platform_version = blk: {
        const ver = self.options.platform_version;
        const platform_version = ver.major << 16 | ver.minor << 8;
        break :blk platform_version;
    };
    const sdk_version = blk: {
        const ver = self.options.sdk_version;
        const sdk_version = ver.major << 16 | ver.minor << 8;
        break :blk sdk_version;
    };
    const is_simulator_abi = self.options.target.abi.? == .simulator;
    try lc_writer.writeStruct(macho.build_version_command{
        .cmdsize = cmdsize,
        .platform = switch (self.options.target.os_tag.?) {
            .macos => .MACOS,
            .ios => if (is_simulator_abi) macho.PLATFORM.IOSSIMULATOR else macho.PLATFORM.IOS,
            .watchos => if (is_simulator_abi) macho.PLATFORM.WATCHOSSIMULATOR else macho.PLATFORM.WATCHOS,
            .tvos => if (is_simulator_abi) macho.PLATFORM.TVOSSIMULATOR else macho.PLATFORM.TVOS,
            else => unreachable,
        },
        .minos = platform_version,
        .sdk = sdk_version,
        .ntools = 1,
    });
    try lc_writer.writeAll(mem.asBytes(&macho.build_tool_version{
        .tool = .LD,
        .version = 0x0,
    }));
    ncmds.* += 1;
}

fn writeLoadDylibLCs(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    for (self.referenced_dylibs.keys()) |id| {
        const dylib = self.dylibs.items[id];
        const dylib_id = dylib.id orelse unreachable;
        try writeDylibLC(.{
            .cmd = if (dylib.weak) .LOAD_WEAK_DYLIB else .LOAD_DYLIB,
            .name = dylib_id.name,
            .timestamp = dylib_id.timestamp,
            .current_version = dylib_id.current_version,
            .compatibility_version = dylib_id.compatibility_version,
        }, ncmds, lc_writer);
    }
}

pub fn deinit(self: *MachO) void {
    const gpa = self.base.allocator;

    self.tlv_ptr_entries.deinit(gpa);
    self.got_entries.deinit(gpa);
    self.stubs.deinit(gpa);
    self.strtab.deinit(gpa);
    self.locals.deinit(gpa);
    self.unresolved.deinit(gpa);

    for (self.globals.keys()) |key| {
        gpa.free(key);
    }
    self.globals.deinit(gpa);

    for (self.objects.items) |*object| {
        object.deinit(gpa);
    }
    self.objects.deinit(gpa);
    for (self.archives.items) |*archive| {
        archive.deinit(gpa);
    }
    self.archives.deinit(gpa);
    for (self.dylibs.items) |*dylib| {
        dylib.deinit(gpa);
    }
    self.dylibs.deinit(gpa);
    self.dylibs_map.deinit(gpa);
    self.referenced_dylibs.deinit(gpa);

    self.segments.deinit(gpa);
    self.sections.deinit(gpa);

    for (self.atoms.items) |*atom| {
        atom.deinit(gpa);
    }
    self.atoms.deinit(gpa);

    self.atom_by_index_table.deinit(gpa);

    {
        var it = self.relocs.valueIterator();
        while (it.next()) |relocs| {
            relocs.deinit(gpa);
        }
        self.relocs.deinit(gpa);
    }

    {
        var it = self.rebases.valueIterator();
        while (it.next()) |rebases| {
            rebases.deinit(gpa);
        }
        self.rebases.deinit(gpa);
    }

    {
        var it = self.bindings.valueIterator();
        while (it.next()) |bindings| {
            bindings.deinit(gpa);
        }
        self.bindings.deinit(gpa);
    }
}

pub fn closeFiles(self: *const MachO) void {
    for (self.archives.items) |archive| {
        archive.file.close();
    }
}

fn createPagezeroSegment(self: *MachO) !void {
    if (self.options.output_mode == .lib) return;

    const pagezero_vmsize = self.options.pagezero_size orelse default_pagezero_vmsize;
    const aligned_pagezero_vmsize = mem.alignBackwardGeneric(u64, pagezero_vmsize, self.page_size);
    if (aligned_pagezero_vmsize == 0) return;

    if (aligned_pagezero_vmsize != pagezero_vmsize) {
        log.warn("requested __PAGEZERO size (0x{x}) is not page aligned", .{pagezero_vmsize});
        log.warn("  rounding down to 0x{x}", .{aligned_pagezero_vmsize});
    }
    try self.segments.append(self.base.allocator, .{
        .cmdsize = @sizeOf(macho.segment_command_64),
        .segname = makeStaticString("__PAGEZERO"),
        .vmsize = aligned_pagezero_vmsize,
    });
}

inline fn calcInstallNameLen(cmd_size: u64, name: []const u8, assume_max_path_len: bool) u64 {
    const name_len = if (assume_max_path_len) std.os.PATH_MAX else std.mem.len(name) + 1;
    return mem.alignForwardGeneric(u64, cmd_size + name_len, @alignOf(u64));
}

fn calcLCsSize(self: *MachO, assume_max_path_len: bool) !u32 {
    const gpa = self.base.allocator;

    var sizeofcmds: u64 = 0;
    for (self.segments.items) |seg| {
        sizeofcmds += seg.nsects * @sizeOf(macho.section_64) + @sizeOf(macho.segment_command_64);
    }

    // LC_DYLD_INFO_ONLY
    sizeofcmds += @sizeOf(macho.dyld_info_command);
    // LC_FUNCTION_STARTS
    if (self.getSectionByName("__TEXT", "__text")) |_| {
        sizeofcmds += @sizeOf(macho.linkedit_data_command);
    }
    // LC_DATA_IN_CODE
    sizeofcmds += @sizeOf(macho.linkedit_data_command);
    // LC_SYMTAB
    sizeofcmds += @sizeOf(macho.symtab_command);
    // LC_DYSYMTAB
    sizeofcmds += @sizeOf(macho.dysymtab_command);
    // LC_LOAD_DYLINKER
    sizeofcmds += calcInstallNameLen(
        @sizeOf(macho.dylinker_command),
        mem.sliceTo(default_dyld_path, 0),
        false,
    );
    // LC_MAIN
    if (self.options.output_mode == .exe) {
        sizeofcmds += @sizeOf(macho.entry_point_command);
    }
    // LC_ID_DYLIB
    if (self.options.output_mode == .lib) {
        sizeofcmds += blk: {
            const install_name = self.options.install_name orelse self.options.emit.sub_path;
            break :blk calcInstallNameLen(
                @sizeOf(macho.dylib_command),
                install_name,
                assume_max_path_len,
            );
        };
    }
    // LC_RPATH
    {
        var it = RpathIterator.init(gpa, self.options.rpath_list);
        defer it.deinit();
        while (try it.next()) |rpath| {
            sizeofcmds += calcInstallNameLen(
                @sizeOf(macho.rpath_command),
                rpath,
                assume_max_path_len,
            );
        }
    }
    // LC_SOURCE_VERSION
    sizeofcmds += @sizeOf(macho.source_version_command);
    // LC_BUILD_VERSION
    sizeofcmds += @sizeOf(macho.build_version_command) + @sizeOf(macho.build_tool_version);
    // LC_UUID
    sizeofcmds += @sizeOf(macho.uuid_command);
    // LC_LOAD_DYLIB
    for (self.referenced_dylibs.keys()) |id| {
        const dylib = self.dylibs.items[id];
        const dylib_id = dylib.id orelse unreachable;
        sizeofcmds += calcInstallNameLen(
            @sizeOf(macho.dylib_command),
            dylib_id.name,
            assume_max_path_len,
        );
    }
    // LC_CODE_SIGNATURE
    {
        const target = self.options.target;
        const requires_codesig = blk: {
            if (self.options.entitlements) |_| break :blk true;
            if (target.cpu_arch.? == .aarch64 and (target.os_tag.? == .macos or target.abi.? == .simulator))
                break :blk true;
            break :blk false;
        };
        if (requires_codesig) {
            sizeofcmds += @sizeOf(macho.linkedit_data_command);
        }
    }

    return @intCast(u32, sizeofcmds);
}

fn calcMinHeaderPad(self: *MachO) !u64 {
    var padding: u32 = (try self.calcLCsSize(false)) + (self.options.headerpad orelse 0);
    log.debug("minimum requested headerpad size 0x{x}", .{padding + @sizeOf(macho.mach_header_64)});

    if (self.options.headerpad_max_install_names) {
        var min_headerpad_size: u32 = try self.calcLCsSize(true);
        log.debug("headerpad_max_install_names minimum headerpad size 0x{x}", .{
            min_headerpad_size + @sizeOf(macho.mach_header_64),
        });
        padding = @maximum(padding, min_headerpad_size);
    }

    const offset = @sizeOf(macho.mach_header_64) + padding;
    log.debug("actual headerpad size 0x{x}", .{offset});

    return offset;
}

fn allocateSymbol(self: *MachO) !u32 {
    try self.locals.ensureUnusedCapacity(self.base.allocator, 1);
    log.debug("  (allocating symbol index {d})", .{self.locals.items.len});
    const index = @intCast(u32, self.locals.items.len);
    _ = self.locals.addOneAssumeCapacity();
    self.locals.items[index] = .{
        .n_strx = 0,
        .n_type = 0,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
    return index;
}

fn allocateAtoms(self: *MachO) !void {
    const slice = &self.sections.slice();
    for (slice.items(.first_atom_index)) |first_atom_index, sect_id| {
        const header = slice.items(.header)[sect_id];
        var atom_index = first_atom_index;
        var atom = self.getAtom(atom_index);

        const n_sect = @intCast(u8, sect_id + 1);
        var base_vaddr = header.addr;

        log.debug("allocating local symbols in sect({d}, '{s},{s}')", .{
            n_sect,
            header.segName(),
            header.sectName(),
        });

        while (true) {
            const alignment = try math.powi(u32, 2, atom.alignment);
            base_vaddr = mem.alignForwardGeneric(u64, base_vaddr, alignment);

            const sym = self.getSymbolPtr(atom.getSymbolWithLoc());
            sym.n_value = base_vaddr;
            sym.n_sect = n_sect;

            log.debug("  ATOM(%{d}, '{s}') @{x}", .{
                atom.sym_index,
                self.getSymbolName(atom.getSymbolWithLoc()),
                base_vaddr,
            });

            // Update each symbol contained within the atom
            for (atom.contained.items) |sym_at_off| {
                const contained_sym = self.getSymbolPtr(.{
                    .sym_index = sym_at_off.sym_index,
                    .file = atom.file,
                });
                contained_sym.n_value = base_vaddr + sym_at_off.offset;
                contained_sym.n_sect = n_sect;
            }

            base_vaddr += atom.size;

            if (atom.next_index) |next_index| {
                atom_index = next_index;
                atom = self.getAtom(atom_index);
            } else break;
        }
    }
}

fn allocateSpecialSymbols(self: *MachO) !void {
    for (&[_][]const u8{
        "___dso_handle",
        "__mh_execute_header",
    }) |name| {
        const global = self.globals.get(name) orelse continue;
        if (global.file != null) continue;
        const sym = self.getSymbolPtr(global);
        const segment_index = self.getSegmentByName("__TEXT").?;
        const seg = self.segments.items[segment_index];
        sym.n_sect = 1;
        sym.n_value = seg.vmaddr;
        log.debug("allocating {s} at the start of {s}", .{
            name,
            seg.segName(),
        });
    }
}

fn writeAtoms(self: *MachO) !void {
    const gpa = self.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.first_atom_index)) |first_atom_index, sect_id| {
        const header = slice.items(.header)[sect_id];
        var atom_index = first_atom_index;
        var atom = self.getAtom(atom_index);

        if (header.isZerofill()) continue;

        var buffer = std.ArrayList(u8).init(gpa);
        defer buffer.deinit();
        try buffer.ensureTotalCapacity(math.cast(usize, header.size) orelse return error.Overflow);

        log.debug("writing atoms in {s},{s}", .{ header.segName(), header.sectName() });

        var count: u32 = 0;
        while (true) : (count += 1) {
            const this_sym = self.getSymbol(atom.getSymbolWithLoc());
            const padding_size: usize = if (atom.next_index) |next_index| blk: {
                const next_sym = self.getSymbol(self.getAtom(next_index).getSymbolWithLoc());
                const size = next_sym.n_value - (this_sym.n_value + atom.size);
                break :blk math.cast(usize, size) orelse return error.Overflow;
            } else 0;

            log.debug("  (adding ATOM(%{d}, '{s}') from object({?}) to buffer)", .{
                atom.sym_index,
                self.getSymbolName(atom.getSymbolWithLoc()),
                atom.file,
            });
            if (padding_size > 0) {
                log.debug("    (with padding {x})", .{padding_size});
            }

            const offset = buffer.items.len;

            // TODO: move writing synthetic sections into a separate function
            if (atom.file == null) outer: {
                if (self.dyld_private_sym_index) |sym_index| {
                    if (atom.sym_index == sym_index) {
                        buffer.appendSliceAssumeCapacity(&[_]u8{0} ** @sizeOf(u64));
                        break :outer;
                    }
                }
                switch (header.@"type"()) {
                    macho.S_NON_LAZY_SYMBOL_POINTERS => {
                        try self.writeGotPointer(count, buffer.writer());
                    },
                    macho.S_LAZY_SYMBOL_POINTERS => {
                        try self.writeLazyPointer(count, buffer.writer());
                    },
                    macho.S_THREAD_LOCAL_VARIABLE_POINTERS => {
                        buffer.appendSliceAssumeCapacity(&[_]u8{0} ** @sizeOf(u64));
                    },
                    else => {
                        if (self.stub_helper_preamble_sym_index) |sym_index| {
                            if (sym_index == atom.sym_index) {
                                try self.writeStubHelperPreambleCode(buffer.writer());
                                break :outer;
                            }
                        }
                        if (header.@"type"() == macho.S_SYMBOL_STUBS) {
                            try self.writeStubCode(atom_index, count, buffer.writer());
                        } else {
                            try self.writeStubHelperCode(atom_index, buffer.writer());
                        }
                    },
                }
            } else {
                const code = Atom.getAtomCode(self, atom_index).?;
                buffer.appendSliceAssumeCapacity(code);
                try Atom.resolveRelocs(self, atom_index, buffer.items[offset..][0..atom.size]);
            }

            var i: usize = 0;
            while (i < padding_size) : (i += 1) {
                // TODO with NOPs
                buffer.appendAssumeCapacity(0);
            }

            if (atom.next_index) |next_index| {
                atom_index = next_index;
                atom = self.getAtom(atom_index);
            } else {
                assert(buffer.items.len == header.size);
                log.debug("  (writing at file offset 0x{x})", .{header.offset});
                try self.base.file.pwriteAll(buffer.items, header.offset);
                break;
            }
        }
    }
}

fn allocateSegments(self: *MachO) !void {
    for (self.segments.items) |*segment, segment_index| {
        const is_text_segment = mem.eql(u8, segment.segName(), "__TEXT");
        const base_size = if (is_text_segment) try self.calcMinHeaderPad() else 0;
        try self.allocateSegment(@intCast(u8, segment_index), base_size);

        if (is_text_segment) blk: {
            const indexes = self.getSectionIndexes(@intCast(u8, segment_index));
            if (indexes.start == indexes.end) break :blk;

            // Shift all sections to the back to minimize jump size between __TEXT and __DATA segments.
            var min_alignment: u32 = 0;
            for (self.sections.items(.header)[indexes.start..indexes.end]) |header| {
                const alignment = try math.powi(u32, 2, header.@"align");
                min_alignment = math.max(min_alignment, alignment);
            }

            assert(min_alignment > 0);
            const last_header = self.sections.items(.header)[indexes.end - 1];
            const shift: u32 = shift: {
                const diff = segment.filesize - last_header.offset - last_header.size;
                const factor = @divTrunc(diff, min_alignment);
                break :shift @intCast(u32, factor * min_alignment);
            };

            if (shift > 0) {
                for (self.sections.items(.header)[indexes.start..indexes.end]) |*header| {
                    header.offset += shift;
                    header.addr += shift;
                }
            }
        }
    }
}

fn getSegmentAllocBase(self: MachO, segment_index: u8) struct { vmaddr: u64, fileoff: u64 } {
    if (segment_index > 0) {
        const prev_segment = self.segments.items[segment_index - 1];
        return .{
            .vmaddr = prev_segment.vmaddr + prev_segment.vmsize,
            .fileoff = prev_segment.fileoff + prev_segment.filesize,
        };
    }
    return .{ .vmaddr = 0, .fileoff = 0 };
}

fn allocateSegment(self: *MachO, segment_index: u8, init_size: u64) !void {
    const segment = &self.segments.items[segment_index];

    if (mem.eql(u8, segment.segName(), "__PAGEZERO")) return; // allocated upon creation

    const base = self.getSegmentAllocBase(segment_index);
    segment.vmaddr = base.vmaddr;
    segment.fileoff = base.fileoff;
    segment.filesize = init_size;
    segment.vmsize = init_size;

    // Allocate the sections according to their alignment at the beginning of the segment.
    const indexes = self.getSectionIndexes(segment_index);
    var start = init_size;
    const slice = self.sections.slice();
    for (slice.items(.header)[indexes.start..indexes.end]) |*header| {
        const alignment = try math.powi(u32, 2, header.@"align");
        const start_aligned = mem.alignForwardGeneric(u64, start, alignment);

        header.offset = if (header.isZerofill())
            0
        else
            @intCast(u32, segment.fileoff + start_aligned);
        header.addr = segment.vmaddr + start_aligned;

        start = start_aligned + header.size;

        if (!header.isZerofill()) {
            segment.filesize = start;
        }
        segment.vmsize = start;
    }

    segment.filesize = mem.alignForwardGeneric(u64, segment.filesize, self.page_size);
    segment.vmsize = mem.alignForwardGeneric(u64, segment.vmsize, self.page_size);
}

const InitSectionOpts = struct {
    flags: u32 = macho.S_REGULAR,
    reserved1: u32 = 0,
    reserved2: u32 = 0,
};

fn initSection(
    self: *MachO,
    segname: []const u8,
    sectname: []const u8,
    opts: InitSectionOpts,
) !u8 {
    const segment_id = self.getSegmentByName(segname) orelse blk: {
        const precedence = getSegmentPrecedence(segname);
        const insertion_index = for (self.segments.items) |segment, i| {
            if (getSegmentPrecedence(segment.segName()) > precedence) break @intCast(u8, i);
        } else @intCast(u8, self.segments.items.len);
        for (self.sections.items(.segment_index)) |*segment_index| {
            if (segment_index.* >= insertion_index) {
                segment_index.* += 1;
            }
        }
        log.debug("inserting segment '{s}' at index {d}", .{ segname, insertion_index });
        const protection = getSegmentMemoryProtection(segname);
        try self.segments.insert(self.base.allocator, insertion_index, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString(segname),
            .maxprot = protection,
            .initprot = protection,
        });
        break :blk insertion_index;
    };
    const seg = &self.segments.items[segment_id];
    const index = try self.insertSection(segment_id, .{
        .sectname = makeStaticString(sectname),
        .segname = seg.segname,
        .flags = opts.flags,
        .reserved1 = opts.reserved1,
        .reserved2 = opts.reserved2,
    });
    seg.cmdsize += @sizeOf(macho.section_64);
    seg.nsects += 1;
    return index;
}

inline fn getSegmentPrecedence(segname: []const u8) u3 {
    if (mem.eql(u8, segname, "__PAGEZERO")) return 0x0;
    if (mem.eql(u8, segname, "__TEXT")) return 0x1;
    if (mem.eql(u8, segname, "__DATA_CONST")) return 0x2;
    if (mem.eql(u8, segname, "__DATA")) return 0x3;
    if (mem.eql(u8, segname, "__LINKEDIT")) return 0x5;
    return 0x4;
}

inline fn getSegmentMemoryProtection(segname: []const u8) macho.vm_prot_t {
    if (mem.eql(u8, segname, "__PAGEZERO")) return macho.PROT.NONE;
    if (mem.eql(u8, segname, "__TEXT")) return macho.PROT.READ | macho.PROT.EXEC;
    if (mem.eql(u8, segname, "__LINKEDIT")) return macho.PROT.READ;
    return macho.PROT.READ | macho.PROT.WRITE;
}

inline fn getSectionPrecedence(header: macho.section_64) u4 {
    if (header.isCode()) {
        if (mem.eql(u8, "__text", header.sectName())) return 0x0;
        if (header.@"type"() == macho.S_SYMBOL_STUBS) return 0x1;
        return 0x2;
    }
    switch (header.@"type"()) {
        macho.S_NON_LAZY_SYMBOL_POINTERS,
        macho.S_LAZY_SYMBOL_POINTERS,
        => return 0x0,
        macho.S_MOD_INIT_FUNC_POINTERS => return 0x1,
        macho.S_MOD_TERM_FUNC_POINTERS => return 0x2,
        macho.S_ZEROFILL => return 0xf,
        macho.S_THREAD_LOCAL_REGULAR => return 0xd,
        macho.S_THREAD_LOCAL_ZEROFILL => return 0xe,
        else => if (mem.eql(u8, "__eh_frame", header.sectName()))
            return 0xf
        else
            return 0x3,
    }
}

fn insertSection(self: *MachO, segment_index: u8, header: macho.section_64) !u8 {
    const precedence = getSectionPrecedence(header);
    const indexes = self.getSectionIndexes(segment_index);
    const insertion_index = for (self.sections.items(.header)[indexes.start..indexes.end]) |hdr, i| {
        if (getSectionPrecedence(hdr) > precedence) break @intCast(u8, i + indexes.start);
    } else indexes.end;
    log.debug("inserting section '{s},{s}' at index {d}", .{
        header.segName(),
        header.sectName(),
        insertion_index,
    });
    try self.sections.insert(self.base.allocator, insertion_index, .{
        .segment_index = segment_index,
        .header = header,
        .first_atom_index = undefined,
        .last_atom_index = undefined,
    });
    return insertion_index;
}

fn writeSegmentHeaders(self: *MachO, ncmds: *u32, writer: anytype) !void {
    for (self.segments.items) |seg, i| {
        const indexes = self.getSectionIndexes(@intCast(u8, i));
        var out_seg = seg;
        out_seg.cmdsize = @sizeOf(macho.segment_command_64);
        out_seg.nsects = 0;

        // Update section headers count; any section with size of 0 is excluded
        // since it doesn't have any data in the final binary file.
        for (self.sections.items(.header)[indexes.start..indexes.end]) |header| {
            if (header.size == 0) continue;
            out_seg.cmdsize += @sizeOf(macho.section_64);
            out_seg.nsects += 1;
        }

        if (out_seg.nsects == 0 and
            (mem.eql(u8, out_seg.segName(), "__DATA_CONST") or
            mem.eql(u8, out_seg.segName(), "__DATA"))) continue;

        try writer.writeStruct(out_seg);
        for (self.sections.items(.header)[indexes.start..indexes.end]) |header| {
            if (header.size == 0) continue;
            try writer.writeStruct(header);
        }

        ncmds.* += 1;
    }
}

fn writeLinkeditSegmentData(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    {
        const protection = getSegmentMemoryProtection("__LINKEDIT");
        const base = self.getSegmentAllocBase(@intCast(u8, self.segments.items.len));
        try self.segments.append(self.base.allocator, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString("__LINKEDIT"),
            .vmaddr = base.vmaddr,
            .fileoff = base.fileoff,
            .maxprot = protection,
            .initprot = protection,
        });
    }

    try self.writeDyldInfoData(ncmds, lc_writer);
    try self.writeFunctionStarts(ncmds, lc_writer);
    try self.writeDataInCode(ncmds, lc_writer);
    try self.writeSymtabs(ncmds, lc_writer);

    const seg = self.getLinkeditSegmentPtr();
    seg.vmsize = mem.alignForwardGeneric(u64, seg.filesize, self.page_size);
}

const AtomLessThanByAddressContext = struct {
    macho_file: *MachO,
};

fn atomLessThanByAddress(ctx: AtomLessThanByAddressContext, lhs: AtomIndex, rhs: AtomIndex) bool {
    const lhs_atom = ctx.macho_file.getAtom(lhs);
    const lhs_sym = ctx.macho_file.getSymbol(lhs_atom.getSymbolWithLoc());
    const rhs_atom = ctx.macho_file.getAtom(rhs);
    const rhs_sym = ctx.macho_file.getSymbol(rhs_atom.getSymbolWithLoc());
    return lhs_sym.n_value < rhs_sym.n_value;
}

fn collectRebaseDataFromContainer(
    self: *MachO,
    sect_id: u8,
    pointers: *std.ArrayList(bind.Pointer),
    container: anytype,
) !void {
    const slice = self.sections.slice();
    const segment_index = slice.items(.segment_index)[sect_id];
    const seg = self.getSegment(sect_id);

    try pointers.ensureUnusedCapacity(container.count());

    for (container.values()) |sym_index| {
        const sym = self.getSymbol(.{ .sym_index = sym_index, .file = null });
        const base_offset = sym.n_value - seg.vmaddr;

        log.debug("    | rebase at {x}", .{base_offset});

        pointers.appendAssumeCapacity(.{
            .offset = base_offset,
            .segment_id = segment_index,
        });
    }
}

fn collectRebaseData(self: *MachO, pointers: *std.ArrayList(bind.Pointer)) !void {
    const gpa = self.base.allocator;

    log.debug("collecting rebase data", .{});

    // First, unpack GOT entries
    if (self.getSectionByName("__DATA_CONST", "__got")) |sect_id| {
        try self.collectRebaseDataFromContainer(sect_id, pointers, self.got_entries);
    }

    const slice = self.sections.slice();

    // Next, unpact lazy pointers
    // TODO: save la_ptr in a container so that we can re-use the helper
    if (self.getSectionByName("__DATA", "__la_symbol_ptr")) |sect_id| {
        const segment_index = slice.items(.segment_index)[sect_id];
        const seg = self.getSegment(sect_id);
        var atom_index = slice.items(.first_atom_index)[sect_id];

        try pointers.ensureUnusedCapacity(self.stubs.count());

        while (true) {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());
            const base_offset = sym.n_value - seg.vmaddr;

            log.debug("    | rebase at {x}", .{base_offset});

            pointers.appendAssumeCapacity(.{
                .offset = base_offset,
                .segment_id = segment_index,
            });

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    // Finally, unpack the rest
    // TODO: either traverse the relocations again, or save generated reabase offsets in local context
    // when writing and resolving relocations.
    var sorted_atoms_by_address = std.ArrayList(AtomIndex).init(gpa);
    defer sorted_atoms_by_address.deinit();
    try sorted_atoms_by_address.ensureTotalCapacityPrecise(self.rebases.count());

    var it = self.rebases.keyIterator();
    while (it.next()) |key_ptr| {
        sorted_atoms_by_address.appendAssumeCapacity(key_ptr.*);
    }

    std.sort.sort(AtomIndex, sorted_atoms_by_address.items, AtomLessThanByAddressContext{
        .macho_file = self,
    }, atomLessThanByAddress);

    for (sorted_atoms_by_address.items) |atom_index| {
        const atom = self.getAtom(atom_index);

        log.debug("  ATOM(%{d}, '{s}')", .{ atom.sym_index, self.getSymbolName(atom.getSymbolWithLoc()) });

        const sym = self.getSymbol(atom.getSymbolWithLoc());
        const segment_index = slice.items(.segment_index)[sym.n_sect - 1];
        const seg = self.getSegment(sym.n_sect - 1);

        const base_offset = sym.n_value - seg.vmaddr;

        const rebases = self.rebases.get(atom_index).?;
        try pointers.ensureUnusedCapacity(rebases.items.len);
        for (rebases.items) |offset| {
            log.debug("    | rebase at {x}", .{base_offset + offset});

            pointers.appendAssumeCapacity(.{
                .offset = base_offset + offset,
                .segment_id = segment_index,
            });
        }
    }
}

fn collectBindDataFromContainer(
    self: *MachO,
    sect_id: u8,
    pointers: *std.ArrayList(bind.Pointer),
    container: anytype,
) !void {
    const slice = self.sections.slice();
    const segment_index = slice.items(.segment_index)[sect_id];
    const seg = self.getSegment(sect_id);

    try pointers.ensureUnusedCapacity(container.count());

    for (container.keys()) |target| {
        const bind_sym_name = self.getSymbolName(target);
        const global = self.globals.get(bind_sym_name).?;
        const bind_sym = self.getSymbol(global);
        if (bind_sym.sect()) continue;

        const sym_index = container.get(target).?;
        const sym = self.getSymbol(.{ .sym_index = sym_index, .file = null });
        const base_offset = sym.n_value - seg.vmaddr;

        const dylib_ordinal = @divTrunc(@bitCast(i16, bind_sym.n_desc), macho.N_SYMBOL_RESOLVER);
        var flags: u4 = 0;
        log.debug("    | bind at {x}, import('{s}') in dylib({d})", .{
            base_offset,
            bind_sym_name,
            dylib_ordinal,
        });
        if (bind_sym.weakRef()) {
            log.debug("    | marking as weak ref ", .{});
            flags |= @truncate(u4, macho.BIND_SYMBOL_FLAGS_WEAK_IMPORT);
        }
        pointers.appendAssumeCapacity(.{
            .offset = base_offset,
            .segment_id = segment_index,
            .dylib_ordinal = dylib_ordinal,
            .name = bind_sym_name,
            .bind_flags = flags,
        });
    }
}

fn collectBindData(self: *MachO, pointers: *std.ArrayList(bind.Pointer), raw_bindings: anytype) !void {
    const gpa = self.base.allocator;

    log.debug("collecting bind data", .{});

    // First, unpack GOT section
    if (self.getSectionByName("__DATA_CONST", "__got")) |sect_id| {
        try self.collectBindDataFromContainer(sect_id, pointers, self.got_entries);
    }

    // Next, unpack TLV pointers section
    if (self.getSectionByName("__DATA", "__thread_ptrs")) |sect_id| {
        try self.collectBindDataFromContainer(sect_id, pointers, self.tlv_ptr_entries);
    }

    // TODO: scan relocations for any remaining binds here
    var sorted_atoms_by_address = std.ArrayList(AtomIndex).init(gpa);
    defer sorted_atoms_by_address.deinit();
    try sorted_atoms_by_address.ensureTotalCapacityPrecise(raw_bindings.count());

    var it = raw_bindings.keyIterator();
    while (it.next()) |key_ptr| {
        sorted_atoms_by_address.appendAssumeCapacity(key_ptr.*);
    }

    std.sort.sort(AtomIndex, sorted_atoms_by_address.items, AtomLessThanByAddressContext{
        .macho_file = self,
    }, atomLessThanByAddress);

    const slice = self.sections.slice();
    for (sorted_atoms_by_address.items) |atom_index| {
        const atom = self.getAtom(atom_index);

        log.debug("  ATOM(%{d}, '{s}')", .{ atom.sym_index, self.getSymbolName(atom.getSymbolWithLoc()) });

        const sym = self.getSymbol(atom.getSymbolWithLoc());
        const segment_index = slice.items(.segment_index)[sym.n_sect - 1];
        const seg = self.getSegment(sym.n_sect - 1);

        const base_offset = sym.n_value - seg.vmaddr;

        const bindings = raw_bindings.get(atom_index).?;
        try pointers.ensureUnusedCapacity(bindings.items.len);
        for (bindings.items) |binding| {
            const bind_sym = self.getSymbol(binding.target);
            const bind_sym_name = self.getSymbolName(binding.target);
            const dylib_ordinal = @divTrunc(
                @bitCast(i16, bind_sym.n_desc),
                macho.N_SYMBOL_RESOLVER,
            );
            var flags: u4 = 0;
            log.debug("    | bind at {x}, import('{s}') in dylib({d})", .{
                binding.offset + base_offset,
                bind_sym_name,
                dylib_ordinal,
            });
            if (bind_sym.weakRef()) {
                log.debug("    | marking as weak ref ", .{});
                flags |= @truncate(u4, macho.BIND_SYMBOL_FLAGS_WEAK_IMPORT);
            }
            pointers.appendAssumeCapacity(.{
                .offset = binding.offset + base_offset,
                .segment_id = segment_index,
                .dylib_ordinal = dylib_ordinal,
                .name = bind_sym_name,
                .bind_flags = flags,
            });
        }
    }
}

fn collectLazyBindData(self: *MachO, pointers: *std.ArrayList(bind.Pointer)) !void {
    const sect_id = self.getSectionByName("__DATA", "__la_symbol_ptr") orelse return;

    log.debug("collecting lazy bind data", .{});

    const slice = self.sections.slice();
    const segment_index = slice.items(.segment_index)[sect_id];
    const seg = self.getSegment(sect_id);
    var atom_index = slice.items(.first_atom_index)[sect_id];

    // TODO: we actually don't need to store lazy pointer atoms as they are synthetically generated by the linker
    try pointers.ensureUnusedCapacity(self.stubs.count());

    var count: u32 = 0;
    while (true) : (count += 1) {
        const atom = self.getAtom(atom_index);

        log.debug("  ATOM(%{d}, '{s}')", .{ atom.sym_index, self.getSymbolName(atom.getSymbolWithLoc()) });

        const sym = self.getSymbol(atom.getSymbolWithLoc());
        const base_offset = sym.n_value - seg.vmaddr;

        const bind_target = self.stubs.keys()[count];
        const bind_sym = self.getSymbol(bind_target);
        const bind_sym_name = self.getSymbolName(bind_target);
        const dylib_ordinal = @divTrunc(@bitCast(i16, bind_sym.n_desc), macho.N_SYMBOL_RESOLVER);
        var flags: u4 = 0;
        log.debug("    | lazy bind at {x}, import('{s}') in dylib({d})", .{
            base_offset,
            bind_sym_name,
            dylib_ordinal,
        });
        if (bind_sym.weakRef()) {
            log.debug("    | marking as weak ref ", .{});
            flags |= @truncate(u4, macho.BIND_SYMBOL_FLAGS_WEAK_IMPORT);
        }
        pointers.appendAssumeCapacity(.{
            .offset = base_offset,
            .segment_id = segment_index,
            .dylib_ordinal = dylib_ordinal,
            .name = bind_sym_name,
            .bind_flags = flags,
        });

        if (atom.next_index) |next_index| {
            atom_index = next_index;
        } else break;
    }
}

fn collectExportData(self: *MachO, trie: *Trie) !void {
    const gpa = self.base.allocator;

    // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
    log.debug("collecting export data", .{});

    const segment_index = self.getSegmentByName("__TEXT").?;
    const exec_segment = self.segments.items[segment_index];
    const base_address = exec_segment.vmaddr;

    if (self.options.output_mode == .exe) {
        for (&[_]SymbolWithLoc{
            try self.getEntryPoint(),
            self.globals.get("__mh_execute_header").?,
        }) |global| {
            const sym = self.getSymbol(global);
            const sym_name = self.getSymbolName(global);
            log.debug("  (putting '{s}' defined at 0x{x})", .{ sym_name, sym.n_value });
            try trie.put(gpa, .{
                .name = sym_name,
                .vmaddr_offset = sym.n_value - base_address,
                .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
            });
        }
    } else {
        assert(self.options.output_mode == .lib);
        for (self.globals.values()) |global| {
            const sym = self.getSymbol(global);

            if (sym.undf()) continue;
            if (!sym.ext()) continue;
            if (sym.n_desc == N_DESC_GCED) continue;

            const sym_name = self.getSymbolName(global);
            log.debug("  (putting '{s}' defined at 0x{x})", .{ sym_name, sym.n_value });
            try trie.put(gpa, .{
                .name = sym_name,
                .vmaddr_offset = sym.n_value - base_address,
                .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
            });
        }
    }

    try trie.finalize(gpa);
}

fn writeDyldInfoData(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    const gpa = self.base.allocator;

    var rebase_pointers = std.ArrayList(bind.Pointer).init(gpa);
    defer rebase_pointers.deinit();
    try self.collectRebaseData(&rebase_pointers);

    var bind_pointers = std.ArrayList(bind.Pointer).init(gpa);
    defer bind_pointers.deinit();
    try self.collectBindData(&bind_pointers, self.bindings);

    var lazy_bind_pointers = std.ArrayList(bind.Pointer).init(gpa);
    defer lazy_bind_pointers.deinit();
    try self.collectLazyBindData(&lazy_bind_pointers);

    var trie = Trie{};
    defer trie.deinit(gpa);
    try self.collectExportData(&trie);

    const link_seg = self.getLinkeditSegmentPtr();
    const rebase_off = mem.alignForwardGeneric(u64, link_seg.fileoff, @alignOf(u64));
    assert(rebase_off == link_seg.fileoff);
    const rebase_size = try bind.rebaseInfoSize(rebase_pointers.items);
    log.debug("writing rebase info from 0x{x} to 0x{x}", .{ rebase_off, rebase_off + rebase_size });

    const bind_off = mem.alignForwardGeneric(u64, rebase_off + rebase_size, @alignOf(u64));
    const bind_size = try bind.bindInfoSize(bind_pointers.items);
    log.debug("writing bind info from 0x{x} to 0x{x}", .{ bind_off, bind_off + bind_size });

    const lazy_bind_off = mem.alignForwardGeneric(u64, bind_off + bind_size, @alignOf(u64));
    const lazy_bind_size = try bind.lazyBindInfoSize(lazy_bind_pointers.items);
    log.debug("writing lazy bind info from 0x{x} to 0x{x}", .{ lazy_bind_off, lazy_bind_off + lazy_bind_size });

    const export_off = mem.alignForwardGeneric(u64, lazy_bind_off + lazy_bind_size, @alignOf(u64));
    const export_size = trie.size;
    log.debug("writing export trie from 0x{x} to 0x{x}", .{ export_off, export_off + export_size });

    const needed_size = export_off + export_size - rebase_off;
    link_seg.filesize = needed_size;

    var buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);
    mem.set(u8, buffer, 0);

    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();

    try bind.writeRebaseInfo(rebase_pointers.items, writer);
    try stream.seekTo(bind_off - rebase_off);

    try bind.writeBindInfo(bind_pointers.items, writer);
    try stream.seekTo(lazy_bind_off - rebase_off);

    try bind.writeLazyBindInfo(lazy_bind_pointers.items, writer);
    try stream.seekTo(export_off - rebase_off);

    _ = try trie.write(writer);

    log.debug("writing dyld info from 0x{x} to 0x{x}", .{
        rebase_off,
        rebase_off + needed_size,
    });

    try self.base.file.pwriteAll(buffer, rebase_off);
    try self.populateLazyBindOffsetsInStubHelper(buffer[lazy_bind_off - rebase_off ..][0..lazy_bind_size]);

    try lc_writer.writeStruct(macho.dyld_info_command{
        .cmd = .DYLD_INFO_ONLY,
        .cmdsize = @sizeOf(macho.dyld_info_command),
        .rebase_off = @intCast(u32, rebase_off),
        .rebase_size = @intCast(u32, rebase_size),
        .bind_off = @intCast(u32, bind_off),
        .bind_size = @intCast(u32, bind_size),
        .weak_bind_off = 0,
        .weak_bind_size = 0,
        .lazy_bind_off = @intCast(u32, lazy_bind_off),
        .lazy_bind_size = @intCast(u32, lazy_bind_size),
        .export_off = @intCast(u32, export_off),
        .export_size = @intCast(u32, export_size),
    });
    ncmds.* += 1;
}

fn populateLazyBindOffsetsInStubHelper(self: *MachO, buffer: []const u8) !void {
    const gpa = self.base.allocator;

    const stub_helper_section_index = self.getSectionByName("__TEXT", "__stub_helper") orelse return;
    if (self.stub_helper_preamble_sym_index == null) return;

    const section = self.sections.get(stub_helper_section_index);
    const last_atom_index = section.last_atom_index;

    var table = std.AutoHashMap(i64, AtomIndex).init(gpa);
    defer table.deinit();

    {
        var stub_atom_index = last_atom_index;
        var stub_atom = self.getAtom(stub_atom_index);

        const la_symbol_ptr_section_index = self.getSectionByName("__DATA", "__la_symbol_ptr").?;
        var laptr_atom_index = self.sections.items(.last_atom_index)[la_symbol_ptr_section_index];
        var laptr_atom = self.getAtom(laptr_atom_index);

        const base_addr = blk: {
            const segment_index = self.getSegmentByName("__DATA").?;
            const seg = self.segments.items[segment_index];
            break :blk seg.vmaddr;
        };

        while (true) {
            const laptr_off = blk: {
                const sym = self.getSymbolPtr(laptr_atom.getSymbolWithLoc());
                break :blk @intCast(i64, sym.n_value - base_addr);
            };

            try table.putNoClobber(laptr_off, stub_atom_index);

            if (laptr_atom.prev_index) |prev_index| {
                laptr_atom_index = prev_index;
                laptr_atom = self.getAtom(laptr_atom_index);
                stub_atom_index = stub_atom.prev_index.?;
                stub_atom = self.getAtom(stub_atom_index);
            } else break;
        }
    }

    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    var offsets = std.ArrayList(struct { sym_offset: i64, offset: u32 }).init(gpa);
    try offsets.append(.{ .sym_offset = undefined, .offset = 0 });
    defer offsets.deinit();
    var valid_block = false;

    while (true) {
        const inst = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
        };
        const opcode: u8 = inst & macho.BIND_OPCODE_MASK;

        switch (opcode) {
            macho.BIND_OPCODE_DO_BIND => {
                valid_block = true;
            },
            macho.BIND_OPCODE_DONE => {
                if (valid_block) {
                    const offset = try stream.getPos();
                    try offsets.append(.{ .sym_offset = undefined, .offset = @intCast(u32, offset) });
                }
                valid_block = false;
            },
            macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                var next = try reader.readByte();
                while (next != @as(u8, 0)) {
                    next = try reader.readByte();
                }
            },
            macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                var inserted = offsets.pop();
                inserted.sym_offset = try std.leb.readILEB128(i64, reader);
                try offsets.append(inserted);
            },
            macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                _ = try std.leb.readULEB128(u64, reader);
            },
            macho.BIND_OPCODE_SET_ADDEND_SLEB => {
                _ = try std.leb.readILEB128(i64, reader);
            },
            else => {},
        }
    }

    const header = self.sections.items(.header)[stub_helper_section_index];
    const stub_offset: u4 = switch (self.options.target.cpu_arch.?) {
        .x86_64 => 1,
        .aarch64 => 2 * @sizeOf(u32),
        else => unreachable,
    };
    var buf: [@sizeOf(u32)]u8 = undefined;
    _ = offsets.pop();

    while (offsets.popOrNull()) |bind_offset| {
        const atom_index = table.get(bind_offset.sym_offset).?;
        const atom = self.getAtom(atom_index);
        const sym = self.getSymbol(atom.getSymbolWithLoc());

        const file_offset = header.offset + sym.n_value - header.addr + stub_offset;
        mem.writeIntLittle(u32, &buf, bind_offset.offset);

        log.debug("writing lazy bind offset in stub helper of 0x{x} for symbol {s} at offset 0x{x}", .{
            bind_offset.offset,
            self.getSymbolName(atom.getSymbolWithLoc()),
            file_offset,
        });

        try self.base.file.pwriteAll(&buf, file_offset);
    }
}

const asc_u64 = std.sort.asc(u64);

fn writeFunctionStarts(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    const text_seg_index = self.getSegmentByName("__TEXT") orelse return;
    const text_sect_index = self.getSectionByName("__TEXT", "__text") orelse return;
    const text_seg = self.segments.items[text_seg_index];

    const gpa = self.base.allocator;

    // We need to sort by address first
    var addresses = std.ArrayList(u64).init(gpa);
    defer addresses.deinit();
    try addresses.ensureTotalCapacityPrecise(self.globals.count());

    for (self.globals.values()) |global| {
        const sym = self.getSymbol(global);
        if (sym.undf()) continue;
        if (sym.n_desc == N_DESC_GCED) continue;
        const sect_id = sym.n_sect - 1;
        if (sect_id != text_sect_index) continue;

        addresses.appendAssumeCapacity(sym.n_value);
    }

    std.sort.sort(u64, addresses.items, {}, asc_u64);

    var offsets = std.ArrayList(u32).init(gpa);
    defer offsets.deinit();
    try offsets.ensureTotalCapacityPrecise(addresses.items.len);

    var last_off: u32 = 0;
    for (addresses.items) |addr| {
        const offset = @intCast(u32, addr - text_seg.vmaddr);
        const diff = offset - last_off;

        if (diff == 0) continue;

        offsets.appendAssumeCapacity(diff);
        last_off = offset;
    }

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const max_size = @intCast(usize, offsets.items.len * @sizeOf(u64));
    try buffer.ensureTotalCapacity(max_size);

    for (offsets.items) |offset| {
        try std.leb.writeULEB128(buffer.writer(), offset);
    }

    const link_seg = self.getLinkeditSegmentPtr();
    const offset = mem.alignForwardGeneric(u64, link_seg.fileoff + link_seg.filesize, @alignOf(u64));
    const needed_size = buffer.items.len;
    link_seg.filesize = offset + needed_size - link_seg.fileoff;

    log.debug("writing function starts info from 0x{x} to 0x{x}", .{ offset, offset + needed_size });

    try self.base.file.pwriteAll(buffer.items, offset);

    try lc_writer.writeStruct(macho.linkedit_data_command{
        .cmd = .FUNCTION_STARTS,
        .cmdsize = @sizeOf(macho.linkedit_data_command),
        .dataoff = @intCast(u32, offset),
        .datasize = @intCast(u32, needed_size),
    });
    ncmds.* += 1;
}

fn filterDataInCode(
    dices: []const macho.data_in_code_entry,
    start_addr: u64,
    end_addr: u64,
) []const macho.data_in_code_entry {
    const Predicate = struct {
        addr: u64,

        pub fn predicate(self: @This(), dice: macho.data_in_code_entry) bool {
            return dice.offset >= self.addr;
        }
    };

    const start = MachO.findFirst(macho.data_in_code_entry, dices, 0, Predicate{ .addr = start_addr });
    const end = MachO.findFirst(macho.data_in_code_entry, dices, start, Predicate{ .addr = end_addr });

    return dices[start..end];
}

fn writeDataInCode(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    var out_dice = std.ArrayList(macho.data_in_code_entry).init(self.base.allocator);
    defer out_dice.deinit();

    const text_sect_id = self.getSectionByName("__TEXT", "__text") orelse return;
    const text_sect_header = self.sections.items(.header)[text_sect_id];

    for (self.objects.items) |object| {
        const dice = object.parseDataInCode() orelse continue;
        try out_dice.ensureUnusedCapacity(dice.len);

        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());
            if (sym.n_desc == N_DESC_GCED) continue;

            const sect_id = sym.n_sect - 1;
            if (sect_id != text_sect_id) {
                continue;
            }

            const source_sym = object.getSourceSymbol(atom.sym_index) orelse continue;
            const source_addr = math.cast(u32, source_sym.n_value) orelse return error.Overflow;
            const filtered_dice = filterDataInCode(dice, source_addr, source_addr + atom.size);
            const base = math.cast(u32, sym.n_value - text_sect_header.addr + text_sect_header.offset) orelse
                return error.Overflow;

            for (filtered_dice) |single| {
                const offset = single.offset - source_addr + base;
                out_dice.appendAssumeCapacity(.{
                    .offset = offset,
                    .length = single.length,
                    .kind = single.kind,
                });
            }
        }
    }

    const seg = self.getLinkeditSegmentPtr();
    const offset = mem.alignForwardGeneric(u64, seg.fileoff + seg.filesize, @alignOf(u64));
    const needed_size = out_dice.items.len * @sizeOf(macho.data_in_code_entry);
    seg.filesize = offset + needed_size - seg.fileoff;

    log.debug("writing data-in-code from 0x{x} to 0x{x}", .{ offset, offset + needed_size });

    try self.base.file.pwriteAll(mem.sliceAsBytes(out_dice.items), offset);
    try lc_writer.writeStruct(macho.linkedit_data_command{
        .cmd = .DATA_IN_CODE,
        .cmdsize = @sizeOf(macho.linkedit_data_command),
        .dataoff = @intCast(u32, offset),
        .datasize = @intCast(u32, needed_size),
    });
    ncmds.* += 1;
}

fn writeSymtabs(self: *MachO, ncmds: *u32, lc_writer: anytype) !void {
    var symtab_cmd = macho.symtab_command{
        .cmdsize = @sizeOf(macho.symtab_command),
        .symoff = 0,
        .nsyms = 0,
        .stroff = 0,
        .strsize = 0,
    };
    var dysymtab_cmd = macho.dysymtab_command{
        .cmdsize = @sizeOf(macho.dysymtab_command),
        .ilocalsym = 0,
        .nlocalsym = 0,
        .iextdefsym = 0,
        .nextdefsym = 0,
        .iundefsym = 0,
        .nundefsym = 0,
        .tocoff = 0,
        .ntoc = 0,
        .modtaboff = 0,
        .nmodtab = 0,
        .extrefsymoff = 0,
        .nextrefsyms = 0,
        .indirectsymoff = 0,
        .nindirectsyms = 0,
        .extreloff = 0,
        .nextrel = 0,
        .locreloff = 0,
        .nlocrel = 0,
    };
    var ctx = try self.writeSymtab(&symtab_cmd);
    defer ctx.imports_table.deinit();
    try self.writeDysymtab(ctx, &dysymtab_cmd);
    try self.writeStrtab(&symtab_cmd);
    try lc_writer.writeStruct(symtab_cmd);
    try lc_writer.writeStruct(dysymtab_cmd);
    ncmds.* += 2;
}

fn writeSymtab(self: *MachO, lc: *macho.symtab_command) !SymtabCtx {
    const gpa = self.base.allocator;

    var locals = std.ArrayList(macho.nlist_64).init(gpa);
    defer locals.deinit();

    for (self.locals.items) |sym, sym_id| {
        if (sym.n_strx == 0) continue; // no name, skip
        if (sym.n_desc == N_DESC_GCED) continue; // GCed, skip
        const sym_loc = SymbolWithLoc{ .sym_index = @intCast(u32, sym_id), .file = null };
        if (self.symbolIsTemp(sym_loc)) continue; // local temp symbol, skip
        if (self.globals.contains(self.getSymbolName(sym_loc))) continue; // global symbol is either an export or import, skip
        try locals.append(sym);
    }

    for (self.objects.items) |object, object_id| {
        for (object.symtab.items) |sym, sym_id| {
            if (sym.n_strx == 0) continue; // no name, skip
            if (sym.n_desc == N_DESC_GCED) continue; // GCed, skip
            const sym_loc = SymbolWithLoc{ .sym_index = @intCast(u32, sym_id), .file = @intCast(u32, object_id) };
            if (self.symbolIsTemp(sym_loc)) continue; // local temp symbol, skip
            if (self.globals.contains(self.getSymbolName(sym_loc))) continue; // global symbol is either an export or import, skip
            var out_sym = sym;
            out_sym.n_strx = try self.strtab.insert(gpa, self.getSymbolName(sym_loc));
            try locals.append(out_sym);
        }

        if (!self.options.strip) {
            try self.generateSymbolStabs(object, &locals);
        }
    }

    var exports = std.ArrayList(macho.nlist_64).init(gpa);
    defer exports.deinit();

    for (self.globals.values()) |global| {
        const sym = self.getSymbol(global);
        if (sym.undf()) continue; // import, skip
        if (sym.n_desc == N_DESC_GCED) continue; // GCed, skip
        var out_sym = sym;
        out_sym.n_strx = try self.strtab.insert(gpa, self.getSymbolName(global));
        try exports.append(out_sym);
    }

    var imports = std.ArrayList(macho.nlist_64).init(gpa);
    defer imports.deinit();

    var imports_table = std.AutoHashMap(SymbolWithLoc, u32).init(gpa);

    for (self.globals.values()) |global| {
        const sym = self.getSymbol(global);
        if (sym.n_strx == 0) continue; // no name, skip
        if (!sym.undf()) continue; // not an import, skip
        const new_index = @intCast(u32, imports.items.len);
        var out_sym = sym;
        out_sym.n_strx = try self.strtab.insert(gpa, self.getSymbolName(global));
        try imports.append(out_sym);
        try imports_table.putNoClobber(global, new_index);
    }

    const nlocals = @intCast(u32, locals.items.len);
    const nexports = @intCast(u32, exports.items.len);
    const nimports = @intCast(u32, imports.items.len);
    const nsyms = nlocals + nexports + nimports;

    const seg = self.getLinkeditSegmentPtr();
    const offset = mem.alignForwardGeneric(
        u64,
        seg.fileoff + seg.filesize,
        @alignOf(macho.nlist_64),
    );
    const needed_size = nsyms * @sizeOf(macho.nlist_64);
    seg.filesize = offset + needed_size - seg.fileoff;

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(needed_size);
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(locals.items));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(exports.items));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(imports.items));

    log.debug("writing symtab from 0x{x} to 0x{x}", .{ offset, offset + needed_size });
    try self.base.file.pwriteAll(buffer.items, offset);

    lc.symoff = @intCast(u32, offset);
    lc.nsyms = nsyms;

    return SymtabCtx{
        .nlocalsym = nlocals,
        .nextdefsym = nexports,
        .nundefsym = nimports,
        .imports_table = imports_table,
    };
}

fn writeStrtab(self: *MachO, lc: *macho.symtab_command) !void {
    const seg = self.getLinkeditSegmentPtr();
    const offset = mem.alignForwardGeneric(u64, seg.fileoff + seg.filesize, @alignOf(u64));
    const needed_size = self.strtab.buffer.items.len;
    seg.filesize = offset + needed_size - seg.fileoff;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ offset, offset + needed_size });

    try self.base.file.pwriteAll(self.strtab.buffer.items, offset);

    lc.stroff = @intCast(u32, offset);
    lc.strsize = @intCast(u32, needed_size);
}

const SymtabCtx = struct {
    nlocalsym: u32,
    nextdefsym: u32,
    nundefsym: u32,
    imports_table: std.AutoHashMap(SymbolWithLoc, u32),
};

fn writeDysymtab(self: *MachO, ctx: SymtabCtx, lc: *macho.dysymtab_command) !void {
    const gpa = self.base.allocator;
    const nstubs = @intCast(u32, self.stubs.count());
    const ngot_entries = @intCast(u32, self.got_entries.count());
    const nindirectsyms = nstubs * 2 + ngot_entries;
    const iextdefsym = ctx.nlocalsym;
    const iundefsym = iextdefsym + ctx.nextdefsym;

    const seg = self.getLinkeditSegmentPtr();
    const offset = mem.alignForwardGeneric(u64, seg.fileoff + seg.filesize, @alignOf(u64));
    const needed_size = nindirectsyms * @sizeOf(u32);
    seg.filesize = offset + needed_size - seg.fileoff;

    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{ offset, offset + needed_size });

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();
    try buf.ensureTotalCapacity(needed_size);
    const writer = buf.writer();

    if (self.getSectionByName("__TEXT", "__stubs")) |sect_id| {
        const stubs = &self.sections.items(.header)[sect_id];
        stubs.reserved1 = 0;
        for (self.stubs.keys()) |target| {
            const sym_index = self.stubs.get(target).?;
            assert(sym_index > 0);
            const atom_sym = self.getSymbol(.{ .sym_index = sym_index, .file = null });
            if (atom_sym.n_desc == N_DESC_GCED) continue;
            const target_sym = self.getSymbol(target);
            assert(target_sym.undf());
            try writer.writeIntLittle(u32, iundefsym + ctx.imports_table.get(target).?);
        }
    }

    if (self.getSectionByName("__DATA_CONST", "__got")) |sect_id| {
        const got = &self.sections.items(.header)[sect_id];
        got.reserved1 = nstubs;
        for (self.got_entries.keys()) |target| {
            const sym_index = self.got_entries.get(target).?;
            assert(sym_index > 0);
            const atom_sym = self.getSymbol(.{ .sym_index = sym_index, .file = null });
            if (atom_sym.n_desc == N_DESC_GCED) continue;
            const target_sym = self.getSymbol(target);
            if (target_sym.undf()) {
                try writer.writeIntLittle(u32, iundefsym + ctx.imports_table.get(target).?);
            } else {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            }
        }
    }

    if (self.getSectionByName("__DATA", "__la_symbol_ptr")) |sect_id| {
        const la_symbol_ptr = &self.sections.items(.header)[sect_id];
        la_symbol_ptr.reserved1 = nstubs + ngot_entries;
        for (self.stubs.keys()) |target| {
            const sym_index = self.stubs.get(target).?;
            assert(sym_index > 0);
            const atom_sym = self.getSymbol(.{ .sym_index = sym_index, .file = null });
            if (atom_sym.n_desc == N_DESC_GCED) continue;
            const target_sym = self.getSymbol(target);
            assert(target_sym.undf());
            try writer.writeIntLittle(u32, iundefsym + ctx.imports_table.get(target).?);
        }
    }

    assert(buf.items.len == needed_size);
    try self.base.file.pwriteAll(buf.items, offset);

    lc.nlocalsym = ctx.nlocalsym;
    lc.iextdefsym = iextdefsym;
    lc.nextdefsym = ctx.nextdefsym;
    lc.iundefsym = iundefsym;
    lc.nundefsym = ctx.nundefsym;
    lc.indirectsymoff = @intCast(u32, offset);
    lc.nindirectsyms = nindirectsyms;
}

fn writeCodeSignaturePadding(
    self: *MachO,
    code_sig: *CodeSignature,
    ncmds: *u32,
    lc_writer: anytype,
) !u32 {
    const seg = self.getLinkeditSegmentPtr();
    // Code signature data has to be 16-bytes aligned for Apple tools to recognize the file
    // https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/libstuff/checkout.c#L271
    const offset = mem.alignForwardGeneric(u64, seg.fileoff + seg.filesize, 16);
    const needed_size = code_sig.estimateSize(offset);
    seg.filesize = offset + needed_size - seg.fileoff;
    seg.vmsize = mem.alignForwardGeneric(u64, seg.filesize, self.page_size);
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ offset, offset + needed_size });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.base.file.pwriteAll(&[_]u8{0}, offset + needed_size - 1);

    try lc_writer.writeStruct(macho.linkedit_data_command{
        .cmd = .CODE_SIGNATURE,
        .cmdsize = @sizeOf(macho.linkedit_data_command),
        .dataoff = @intCast(u32, offset),
        .datasize = @intCast(u32, needed_size),
    });
    ncmds.* += 1;

    return @intCast(u32, offset);
}

fn writeCodeSignature(self: *MachO, code_sig: *CodeSignature, offset: u32) !void {
    const seg_id = self.getSegmentByName("__TEXT").?;
    const seg = self.segments.items[seg_id];

    var buffer = std.ArrayList(u8).init(self.base.allocator);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(code_sig.size());
    try code_sig.writeAdhocSignature(self.base.allocator, .{
        .file = self.base.file,
        .exec_seg_base = seg.fileoff,
        .exec_seg_limit = seg.filesize,
        .file_size = offset,
        .output_mode = self.options.output_mode,
    }, buffer.writer());
    assert(buffer.items.len == code_sig.size());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{
        offset,
        offset + buffer.items.len,
    });

    try self.base.file.pwriteAll(buffer.items, offset);
}

/// Writes Mach-O file header.
fn writeHeader(self: *MachO, ncmds: u32, sizeofcmds: u32) !void {
    var header: macho.mach_header_64 = .{};
    header.flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE | macho.MH_TWOLEVEL;

    switch (self.options.target.cpu_arch.?) {
        .aarch64 => {
            header.cputype = macho.CPU_TYPE_ARM64;
            header.cpusubtype = macho.CPU_SUBTYPE_ARM_ALL;
        },
        .x86_64 => {
            header.cputype = macho.CPU_TYPE_X86_64;
            header.cpusubtype = macho.CPU_SUBTYPE_X86_64_ALL;
        },
        else => return error.UnsupportedCpuArchitecture,
    }

    switch (self.options.output_mode) {
        .exe => {
            header.filetype = macho.MH_EXECUTE;
        },
        .lib => {
            // By this point, it can only be a dylib.
            header.filetype = macho.MH_DYLIB;
            header.flags |= macho.MH_NO_REEXPORTED_DYLIBS;
        },
    }

    if (self.getSectionByName("__DATA", "__thread_vars")) |sect_id| {
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
        if (self.sections.items(.header)[sect_id].size > 0) {
            header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
        }
    }

    header.ncmds = ncmds;
    header.sizeofcmds = sizeofcmds;

    log.debug("writing Mach-O header {}", .{header});

    try self.base.file.pwriteAll(mem.asBytes(&header), 0);
}

pub fn addRelocation(self: *MachO, atom_index: AtomIndex, reloc: Atom.Relocation) !void {
    return self.addRelocations(atom_index, 1, .{reloc});
}

pub fn addRelocations(
    self: *MachO,
    atom_index: AtomIndex,
    comptime count: comptime_int,
    relocs: [count]Atom.Relocation,
) !void {
    const gpa = self.base.allocator;
    const target = self.options.target;
    const gop = try self.relocs.getOrPut(gpa, atom_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    try gop.value_ptr.ensureUnusedCapacity(gpa, count);
    for (relocs) |reloc| {
        log.debug("  (adding reloc of type {s} to target %{d})", .{
            reloc.fmtType(target),
            reloc.target.sym_index,
        });
        gop.value_ptr.appendAssumeCapacity(reloc);
    }
}

pub fn addRebase(self: *MachO, atom_index: AtomIndex, offset: u32) !void {
    const gpa = self.base.allocator;
    const atom = self.getAtom(atom_index);
    log.debug("  (adding rebase at offset 0x{x} in %{d})", .{ offset, atom.sym_index });
    const gop = try self.rebases.getOrPut(gpa, atom_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    try gop.value_ptr.append(gpa, offset);
}

pub fn addBinding(self: *MachO, atom_index: AtomIndex, binding: Atom.Binding) !void {
    const gpa = self.base.allocator;
    const atom = self.getAtom(atom_index);
    log.debug("  (adding binding to symbol {s} at offset 0x{x} in %{d})", .{
        self.getSymbolName(binding.target),
        binding.offset,
        atom.sym_index,
    });
    const gop = try self.bindings.getOrPut(gpa, atom_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    try gop.value_ptr.append(gpa, binding);
}

pub fn freeAtom(self: *MachO, atom_index: AtomIndex) void {
    const gpa = self.base.allocator;
    if (self.relocs.getPtr(atom_index)) |relocs| {
        relocs.deinit(gpa);
    }
    if (self.rebases.getPtr(atom_index)) |rebases| {
        rebases.deinit(gpa);
    }
    if (self.bindings.getPtr(atom_index)) |bindings| {
        bindings.deinit(gpa);
    }
    _ = self.relocs.remove(atom_index);
    _ = self.rebases.remove(atom_index);
    _ = self.bindings.remove(atom_index);
}

pub fn makeStaticString(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    assert(bytes.len <= buf.len);
    mem.copy(u8, &buf, bytes);
    return buf;
}

pub inline fn getAtomPtr(self: *MachO, atom_index: AtomIndex) *Atom {
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub inline fn getAtom(self: MachO, atom_index: AtomIndex) Atom {
    assert(atom_index < self.atoms.items.len);
    return self.atoms.items[atom_index];
}

fn getSegmentByName(self: MachO, segname: []const u8) ?u8 {
    for (self.segments.items) |seg, i| {
        if (mem.eql(u8, segname, seg.segName())) return @intCast(u8, i);
    } else return null;
}

pub inline fn getSegment(self: MachO, sect_id: u8) macho.segment_command_64 {
    const index = self.sections.items(.segment_index)[sect_id];
    return self.segments.items[index];
}

pub inline fn getSegmentPtr(self: *MachO, sect_id: u8) *macho.segment_command_64 {
    const index = self.sections.items(.segment_index)[sect_id];
    return &self.segments.items[index];
}

pub inline fn getLinkeditSegmentPtr(self: *MachO) *macho.segment_command_64 {
    assert(self.segments.items.len > 0);
    const seg = &self.segments.items[self.segments.items.len - 1];
    assert(mem.eql(u8, seg.segName(), "__LINKEDIT"));
    return seg;
}

pub fn getSectionByName(self: MachO, segname: []const u8, sectname: []const u8) ?u8 {
    // TODO investigate caching with a hashmap
    for (self.sections.items(.header)) |header, i| {
        if (mem.eql(u8, header.segName(), segname) and mem.eql(u8, header.sectName(), sectname))
            return @intCast(u8, i);
    } else return null;
}

pub fn getSectionIndexes(self: MachO, segment_index: u8) struct { start: u8, end: u8 } {
    var start: u8 = 0;
    const nsects = for (self.segments.items) |seg, i| {
        if (i == segment_index) break @intCast(u8, seg.nsects);
        start += @intCast(u8, seg.nsects);
    } else 0;
    return .{ .start = start, .end = start + nsects };
}

pub fn symbolIsTemp(self: *MachO, sym_with_loc: SymbolWithLoc) bool {
    const sym = self.getSymbol(sym_with_loc);
    if (!sym.sect()) return false;
    if (sym.ext()) return false;
    const sym_name = self.getSymbolName(sym_with_loc);
    return mem.startsWith(u8, sym_name, "l") or mem.startsWith(u8, sym_name, "L");
}

/// Returns pointer-to-symbol described by `sym_with_loc` descriptor.
pub fn getSymbolPtr(self: *MachO, sym_with_loc: SymbolWithLoc) *macho.nlist_64 {
    if (sym_with_loc.file) |file| {
        const object = &self.objects.items[file];
        return &object.symtab.items[sym_with_loc.sym_index];
    } else {
        return &self.locals.items[sym_with_loc.sym_index];
    }
}

/// Returns symbol described by `sym_with_loc` descriptor.
pub fn getSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) macho.nlist_64 {
    return self.getSymbolPtr(sym_with_loc).*;
}

/// Returns name of the symbol described by `sym_with_loc` descriptor.
pub fn getSymbolName(self: *MachO, sym_with_loc: SymbolWithLoc) []const u8 {
    if (sym_with_loc.file) |file| {
        const object = self.objects.items[file];
        const sym = object.symtab.items[sym_with_loc.sym_index];
        return object.getString(sym.n_strx);
    } else {
        const sym = self.locals.items[sym_with_loc.sym_index];
        return self.strtab.get(sym.n_strx).?;
    }
}

/// Returns atom if there is an atom referenced by the symbol described by `sym_with_loc` descriptor.
/// Returns null on failure.
pub fn getAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    if (sym_with_loc.file) |file| {
        const object = self.objects.items[file];
        return object.getAtomIndexForSymbol(sym_with_loc.sym_index);
    } else {
        return self.atom_by_index_table.get(sym_with_loc.sym_index);
    }
}

/// Returns GOT atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getGotAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    const sym_index = self.got_entries.get(sym_with_loc) orelse return null;
    return self.getAtomIndexForSymbol(.{ .sym_index = sym_index, .file = null });
}

/// Returns stubs atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getStubsAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    const sym_index = self.stubs.get(sym_with_loc) orelse return null;
    return self.getAtomIndexForSymbol(.{ .sym_index = sym_index, .file = null });
}

/// Returns TLV pointer atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getTlvPtrAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    const sym_index = self.tlv_ptr_entries.get(sym_with_loc) orelse return null;
    return self.getAtomIndexForSymbol(.{ .sym_index = sym_index, .file = null });
}

/// Returns symbol location corresponding to the set entrypoint.
/// Asserts output mode is executable.
pub fn getEntryPoint(self: MachO) error{MissingMainEntrypoint}!SymbolWithLoc {
    assert(self.options.output_mode == .exe);
    const entry_name = self.options.entry orelse "_main";
    const global = self.globals.get(entry_name) orelse {
        log.err("entrypoint '{s}' not found", .{entry_name});
        return error.MissingMainEntrypoint;
    };
    return global;
}

pub fn findFirst(comptime T: type, haystack: []align(1) const T, start: usize, predicate: anytype) usize {
    if (!@hasDecl(@TypeOf(predicate), "predicate"))
        @compileError("Predicate is required to define fn predicate(@This(), T) bool");

    if (start == haystack.len) return start;

    var i = start;
    while (i < haystack.len) : (i += 1) {
        if (predicate.predicate(haystack[i])) break;
    }
    return i;
}

pub fn generateSymbolStabs(
    self: *MachO,
    object: Object,
    locals: *std.ArrayList(macho.nlist_64),
) !void {
    assert(!self.options.strip);

    log.debug("parsing debug info in '{s}'", .{object.name});

    const gpa = self.base.allocator;
    var debug_info = object.parseDwarfInfo();
    defer debug_info.deinit(gpa);
    try dwarf.openDwarfDebugInfo(&debug_info, gpa);

    // We assume there is only one CU.
    const compile_unit = debug_info.findCompileUnit(0x0) catch |err| switch (err) {
        error.MissingDebugInfo => {
            // TODO audit cases with missing debug info and audit our dwarf.zig module.
            log.debug("invalid or missing debug info in {s}; skipping", .{object.name});
            return;
        },
        else => |e| return e,
    };
    const tu_name = try compile_unit.die.getAttrString(&debug_info, dwarf.AT.name, debug_info.debug_str, compile_unit.*);
    const tu_comp_dir = try compile_unit.die.getAttrString(&debug_info, dwarf.AT.comp_dir, debug_info.debug_str, compile_unit.*);

    // Open scope
    try locals.ensureUnusedCapacity(3);
    locals.appendAssumeCapacity(.{
        .n_strx = try self.strtab.insert(gpa, tu_comp_dir),
        .n_type = macho.N_SO,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    locals.appendAssumeCapacity(.{
        .n_strx = try self.strtab.insert(gpa, tu_name),
        .n_type = macho.N_SO,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    locals.appendAssumeCapacity(.{
        .n_strx = try self.strtab.insert(gpa, object.name),
        .n_type = macho.N_OSO,
        .n_sect = 0,
        .n_desc = 1,
        .n_value = object.mtime,
    });

    var stabs_buf: [4]macho.nlist_64 = undefined;

    for (object.atoms.items) |atom_index| {
        const atom = self.getAtom(atom_index);
        const stabs = try self.generateSymbolStabsForSymbol(
            atom.getSymbolWithLoc(),
            debug_info,
            &stabs_buf,
        );
        try locals.appendSlice(stabs);

        for (atom.contained.items) |sym_at_off| {
            const sym_loc = SymbolWithLoc{
                .sym_index = sym_at_off.sym_index,
                .file = atom.file,
            };
            const contained_stabs = try self.generateSymbolStabsForSymbol(
                sym_loc,
                debug_info,
                &stabs_buf,
            );
            try locals.appendSlice(contained_stabs);
        }
    }

    // Close scope
    try locals.append(.{
        .n_strx = 0,
        .n_type = macho.N_SO,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
}

fn generateSymbolStabsForSymbol(
    self: *MachO,
    sym_loc: SymbolWithLoc,
    debug_info: dwarf.DwarfInfo,
    buf: *[4]macho.nlist_64,
) ![]const macho.nlist_64 {
    const gpa = self.base.allocator;
    const object = self.objects.items[sym_loc.file.?];
    const sym = self.getSymbol(sym_loc);
    const sym_name = self.getSymbolName(sym_loc);

    if (sym.n_strx == 0) return buf[0..0];
    if (sym.n_desc == N_DESC_GCED) return buf[0..0];
    if (self.symbolIsTemp(sym_loc)) return buf[0..0];

    const source_sym = object.getSourceSymbol(sym_loc.sym_index) orelse return buf[0..0];
    const size: ?u64 = size: {
        if (source_sym.tentative()) break :size null;
        for (debug_info.func_list.items) |func| {
            if (func.pc_range) |range| {
                if (source_sym.n_value >= range.start and source_sym.n_value < range.end) {
                    break :size range.end - range.start;
                }
            }
        }
        break :size null;
    };

    if (size) |ss| {
        buf[0] = .{
            .n_strx = 0,
            .n_type = macho.N_BNSYM,
            .n_sect = sym.n_sect,
            .n_desc = 0,
            .n_value = sym.n_value,
        };
        buf[1] = .{
            .n_strx = try self.strtab.insert(gpa, sym_name),
            .n_type = macho.N_FUN,
            .n_sect = sym.n_sect,
            .n_desc = 0,
            .n_value = sym.n_value,
        };
        buf[2] = .{
            .n_strx = 0,
            .n_type = macho.N_FUN,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = ss,
        };
        buf[3] = .{
            .n_strx = 0,
            .n_type = macho.N_ENSYM,
            .n_sect = sym.n_sect,
            .n_desc = 0,
            .n_value = ss,
        };
        return buf;
    } else {
        buf[0] = .{
            .n_strx = try self.strtab.insert(gpa, sym_name),
            .n_type = macho.N_STSYM,
            .n_sect = sym.n_sect,
            .n_desc = 0,
            .n_value = sym.n_value,
        };
        return buf[0..1];
    }
}

fn logSegments(self: *MachO) void {
    log.debug("segments:", .{});
    for (self.segments.items) |segment, i| {
        log.debug("  segment({d}): {s} @{x} ({x}), sizeof({x})", .{
            i,
            segment.segName(),
            segment.fileoff,
            segment.vmaddr,
            segment.vmsize,
        });
    }
}

fn logSections(self: *MachO) void {
    log.debug("sections:", .{});
    for (self.sections.items(.header)) |header, i| {
        log.debug("  sect({d}): {s},{s} @{x} ({x}), sizeof({x})", .{
            i + 1,
            header.segName(),
            header.sectName(),
            header.offset,
            header.addr,
            header.size,
        });
    }
}

fn logSymAttributes(sym: macho.nlist_64, buf: *[9]u8) []const u8 {
    mem.set(u8, buf[0..4], '_');
    mem.set(u8, buf[4..], ' ');
    if (sym.sect()) {
        buf[0] = 's';
    }
    if (sym.ext()) {
        if (sym.weakDef() or sym.pext()) {
            buf[1] = 'w';
        } else {
            buf[1] = 'e';
        }
    }
    if (sym.tentative()) {
        buf[2] = 't';
    }
    if (sym.undf()) {
        buf[3] = 'u';
    }
    if (sym.n_desc == N_DESC_GCED) {
        mem.copy(u8, buf[5..], "DEAD");
    }
    return buf[0..];
}

fn logSymtab(self: *MachO) void {
    var buf: [9]u8 = undefined;

    log.debug("symtab:", .{});
    for (self.objects.items) |object, id| {
        log.debug("  object({d}): {s}", .{ id, object.name });
        for (object.symtab.items) |sym, sym_id| {
            const where = if (sym.undf() and !sym.tentative()) "ord" else "sect";
            const def_index = if (sym.undf() and !sym.tentative())
                @divTrunc(sym.n_desc, macho.N_SYMBOL_RESOLVER)
            else
                sym.n_sect;
            log.debug("    %{d}: {s} @{x} in {s}({d}), {s}", .{
                sym_id,
                object.getString(sym.n_strx),
                sym.n_value,
                where,
                def_index,
                logSymAttributes(sym, &buf),
            });
        }
    }
    log.debug("  object(null)", .{});
    for (self.locals.items) |sym, sym_id| {
        const where = if (sym.undf() and !sym.tentative()) "ord" else "sect";
        const def_index = if (sym.undf() and !sym.tentative())
            @divTrunc(sym.n_desc, macho.N_SYMBOL_RESOLVER)
        else
            sym.n_sect;
        log.debug("    %{d}: {s} @{x} in {s}({d}), {s}", .{
            sym_id,
            self.strtab.get(sym.n_strx).?,
            sym.n_value,
            where,
            def_index,
            logSymAttributes(sym, &buf),
        });
    }

    log.debug("globals table:", .{});
    for (self.globals.keys()) |name, id| {
        const value = self.globals.values()[id];
        log.debug("  {s} => %{d} in object({?})", .{ name, value.sym_index, value.file });
    }

    log.debug("GOT entries:", .{});
    for (self.got_entries.keys()) |target, i| {
        const atom_sym = self.getSymbol(.{ .sym_index = self.got_entries.get(target).?, .file = null });
        if (atom_sym.n_desc == N_DESC_GCED) continue;
        const target_sym = self.getSymbol(target);
        if (target_sym.undf()) {
            log.debug("  {d}@{x} => import('{s}')", .{
                i,
                atom_sym.n_value,
                self.getSymbolName(target),
            });
        } else {
            log.debug("  {d}@{x} => local(%{d}) in object({?}) {s}", .{
                i,
                atom_sym.n_value,
                target.sym_index,
                target.file,
                logSymAttributes(target_sym, &buf),
            });
        }
    }

    log.debug("__thread_ptrs entries:", .{});
    for (self.tlv_ptr_entries.keys()) |target, i| {
        const atom_sym = self.getSymbol(.{ .sym_index = self.tlv_ptr_entries.get(target).?, .file = null });
        if (atom_sym.n_desc == N_DESC_GCED) continue;
        const target_sym = self.getSymbol(target);
        assert(target_sym.undf());
        log.debug("  {d}@{x} => import('{s}')", .{
            i,
            atom_sym.n_value,
            self.getSymbolName(target),
        });
    }

    log.debug("stubs entries:", .{});
    for (self.stubs.keys()) |target, i| {
        const target_sym = self.getSymbol(target);
        const atom_sym = self.getSymbol(.{ .sym_index = self.stubs.get(target).?, .file = null });
        assert(target_sym.undf());
        log.debug("  {d}@{x} => import('{s}')", .{
            i,
            atom_sym.n_value,
            self.getSymbolName(target),
        });
    }
}

fn logAtoms(self: *MachO) void {
    log.debug("atoms:", .{});
    const slice = self.sections.slice();
    for (slice.items(.first_atom_index)) |first_atom_index, sect_id| {
        var atom_index = first_atom_index;
        var atom = self.getAtom(atom_index);

        const header = slice.items(.header)[sect_id];

        log.debug("{s},{s}", .{ header.segName(), header.sectName() });

        while (true) {
            self.logAtom(atom_index);

            if (atom.next_index) |next_index| {
                atom_index = next_index;
                atom = self.getAtom(atom_index);
            } else break;
        }
    }
}

pub fn logAtom(self: *MachO, atom_index: AtomIndex) void {
    const atom = self.getAtom(atom_index);
    const sym = self.getSymbol(atom.getSymbolWithLoc());
    const sym_name = self.getSymbolName(atom.getSymbolWithLoc());
    log.debug("  ATOM(%{d}, '{s}') @ {x} (sizeof({x}), alignof({x})) in object({?}) in sect({d})", .{
        atom.sym_index,
        sym_name,
        sym.n_value,
        atom.size,
        atom.alignment,
        atom.file,
        sym.n_sect,
    });

    for (atom.contained.items) |sym_off| {
        const inner_sym = self.getSymbol(.{
            .sym_index = sym_off.sym_index,
            .file = atom.file,
        });
        const inner_sym_name = self.getSymbolName(.{
            .sym_index = sym_off.sym_index,
            .file = atom.file,
        });
        log.debug("    (%{d}, '{s}') @ {x} ({x})", .{
            sym_off.sym_index,
            inner_sym_name,
            inner_sym.n_value,
            sym_off.offset,
        });
    }
}
