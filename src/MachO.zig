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

const Allocator = mem.Allocator;
const Archive = @import("MachO/Archive.zig");
const Atom = @import("MachO/Atom.zig");
const CodeSignature = @import("MachO/CodeSignature.zig");
const Dylib = @import("MachO/Dylib.zig");
const Object = @import("MachO/Object.zig");
pub const Options = @import("MachO/Options.zig");
const LibStub = @import("tapi.zig").LibStub;
const LoadCommand = macho.LoadCommand;
const SegmentCommand = macho.SegmentCommand;
const StringTable = @import("strtab.zig").StringTable;
const Trie = @import("MachO/Trie.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.macho;

pub const N_DESC_GCED: u16 = @bitCast(u16, @as(i16, -1));

base: Zld,
options: Options,

/// Page size is dependent on the target cpu architecture.
/// For x86_64 that's 4KB, whereas for aarch64, that's 16KB.
page_size: u16,

/// Code signature (if any)
code_signature: ?CodeSignature = null,

objects: std.ArrayListUnmanaged(Object) = .{},
archives: std.ArrayListUnmanaged(Archive) = .{},

dylibs: std.ArrayListUnmanaged(Dylib) = .{},
dylibs_map: std.StringHashMapUnmanaged(u16) = .{},
referenced_dylibs: std.AutoArrayHashMapUnmanaged(u16, void) = .{},

load_commands: std.ArrayListUnmanaged(LoadCommand) = .{},

pagezero_segment_cmd_index: ?u16 = null,
text_segment_cmd_index: ?u16 = null,
data_const_segment_cmd_index: ?u16 = null,
data_segment_cmd_index: ?u16 = null,
linkedit_segment_cmd_index: ?u16 = null,
dyld_info_cmd_index: ?u16 = null,
symtab_cmd_index: ?u16 = null,
dysymtab_cmd_index: ?u16 = null,
dylinker_cmd_index: ?u16 = null,
data_in_code_cmd_index: ?u16 = null,
function_starts_cmd_index: ?u16 = null,
main_cmd_index: ?u16 = null,
dylib_id_cmd_index: ?u16 = null,
source_version_cmd_index: ?u16 = null,
build_version_cmd_index: ?u16 = null,
uuid_cmd_index: ?u16 = null,
code_signature_cmd_index: ?u16 = null,

// __TEXT segment sections
text_section_index: ?u16 = null,
stubs_section_index: ?u16 = null,
stub_helper_section_index: ?u16 = null,
text_const_section_index: ?u16 = null,
cstring_section_index: ?u16 = null,
ustring_section_index: ?u16 = null,
gcc_except_tab_section_index: ?u16 = null,
unwind_info_section_index: ?u16 = null,
eh_frame_section_index: ?u16 = null,

objc_methlist_section_index: ?u16 = null,
objc_methname_section_index: ?u16 = null,
objc_methtype_section_index: ?u16 = null,
objc_classname_section_index: ?u16 = null,

// __DATA_CONST segment sections
got_section_index: ?u16 = null,
mod_init_func_section_index: ?u16 = null,
mod_term_func_section_index: ?u16 = null,
data_const_section_index: ?u16 = null,

objc_cfstring_section_index: ?u16 = null,
objc_classlist_section_index: ?u16 = null,
objc_imageinfo_section_index: ?u16 = null,

// __DATA segment sections
tlv_section_index: ?u16 = null,
tlv_data_section_index: ?u16 = null,
tlv_bss_section_index: ?u16 = null,
tlv_ptrs_section_index: ?u16 = null,
la_symbol_ptr_section_index: ?u16 = null,
data_section_index: ?u16 = null,
bss_section_index: ?u16 = null,

objc_const_section_index: ?u16 = null,
objc_selrefs_section_index: ?u16 = null,
objc_classrefs_section_index: ?u16 = null,
objc_data_section_index: ?u16 = null,

rustc_section_index: ?u16 = null,
rustc_section_size: u64 = 0,

locals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
globals: std.StringArrayHashMapUnmanaged(SymbolWithLoc) = .{},
unresolved: std.AutoArrayHashMapUnmanaged(u32, void) = .{},

dyld_stub_binder_index: ?u32 = null,
dyld_private_atom: ?*Atom = null,
stub_helper_preamble_atom: ?*Atom = null,

strtab: StringTable(.strtab) = .{},

tlv_ptr_entries: std.ArrayListUnmanaged(Entry) = .{},
tlv_ptr_entries_table: std.AutoHashMapUnmanaged(SymbolWithLoc, u32) = .{},

got_entries: std.ArrayListUnmanaged(Entry) = .{},
got_entries_table: std.AutoHashMapUnmanaged(SymbolWithLoc, u32) = .{},

stubs: std.ArrayListUnmanaged(Entry) = .{},
stubs_table: std.AutoHashMapUnmanaged(SymbolWithLoc, u32) = .{},

section_ordinals: std.AutoArrayHashMapUnmanaged(MatchingSection, void) = .{},

/// Pointer to the last allocated atom
atoms: std.AutoHashMapUnmanaged(MatchingSection, *Atom) = .{},

/// List of atoms that are owned directly by the linker such as synthetic GOT atoms, etc.
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},

/// Table of atoms indexed by the symbol index.
atom_by_index_table: std.AutoHashMapUnmanaged(u32, *Atom) = .{},

const Entry = struct {
    target: SymbolWithLoc,
    // Index into the synthetic symbol table (i.e., file == null).
    sym_index: u32,

    pub fn getSymbol(entry: Entry, macho_file: *MachO) macho.nlist_64 {
        return macho_file.getSymbol(.{ .sym_index = entry.sym_index, .file = null });
    }

    pub fn getSymbolPtr(entry: Entry, macho_file: *MachO) *macho.nlist_64 {
        return macho_file.getSymbolPtr(.{ .sym_index = entry.sym_index, .file = null });
    }

    pub fn getAtom(entry: Entry, macho_file: *MachO) *Atom {
        return macho_file.getAtomForSymbol(.{ .sym_index = entry.sym_index, .file = null }).?;
    }

    pub fn getName(entry: Entry, macho_file: *MachO) []const u8 {
        return macho_file.getSymbolName(.{ .sym_index = entry.sym_index, .file = null });
    }
};

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
    const os_tag = options.target.os_tag.?;
    const abi = options.target.abi.?;
    const page_size: u16 = if (cpu_arch == .aarch64) 0x4000 else 0x1000;
    // Adhoc code signature is required when targeting aarch64-macos either directly or indirectly via the simulator
    // ABI such as aarch64-ios-simulator, etc.
    const requires_adhoc_codesig = cpu_arch == .aarch64 and (os_tag == .macos or abi == .simulator);

    self.* = .{
        .base = .{
            .tag = .macho,
            .allocator = gpa,
            .file = undefined,
        },
        .options = options,
        .page_size = page_size,
        .code_signature = if (requires_adhoc_codesig)
            CodeSignature.init(page_size)
        else
            null,
    };

    return self;
}

pub fn flush(self: *MachO) !void {
    const gpa = self.base.allocator;
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const syslibroot = self.options.syslibroot;

    try self.strtab.buffer.append(gpa, 0);
    try self.populateMetadata();

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

    // rpaths
    var rpath_table = std.StringArrayHashMap(void).init(arena);
    for (self.options.rpath_list) |rpath| {
        if (rpath_table.contains(rpath)) continue;
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.rpath_command) + rpath.len + 1,
            @sizeOf(u64),
        ));
        var rpath_cmd = macho.emptyGenericCommandWithData(macho.rpath_command{
            .cmdsize = cmdsize,
            .path = @sizeOf(macho.rpath_command),
        });
        rpath_cmd.data = try gpa.alloc(u8, cmdsize - rpath_cmd.inner.path);
        mem.set(u8, rpath_cmd.data, 0);
        mem.copy(u8, rpath_cmd.data, rpath);
        try self.load_commands.append(gpa, .{ .rpath = rpath_cmd });
        try rpath_table.putNoClobber(rpath, {});
    }

    // code signature and entitlements
    if (self.options.entitlements) |path| {
        if (self.code_signature) |*csig| {
            try csig.addEntitlements(gpa, path);
            csig.code_directory.ident = self.options.emit.sub_path;
        } else {
            var csig = CodeSignature.init(self.page_size);
            try csig.addEntitlements(gpa, path);
            csig.code_directory.ident = self.options.emit.sub_path;
            self.code_signature = csig;
        }
    }

    var dependent_libs = std.fifo.LinearFifo(struct {
        id: Dylib.Id,
        parent: u16,
    }, .Dynamic).init(gpa);
    defer dependent_libs.deinit();
    try self.parsePositionals(positionals.items, syslibroot, &dependent_libs);
    try self.parseAndForceLoadStaticArchives(must_link_archives.keys());
    try self.parseLibs(libs.keys(), libs.values(), syslibroot, &dependent_libs);
    try self.parseDependentLibs(syslibroot, &dependent_libs);

    for (self.objects.items) |*object, object_id| {
        try self.resolveSymbolsInObject(object, @intCast(u16, object_id));
    }

    try self.resolveSymbolsInArchives();
    try self.resolveDyldStubBinder();
    try self.createDyldPrivateAtom();
    try self.createStubHelperPreambleAtom();
    try self.resolveSymbolsInDylibs();
    try self.createMhExecuteHeaderSymbol();
    try self.createDsoHandleSymbol();
    try self.addCodeSignatureLC();
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

    try self.createTentativeDefAtoms();

    for (self.objects.items) |*object, object_id| {
        try object.splitIntoAtoms(self, @intCast(u32, object_id));
    }

    if (self.options.dead_strip) {
        try dead_strip.gcAtoms(self);
    }

    try self.pruneAndSortSections();
    try self.allocateSegments();
    try self.allocateSymbols();

    try self.allocateSpecialSymbols();

    if (build_options.enable_logging) {
        self.logSymtab();
        self.logSectionOrdinals();
        self.logAtoms();
    }

    try self.writeAtoms();

    if (self.rustc_section_index) |id| {
        const sect = self.getSectionPtr(.{
            .seg = self.data_segment_cmd_index.?,
            .sect = id,
        });
        sect.size = self.rustc_section_size;
    }

    try self.setEntryPoint();
    try self.writeLinkeditSegment();

    if (self.code_signature) |*csig| {
        csig.clear(gpa);
        csig.code_directory.ident = self.options.emit.sub_path;
        // Preallocate space for the code signature.
        // We need to do this at this stage so that we have the load commands with proper values
        // written out to the file.
        // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
        // where the code signature goes into.
        try self.writeCodeSignaturePadding(csig);
    }

    try self.writeLoadCommands();
    try self.writeHeader();

    if (self.code_signature) |*csig| {
        try self.writeCodeSignature(csig); // code signing always comes last
        const dir = self.options.emit.directory;
        const path = self.options.emit.sub_path;
        try dir.copyFile(path, dir, path, .{});
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
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    const mtime: u64 = mtime: {
        const stat = file.stat() catch break :mtime 0;
        break :mtime @intCast(u64, @divFloor(stat.mtime, 1_000_000_000));
    };

    var object = Object{
        .name = name,
        .file = file,
        .mtime = mtime,
    };

    object.parse(self.base.allocator, self.options.target.cpu_arch.?) catch |err| switch (err) {
        error.EndOfStream, error.NotObject => {
            object.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.objects.append(self.base.allocator, object);

    return true;
}

fn parseArchive(self: *MachO, path: []const u8, force_load: bool) !bool {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    var archive = Archive{
        .name = name,
        .file = file,
    };

    archive.parse(self.base.allocator, self.options.target.cpu_arch.?) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    if (force_load) {
        defer archive.deinit(self.base.allocator);
        // Get all offsets from the ToC
        var offsets = std.AutoArrayHashMap(u32, void).init(self.base.allocator);
        defer offsets.deinit();
        for (archive.toc.values()) |offs| {
            for (offs.items) |off| {
                _ = try offsets.getOrPut(off);
            }
        }
        for (offsets.keys()) |off| {
            const object = try self.objects.addOne(self.base.allocator);
            object.* = try archive.parseObject(self.base.allocator, self.options.target.cpu_arch.?, off);
        }
    } else {
        try self.archives.append(self.base.allocator, archive);
    }

    return true;
}

const ParseDylibError = error{
    OutOfMemory,
    EmptyStubFile,
    MismatchedCpuArchitecture,
    UnsupportedCpuArchitecture,
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
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    const dylib_id = @intCast(u16, self.dylibs.items.len);
    var dylib = Dylib{
        .name = name,
        .file = file,
        .weak = opts.weak,
    };

    dylib.parse(
        self.base.allocator,
        self.options.target.cpu_arch.?,
        dylib_id,
        dependent_libs,
    ) catch |err| switch (err) {
        error.EndOfStream, error.NotDylib => {
            try file.seekTo(0);

            var lib_stub = LibStub.loadFromFile(self.base.allocator, file) catch {
                dylib.deinit(self.base.allocator);
                return false;
            };
            defer lib_stub.deinit();

            try dylib.parseFromStub(
                self.base.allocator,
                self.options.target,
                lib_stub,
                dylib_id,
                dependent_libs,
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
            dylib.deinit(self.base.allocator);
            return false;
        }
    }

    const gop = try self.dylibs_map.getOrPut(self.base.allocator, dylib.id.?.name);
    if (gop.found_existing) {
        dylib.deinit(self.base.allocator);
        return true;
    }
    gop.value_ptr.* = dylib_id;
    try self.dylibs.append(self.base.allocator, dylib);

    const should_link_dylib_even_if_unreachable = blk: {
        if (self.options.dead_strip_dylibs and !opts.needed) break :blk false;
        break :blk !(opts.dependent or self.referenced_dylibs.contains(dylib_id));
    };

    if (should_link_dylib_even_if_unreachable) {
        try self.addLoadDylibLC(dylib_id);
        try self.referenced_dylibs.putNoClobber(self.base.allocator, dylib_id, {});
    }

    return true;
}

fn parsePositionals(self: *MachO, files: []const []const u8, syslibroot: ?[]const u8, dependent_libs: anytype) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };
        defer self.base.allocator.free(full_path);
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
            const path = try fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };
        defer self.base.allocator.free(full_path);
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

    while (dependent_libs.readItem()) |*dep_id| {
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

pub const MatchingSection = struct {
    seg: u16,
    sect: u16,

    pub fn eql(this: MatchingSection, other: struct {
        seg: ?u16,
        sect: ?u16,
    }) bool {
        const seg = other.seg orelse return false;
        const sect = other.sect orelse return false;
        return this.seg == seg and this.sect == sect;
    }
};

pub fn getMatchingSection(self: *MachO, sect: macho.section_64) !?MatchingSection {
    const segname = sect.segName();
    const sectname = sect.sectName();
    const res: ?MatchingSection = blk: {
        switch (sect.type_()) {
            macho.S_4BYTE_LITERALS, macho.S_8BYTE_LITERALS, macho.S_16BYTE_LITERALS => {
                if (self.text_const_section_index == null) {
                    self.text_const_section_index = try self.initSection(
                        self.text_segment_cmd_index.?,
                        "__const",
                        .{},
                    );
                }

                break :blk .{
                    .seg = self.text_segment_cmd_index.?,
                    .sect = self.text_const_section_index.?,
                };
            },
            macho.S_CSTRING_LITERALS => {
                if (mem.eql(u8, sectname, "__objc_methname")) {
                    // TODO it seems the common values within the sections in objects are deduplicated/merged
                    // on merging the sections' contents.
                    if (self.objc_methname_section_index == null) {
                        self.objc_methname_section_index = try self.initSection(
                            self.text_segment_cmd_index.?,
                            "__objc_methname",
                            .{},
                        );
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_methname_section_index.?,
                    };
                } else if (mem.eql(u8, sectname, "__objc_methtype")) {
                    if (self.objc_methtype_section_index == null) {
                        self.objc_methtype_section_index = try self.initSection(
                            self.text_segment_cmd_index.?,
                            "__objc_methtype",
                            .{},
                        );
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_methtype_section_index.?,
                    };
                } else if (mem.eql(u8, sectname, "__objc_classname")) {
                    if (self.objc_classname_section_index == null) {
                        self.objc_classname_section_index = try self.initSection(
                            self.text_segment_cmd_index.?,
                            "__objc_classname",
                            .{},
                        );
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_classname_section_index.?,
                    };
                }

                if (self.cstring_section_index == null) {
                    self.cstring_section_index = try self.initSection(
                        self.text_segment_cmd_index.?,
                        "__cstring",
                        .{
                            .flags = macho.S_CSTRING_LITERALS,
                        },
                    );
                }

                break :blk .{
                    .seg = self.text_segment_cmd_index.?,
                    .sect = self.cstring_section_index.?,
                };
            },
            macho.S_LITERAL_POINTERS => {
                if (mem.eql(u8, segname, "__DATA") and mem.eql(u8, sectname, "__objc_selrefs")) {
                    if (self.objc_selrefs_section_index == null) {
                        self.objc_selrefs_section_index = try self.initSection(
                            self.data_segment_cmd_index.?,
                            "__objc_selrefs",
                            .{
                                .flags = macho.S_LITERAL_POINTERS,
                            },
                        );
                    }

                    break :blk .{
                        .seg = self.data_segment_cmd_index.?,
                        .sect = self.objc_selrefs_section_index.?,
                    };
                } else {
                    // TODO investigate
                    break :blk null;
                }
            },
            macho.S_MOD_INIT_FUNC_POINTERS => {
                if (self.mod_init_func_section_index == null) {
                    self.mod_init_func_section_index = try self.initSection(
                        self.data_const_segment_cmd_index.?,
                        "__mod_init_func",
                        .{
                            .flags = macho.S_MOD_INIT_FUNC_POINTERS,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.mod_init_func_section_index.?,
                };
            },
            macho.S_MOD_TERM_FUNC_POINTERS => {
                if (self.mod_term_func_section_index == null) {
                    self.mod_term_func_section_index = try self.initSection(
                        self.data_const_segment_cmd_index.?,
                        "__mod_term_func",
                        .{
                            .flags = macho.S_MOD_TERM_FUNC_POINTERS,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.mod_term_func_section_index.?,
                };
            },
            macho.S_ZEROFILL => {
                if (self.bss_section_index == null) {
                    self.bss_section_index = try self.initSection(
                        self.data_segment_cmd_index.?,
                        "__bss",
                        .{
                            .flags = macho.S_ZEROFILL,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.bss_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_VARIABLES => {
                if (self.tlv_section_index == null) {
                    self.tlv_section_index = try self.initSection(
                        self.data_segment_cmd_index.?,
                        "__thread_vars",
                        .{
                            .flags = macho.S_THREAD_LOCAL_VARIABLES,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_VARIABLE_POINTERS => {
                if (self.tlv_ptrs_section_index == null) {
                    self.tlv_ptrs_section_index = try self.initSection(
                        self.data_segment_cmd_index.?,
                        "__thread_ptrs",
                        .{
                            .flags = macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_ptrs_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_REGULAR => {
                if (self.tlv_data_section_index == null) {
                    self.tlv_data_section_index = try self.initSection(
                        self.data_segment_cmd_index.?,
                        "__thread_data",
                        .{
                            .flags = macho.S_THREAD_LOCAL_REGULAR,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_data_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_ZEROFILL => {
                if (self.tlv_bss_section_index == null) {
                    self.tlv_bss_section_index = try self.initSection(
                        self.data_segment_cmd_index.?,
                        "__thread_bss",
                        .{
                            .flags = macho.S_THREAD_LOCAL_ZEROFILL,
                        },
                    );
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_bss_section_index.?,
                };
            },
            macho.S_COALESCED => {
                if (mem.eql(u8, "__TEXT", segname) and mem.eql(u8, "__eh_frame", sectname)) {
                    // TODO I believe __eh_frame is currently part of __unwind_info section
                    // in the latest ld64 output.
                    if (self.eh_frame_section_index == null) {
                        self.eh_frame_section_index = try self.initSection(
                            self.text_segment_cmd_index.?,
                            "__eh_frame",
                            .{},
                        );
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.eh_frame_section_index.?,
                    };
                }

                // TODO audit this: is this the right mapping?
                if (self.data_const_section_index == null) {
                    self.data_const_section_index = try self.initSection(
                        self.data_const_segment_cmd_index.?,
                        "__const",
                        .{},
                    );
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.data_const_section_index.?,
                };
            },
            macho.S_REGULAR => {
                if (sect.isCode()) {
                    if (self.text_section_index == null) {
                        self.text_section_index = try self.initSection(
                            self.text_segment_cmd_index.?,
                            "__text",
                            .{
                                .flags = macho.S_REGULAR |
                                    macho.S_ATTR_PURE_INSTRUCTIONS |
                                    macho.S_ATTR_SOME_INSTRUCTIONS,
                            },
                        );
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.text_section_index.?,
                    };
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

                if (mem.eql(u8, segname, "__TEXT")) {
                    if (mem.eql(u8, sectname, "__ustring")) {
                        if (self.ustring_section_index == null) {
                            self.ustring_section_index = try self.initSection(
                                self.text_segment_cmd_index.?,
                                "__ustring",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.ustring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__gcc_except_tab")) {
                        if (self.gcc_except_tab_section_index == null) {
                            self.gcc_except_tab_section_index = try self.initSection(
                                self.text_segment_cmd_index.?,
                                "__gcc_except_tab",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.gcc_except_tab_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_methlist")) {
                        if (self.objc_methlist_section_index == null) {
                            self.objc_methlist_section_index = try self.initSection(
                                self.text_segment_cmd_index.?,
                                "__objc_methlist",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.objc_methlist_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__rodata") or
                        mem.eql(u8, sectname, "__typelink") or
                        mem.eql(u8, sectname, "__itablink") or
                        mem.eql(u8, sectname, "__gosymtab") or
                        mem.eql(u8, sectname, "__gopclntab"))
                    {
                        if (self.data_const_section_index == null) {
                            self.data_const_section_index = try self.initSection(
                                self.data_const_segment_cmd_index.?,
                                "__const",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else {
                        if (self.text_const_section_index == null) {
                            self.text_const_section_index = try self.initSection(
                                self.text_segment_cmd_index.?,
                                "__const",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.text_const_section_index.?,
                        };
                    }
                }

                if (mem.eql(u8, segname, "__DATA_CONST")) {
                    if (self.data_const_section_index == null) {
                        self.data_const_section_index = try self.initSection(
                            self.data_const_segment_cmd_index.?,
                            "__const",
                            .{},
                        );
                    }

                    break :blk .{
                        .seg = self.data_const_segment_cmd_index.?,
                        .sect = self.data_const_section_index.?,
                    };
                }

                if (mem.eql(u8, segname, "__DATA")) {
                    if (mem.eql(u8, sectname, "__const")) {
                        if (self.data_const_section_index == null) {
                            self.data_const_section_index = try self.initSection(
                                self.data_const_segment_cmd_index.?,
                                "__const",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__cfstring")) {
                        if (self.objc_cfstring_section_index == null) {
                            self.objc_cfstring_section_index = try self.initSection(
                                self.data_const_segment_cmd_index.?,
                                "__cfstring",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_cfstring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classlist")) {
                        if (self.objc_classlist_section_index == null) {
                            self.objc_classlist_section_index = try self.initSection(
                                self.data_const_segment_cmd_index.?,
                                "__objc_classlist",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_classlist_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_imageinfo")) {
                        if (self.objc_imageinfo_section_index == null) {
                            self.objc_imageinfo_section_index = try self.initSection(
                                self.data_const_segment_cmd_index.?,
                                "__objc_imageinfo",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_imageinfo_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_const")) {
                        if (self.objc_const_section_index == null) {
                            self.objc_const_section_index = try self.initSection(
                                self.data_segment_cmd_index.?,
                                "__objc_const",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classrefs")) {
                        if (self.objc_classrefs_section_index == null) {
                            self.objc_classrefs_section_index = try self.initSection(
                                self.data_segment_cmd_index.?,
                                "__objc_classrefs",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_classrefs_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_data")) {
                        if (self.objc_data_section_index == null) {
                            self.objc_data_section_index = try self.initSection(
                                self.data_segment_cmd_index.?,
                                "__objc_data",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_data_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, ".rustc")) {
                        if (self.rustc_section_index == null) {
                            self.rustc_section_index = try self.initSection(
                                self.data_segment_cmd_index.?,
                                ".rustc",
                                .{},
                            );
                            // We need to preserve the section size for rustc to properly
                            // decompress the metadata.
                            self.rustc_section_size = sect.size;
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.rustc_section_index.?,
                        };
                    } else {
                        if (self.data_section_index == null) {
                            self.data_section_index = try self.initSection(
                                self.data_segment_cmd_index.?,
                                "__data",
                                .{},
                            );
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.data_section_index.?,
                        };
                    }
                }

                if (mem.eql(u8, "__LLVM", segname) and mem.eql(u8, "__asm", sectname)) {
                    log.debug("TODO LLVM asm section: type 0x{x}, name '{s},{s}'", .{
                        sect.flags, segname, sectname,
                    });
                }

                break :blk null;
            },
            else => break :blk null,
        }
    };
    return res;
}

fn allocateAtom(self: *MachO, atom: *Atom, match: MatchingSection) !void {
    const sym = atom.getSymbolPtr(self);
    try self.addAtomToSection(atom, match);
    sym.n_sect = self.getSectionOrdinal(match);
}

pub fn addAtomToSection(self: *MachO, atom: *Atom, match: MatchingSection) !void {
    if (self.atoms.getPtr(match)) |last| {
        last.*.next = atom;
        atom.prev = last.*;
        last.* = atom;
    } else {
        try self.atoms.putNoClobber(self.base.allocator, match, atom);
    }
    const sect = self.getSectionPtr(match);
    const atom_alignment = try math.powi(u32, 2, atom.alignment);
    const aligned_end_addr = mem.alignForwardGeneric(u64, sect.size, atom_alignment);
    const padding = aligned_end_addr - sect.size;
    sect.size += padding + atom.size;
    sect.@"align" = @maximum(sect.@"align", atom.alignment);
}

fn getSegmentAllocBase(self: MachO, indices: []const ?u16) struct { vmaddr: u64, fileoff: u64 } {
    for (indices) |maybe_prev_id| {
        const prev_id = maybe_prev_id orelse continue;
        const prev = self.load_commands.items[prev_id].segment;
        return .{
            .vmaddr = prev.inner.vmaddr + prev.inner.vmsize,
            .fileoff = prev.inner.fileoff + prev.inner.filesize,
        };
    }
    return .{ .vmaddr = 0, .fileoff = 0 };
}

fn pruneAndSortSectionsInSegment(self: *MachO, maybe_seg_id: *?u16, indices: []*?u16) !void {
    const seg_id = maybe_seg_id.* orelse return;

    var mapping = std.AutoArrayHashMap(u16, ?u16).init(self.base.allocator);
    defer mapping.deinit();

    const seg = &self.load_commands.items[seg_id].segment;
    var sections = seg.sections.toOwnedSlice(self.base.allocator);
    defer self.base.allocator.free(sections);
    try seg.sections.ensureTotalCapacity(self.base.allocator, sections.len);

    for (indices) |maybe_index| {
        const old_idx = maybe_index.* orelse continue;
        const sect = &sections[old_idx];
        if (sect.size == 0) {
            log.debug("pruning section {s},{s}", .{ sect.segName(), sect.sectName() });
            maybe_index.* = null;
            seg.inner.cmdsize -= @sizeOf(macho.section_64);
            seg.inner.nsects -= 1;
        } else {
            maybe_index.* = @intCast(u16, seg.sections.items.len);
            seg.sections.appendAssumeCapacity(sect.*);
        }
        try mapping.putNoClobber(old_idx, maybe_index.*);
    }

    var atoms = std.ArrayList(struct { match: MatchingSection, atom: *Atom }).init(self.base.allocator);
    defer atoms.deinit();
    try atoms.ensureTotalCapacity(mapping.count());

    for (mapping.keys()) |old_sect| {
        const new_sect = mapping.get(old_sect).? orelse {
            _ = self.atoms.remove(.{ .seg = seg_id, .sect = old_sect });
            continue;
        };
        const kv = self.atoms.fetchRemove(.{ .seg = seg_id, .sect = old_sect }).?;
        atoms.appendAssumeCapacity(.{
            .match = .{ .seg = seg_id, .sect = new_sect },
            .atom = kv.value,
        });
    }

    while (atoms.popOrNull()) |next| {
        try self.atoms.putNoClobber(self.base.allocator, next.match, next.atom);
    }

    if (seg.inner.nsects == 0 and !mem.eql(u8, "__TEXT", seg.inner.segName())) {
        // Segment has now become empty, so mark it as such
        log.debug("marking segment {s} as dead", .{seg.inner.segName()});
        seg.inner.cmd = @intToEnum(macho.LC, 0);
        maybe_seg_id.* = null;
    }
}

fn pruneAndSortSections(self: *MachO) !void {
    try self.pruneAndSortSectionsInSegment(&self.text_segment_cmd_index, &.{
        &self.text_section_index,
        &self.stubs_section_index,
        &self.stub_helper_section_index,
        &self.gcc_except_tab_section_index,
        &self.cstring_section_index,
        &self.ustring_section_index,
        &self.text_const_section_index,
        &self.objc_methlist_section_index,
        &self.objc_methname_section_index,
        &self.objc_methtype_section_index,
        &self.objc_classname_section_index,
        &self.eh_frame_section_index,
    });

    try self.pruneAndSortSectionsInSegment(&self.data_const_segment_cmd_index, &.{
        &self.got_section_index,
        &self.mod_init_func_section_index,
        &self.mod_term_func_section_index,
        &self.data_const_section_index,
        &self.objc_cfstring_section_index,
        &self.objc_classlist_section_index,
        &self.objc_imageinfo_section_index,
    });

    try self.pruneAndSortSectionsInSegment(&self.data_segment_cmd_index, &.{
        &self.rustc_section_index,
        &self.la_symbol_ptr_section_index,
        &self.objc_const_section_index,
        &self.objc_selrefs_section_index,
        &self.objc_classrefs_section_index,
        &self.objc_data_section_index,
        &self.data_section_index,
        &self.tlv_section_index,
        &self.tlv_ptrs_section_index,
        &self.tlv_data_section_index,
        &self.tlv_bss_section_index,
        &self.bss_section_index,
    });

    // Create new section ordinals.
    self.section_ordinals.clearRetainingCapacity();
    if (self.text_segment_cmd_index) |seg_id| {
        const seg = self.load_commands.items[seg_id].segment;
        for (seg.sections.items) |_, sect_id| {
            const res = self.section_ordinals.getOrPutAssumeCapacity(.{
                .seg = seg_id,
                .sect = @intCast(u16, sect_id),
            });
            assert(!res.found_existing);
        }
    }
    if (self.data_const_segment_cmd_index) |seg_id| {
        const seg = self.load_commands.items[seg_id].segment;
        for (seg.sections.items) |_, sect_id| {
            const res = self.section_ordinals.getOrPutAssumeCapacity(.{
                .seg = seg_id,
                .sect = @intCast(u16, sect_id),
            });
            assert(!res.found_existing);
        }
    }
    if (self.data_segment_cmd_index) |seg_id| {
        const seg = self.load_commands.items[seg_id].segment;
        for (seg.sections.items) |_, sect_id| {
            const res = self.section_ordinals.getOrPutAssumeCapacity(.{
                .seg = seg_id,
                .sect = @intCast(u16, sect_id),
            });
            assert(!res.found_existing);
        }
    }
}

pub fn createEmptyAtom(gpa: Allocator, sym_index: u32, size: u64, alignment: u32) !*Atom {
    const size_usize = math.cast(usize, size) orelse return error.Overflow;
    const atom = try gpa.create(Atom);
    errdefer gpa.destroy(atom);
    atom.* = Atom.empty;
    atom.sym_index = sym_index;
    atom.size = size;
    atom.alignment = alignment;

    try atom.code.resize(gpa, size_usize);
    mem.set(u8, atom.code.items, 0);

    return atom;
}

pub fn createGotAtom(self: *MachO, target: SymbolWithLoc) !*Atom {
    const gpa = self.base.allocator;
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });

    const atom = try MachO.createEmptyAtom(gpa, sym_index, @sizeOf(u64), 3);
    try atom.relocs.append(gpa, .{
        .offset = 0,
        .target = target,
        .addend = 0,
        .subtractor = null,
        .pcrel = false,
        .length = 3,
        .@"type" = switch (self.options.target.cpu_arch.?) {
            .aarch64 => @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_UNSIGNED),
            .x86_64 => @enumToInt(macho.reloc_type_x86_64.X86_64_RELOC_UNSIGNED),
            else => unreachable,
        },
    });

    const target_sym = self.getSymbol(target);
    if (target_sym.undf()) {
        const global = self.globals.get(self.getSymbolName(target)).?;
        try atom.bindings.append(gpa, .{
            .target = global,
            .offset = 0,
        });
    } else {
        try atom.rebases.append(gpa, 0);
    }

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);

    try self.allocateAtom(atom, .{
        .seg = self.data_const_segment_cmd_index.?,
        .sect = self.got_section_index.?,
    });

    return atom;
}

pub fn createTlvPtrAtom(self: *MachO, target: SymbolWithLoc) !*Atom {
    const gpa = self.base.allocator;
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });

    const atom = try MachO.createEmptyAtom(gpa, sym_index, @sizeOf(u64), 3);
    const target_sym = self.getSymbol(target);
    assert(target_sym.undf());

    const global = self.globals.get(self.getSymbolName(target)).?;
    try atom.bindings.append(gpa, .{
        .target = global,
        .offset = 0,
    });

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);

    const match = (try self.getMatchingSection(.{
        .segname = makeStaticString("__DATA"),
        .sectname = makeStaticString("__thread_ptrs"),
        .flags = macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
    })).?;
    try self.allocateAtom(atom, match);

    return atom;
}

fn createDyldPrivateAtom(self: *MachO) !void {
    if (self.dyld_stub_binder_index == null) return;
    if (self.dyld_private_atom != null) return;

    const gpa = self.base.allocator;
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try MachO.createEmptyAtom(gpa, sym_index, @sizeOf(u64), 3);
    self.dyld_private_atom = atom;

    try self.allocateAtom(atom, .{
        .seg = self.data_segment_cmd_index.?,
        .sect = self.data_section_index.?,
    });

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);
}

fn createStubHelperPreambleAtom(self: *MachO) !void {
    if (self.dyld_stub_binder_index == null) return;
    if (self.stub_helper_preamble_atom != null) return;

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
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try MachO.createEmptyAtom(gpa, sym_index, size, alignment);
    const dyld_private_sym_index = self.dyld_private_atom.?.sym_index;
    switch (cpu_arch) {
        .x86_64 => {
            try atom.relocs.ensureUnusedCapacity(self.base.allocator, 2);
            // lea %r11, [rip + disp]
            atom.code.items[0] = 0x4c;
            atom.code.items[1] = 0x8d;
            atom.code.items[2] = 0x1d;
            atom.relocs.appendAssumeCapacity(.{
                .offset = 3,
                .target = .{ .sym_index = dyld_private_sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_x86_64.X86_64_RELOC_SIGNED),
            });
            // push %r11
            atom.code.items[7] = 0x41;
            atom.code.items[8] = 0x53;
            // jmp [rip + disp]
            atom.code.items[9] = 0xff;
            atom.code.items[10] = 0x25;
            atom.relocs.appendAssumeCapacity(.{
                .offset = 11,
                .target = .{ .sym_index = self.dyld_stub_binder_index.?, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_x86_64.X86_64_RELOC_GOT),
            });
        },
        .aarch64 => {
            try atom.relocs.ensureUnusedCapacity(self.base.allocator, 4);
            // adrp x17, 0
            mem.writeIntLittle(u32, atom.code.items[0..][0..4], aarch64.Instruction.adrp(.x17, 0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 0,
                .target = .{ .sym_index = dyld_private_sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_PAGE21),
            });
            // add x17, x17, 0
            mem.writeIntLittle(u32, atom.code.items[4..][0..4], aarch64.Instruction.add(.x17, .x17, 0, false).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 4,
                .target = .{ .sym_index = dyld_private_sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = false,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_PAGEOFF12),
            });
            // stp x16, x17, [sp, #-16]!
            mem.writeIntLittle(u32, atom.code.items[8..][0..4], aarch64.Instruction.stp(
                .x16,
                .x17,
                aarch64.Register.sp,
                aarch64.Instruction.LoadStorePairOffset.pre_index(-16),
            ).toU32());
            // adrp x16, 0
            mem.writeIntLittle(u32, atom.code.items[12..][0..4], aarch64.Instruction.adrp(.x16, 0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 12,
                .target = .{ .sym_index = self.dyld_stub_binder_index.?, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_GOT_LOAD_PAGE21),
            });
            // ldr x16, [x16, 0]
            mem.writeIntLittle(u32, atom.code.items[16..][0..4], aarch64.Instruction.ldr(
                .x16,
                .x16,
                aarch64.Instruction.LoadStoreOffset.imm(0),
            ).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 16,
                .target = .{ .sym_index = self.dyld_stub_binder_index.?, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = false,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_GOT_LOAD_PAGEOFF12),
            });
            // br x16
            mem.writeIntLittle(u32, atom.code.items[20..][0..4], aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }
    self.stub_helper_preamble_atom = atom;

    try self.allocateAtom(atom, .{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stub_helper_section_index.?,
    });

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);
}

pub fn createStubHelperAtom(self: *MachO) !*Atom {
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
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try MachO.createEmptyAtom(gpa, sym_index, stub_size, alignment);
    try atom.relocs.ensureTotalCapacity(gpa, 1);

    switch (cpu_arch) {
        .x86_64 => {
            // pushq
            atom.code.items[0] = 0x68;
            // Next 4 bytes 1..4 are just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
            // jmpq
            atom.code.items[5] = 0xe9;
            atom.relocs.appendAssumeCapacity(.{
                .offset = 6,
                .target = .{ .sym_index = self.stub_helper_preamble_atom.?.sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_x86_64.X86_64_RELOC_BRANCH),
            });
        },
        .aarch64 => {
            const literal = blk: {
                const div_res = try math.divExact(u64, stub_size - @sizeOf(u32), 4);
                break :blk math.cast(u18, div_res) orelse return error.Overflow;
            };
            // ldr w16, literal
            mem.writeIntLittle(u32, atom.code.items[0..4], aarch64.Instruction.ldrLiteral(
                .w16,
                literal,
            ).toU32());
            // b disp
            mem.writeIntLittle(u32, atom.code.items[4..8], aarch64.Instruction.b(0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 4,
                .target = .{ .sym_index = self.stub_helper_preamble_atom.?.sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_BRANCH26),
            });
            // Next 4 bytes 8..12 are just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
        },
        else => unreachable,
    }

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);

    try self.allocateAtom(atom, .{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stub_helper_section_index.?,
    });

    return atom;
}

pub fn createLazyPointerAtom(self: *MachO, stub_sym_index: u32, target: SymbolWithLoc) !*Atom {
    const gpa = self.base.allocator;
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try MachO.createEmptyAtom(gpa, sym_index, @sizeOf(u64), 3);
    try atom.relocs.append(gpa, .{
        .offset = 0,
        .target = .{ .sym_index = stub_sym_index, .file = null },
        .addend = 0,
        .subtractor = null,
        .pcrel = false,
        .length = 3,
        .@"type" = switch (self.options.target.cpu_arch.?) {
            .aarch64 => @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_UNSIGNED),
            .x86_64 => @enumToInt(macho.reloc_type_x86_64.X86_64_RELOC_UNSIGNED),
            else => unreachable,
        },
    });
    try atom.rebases.append(gpa, 0);

    const global = self.globals.get(self.getSymbolName(target)).?;
    try atom.lazy_bindings.append(gpa, .{
        .target = global,
        .offset = 0,
    });

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);

    try self.allocateAtom(atom, .{
        .seg = self.data_segment_cmd_index.?,
        .sect = self.la_symbol_ptr_section_index.?,
    });

    return atom;
}

pub fn createStubAtom(self: *MachO, laptr_sym_index: u32) !*Atom {
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
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try MachO.createEmptyAtom(gpa, sym_index, stub_size, alignment);
    switch (cpu_arch) {
        .x86_64 => {
            // jmp
            atom.code.items[0] = 0xff;
            atom.code.items[1] = 0x25;
            try atom.relocs.append(gpa, .{
                .offset = 2,
                .target = .{ .sym_index = laptr_sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_x86_64.X86_64_RELOC_BRANCH),
            });
        },
        .aarch64 => {
            try atom.relocs.ensureTotalCapacity(gpa, 2);
            // adrp x16, pages
            mem.writeIntLittle(u32, atom.code.items[0..4], aarch64.Instruction.adrp(.x16, 0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 0,
                .target = .{ .sym_index = laptr_sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = true,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_PAGE21),
            });
            // ldr x16, x16, offset
            mem.writeIntLittle(u32, atom.code.items[4..8], aarch64.Instruction.ldr(
                .x16,
                .x16,
                aarch64.Instruction.LoadStoreOffset.imm(0),
            ).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 4,
                .target = .{ .sym_index = laptr_sym_index, .file = null },
                .addend = 0,
                .subtractor = null,
                .pcrel = false,
                .length = 2,
                .@"type" = @enumToInt(macho.reloc_type_arm64.ARM64_RELOC_PAGEOFF12),
            });
            // br x16
            mem.writeIntLittle(u32, atom.code.items[8..12], aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }

    try self.managed_atoms.append(gpa, atom);
    try self.atom_by_index_table.putNoClobber(gpa, sym_index, atom);

    try self.allocateAtom(atom, .{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stubs_section_index.?,
    });

    return atom;
}

fn createTentativeDefAtoms(self: *MachO) !void {
    const gpa = self.base.allocator;

    for (self.globals.values()) |global| {
        const sym = self.getSymbolPtr(global);
        if (!sym.tentative()) continue;

        log.debug("creating tentative definition for ATOM(%{d}, '{s}') in object({d})", .{
            global.sym_index, self.getSymbolName(global), global.file,
        });

        // Convert any tentative definition into a regular symbol and allocate
        // text blocks for each tentative definition.
        const match = MatchingSection{
            .seg = self.data_segment_cmd_index.?,
            .sect = self.bss_section_index.?,
        };
        _ = try self.section_ordinals.getOrPut(gpa, match);

        const size = sym.n_value;
        const alignment = (sym.n_desc >> 8) & 0x0f;

        sym.* = .{
            .n_strx = sym.n_strx,
            .n_type = macho.N_SECT | macho.N_EXT,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };

        const atom = try MachO.createEmptyAtom(gpa, global.sym_index, size, alignment);
        atom.file = global.file;

        try self.allocateAtom(atom, match);

        if (global.file) |file| {
            const object = &self.objects.items[file];
            try object.managed_atoms.append(gpa, atom);
            try object.atom_by_index_table.putNoClobber(gpa, global.sym_index, atom);
        } else {
            try self.managed_atoms.append(gpa, atom);
            try self.atom_by_index_table.putNoClobber(gpa, global.sym_index, atom);
        }
    }
}

fn resolveSymbolsInObject(self: *MachO, object: *Object, object_id: u16) !void {
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
        self.resolveGlobalSymbol(sym_loc) catch |err| switch (err) {
            error.MultipleSymbolDefinitions => {
                const global = self.globals.get(sym_name).?;
                log.err("symbol '{s}' defined multiple times", .{sym_name});
                if (global.file) |file| {
                    log.err("  first definition in '{s}'", .{self.objects.items[file].name});
                }
                log.err("  next definition in '{s}'", .{self.objects.items[object_id].name});
                return error.MultipleSymbolDefinitions;
            },
            else => |e| return e,
        };
    }
}

fn resolveSymbolsInArchives(self: *MachO) !void {
    if (self.archives.items.len == 0) return;

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
            const object = try self.objects.addOne(self.base.allocator);
            object.* = try archive.parseObject(
                self.base.allocator,
                self.options.target.cpu_arch.?,
                offsets.items[0],
            );
            try self.resolveSymbolsInObject(object, object_id);

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
                try self.addLoadDylibLC(dylib_id);
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
            // TODO allow_shlib_undefined is an ELF flag so figure out macOS specific flags too.
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
    const n_strx = try self.strtab.insert(gpa, "__mh_execute_header");
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = n_strx,
        .n_type = macho.N_SECT | macho.N_EXT,
        .n_sect = 0,
        .n_desc = macho.REFERENCED_DYNAMICALLY,
        .n_value = 0,
    });

    const name = try gpa.dupe(u8, "__mh_execute_header");
    const gop = try self.globals.getOrPut(gpa, name);
    defer if (gop.found_existing) gpa.free(name);
    gop.value_ptr.* = .{
        .sym_index = sym_index,
        .file = null,
    };
}

fn createDsoHandleSymbol(self: *MachO) !void {
    const global = self.globals.getPtr("___dso_handle") orelse return;
    const sym = self.getSymbolPtr(global.*);
    if (!sym.undf()) return;

    const gpa = self.base.allocator;
    const n_strx = try self.strtab.insert(gpa, "___dso_handle");
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = n_strx,
        .n_type = macho.N_SECT | macho.N_EXT,
        .n_sect = 0,
        .n_desc = macho.N_WEAK_DEF,
        .n_value = 0,
    });
    global.* = .{
        .sym_index = sym_index,
        .file = null,
    };
    _ = self.unresolved.swapRemove(@intCast(u32, self.globals.getIndex("___dso_handle").?));
}

fn resolveGlobalSymbol(self: *MachO, current: SymbolWithLoc) !void {
    const gpa = self.base.allocator;
    const sym = self.getSymbol(current);
    const sym_name = self.getSymbolName(current);

    const name = try gpa.dupe(u8, sym_name);
    const global_index = @intCast(u32, self.globals.values().len);
    const gop = try self.globals.getOrPut(gpa, name);
    defer if (gop.found_existing) gpa.free(name);

    if (!gop.found_existing) {
        gop.value_ptr.* = current;
        if (sym.undf() and !sym.tentative()) {
            try self.unresolved.putNoClobber(gpa, global_index, {});
        }
        return;
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

    if (sym_is_strong and global_is_strong) return error.MultipleSymbolDefinitions;
    if (global_is_strong) return;
    if (sym_is_weak and global_is_weak) return;
    if (sym.tentative() and global_sym.tentative()) {
        if (global_sym.n_value >= sym.n_value) return;
    }
    if (sym.undf() and !sym.tentative()) return;

    _ = self.unresolved.swapRemove(@intCast(u32, self.globals.getIndex(name).?));

    gop.value_ptr.* = current;
}

fn resolveDyldStubBinder(self: *MachO) !void {
    if (self.dyld_stub_binder_index != null) return;
    if (self.unresolved.count() == 0) return; // no need for a stub binder if we don't have any imports

    const gpa = self.base.allocator;
    const n_strx = try self.strtab.insert(gpa, "dyld_stub_binder");
    const sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(gpa, .{
        .n_strx = n_strx,
        .n_type = macho.N_UNDF,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const sym_name = try gpa.dupe(u8, "dyld_stub_binder");
    const global = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    try self.globals.putNoClobber(gpa, sym_name, global);
    const sym = &self.locals.items[sym_index];

    for (self.dylibs.items) |dylib, id| {
        if (!dylib.symbols.contains(sym_name)) continue;

        const dylib_id = @intCast(u16, id);
        if (!self.referenced_dylibs.contains(dylib_id)) {
            try self.addLoadDylibLC(dylib_id);
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

    // Add dyld_stub_binder as the final GOT entry.
    const got_index = try self.allocateGotEntry(global);
    const got_atom = try self.createGotAtom(global);
    self.got_entries.items[got_index].sym_index = got_atom.sym_index;
}

fn addLoadDylibLC(self: *MachO, id: u16) !void {
    const dylib = self.dylibs.items[id];
    const dylib_id = dylib.id orelse unreachable;
    var dylib_cmd = try macho.createLoadDylibCommand(
        self.base.allocator,
        if (dylib.weak) .LOAD_WEAK_DYLIB else .LOAD_DYLIB,
        dylib_id.name,
        dylib_id.timestamp,
        dylib_id.current_version,
        dylib_id.compatibility_version,
    );
    errdefer dylib_cmd.deinit(self.base.allocator);
    try self.load_commands.append(self.base.allocator, .{ .dylib = dylib_cmd });
}

fn addCodeSignatureLC(self: *MachO) !void {
    if (self.code_signature_cmd_index != null or self.code_signature == null) return;
    self.code_signature_cmd_index = @intCast(u16, self.load_commands.items.len);
    try self.load_commands.append(self.base.allocator, .{
        .linkedit_data = .{
            .cmd = .CODE_SIGNATURE,
            .cmdsize = @sizeOf(macho.linkedit_data_command),
            .dataoff = 0,
            .datasize = 0,
        },
    });
}

fn setEntryPoint(self: *MachO) !void {
    if (self.options.output_mode != .exe) return;
    const seg = self.load_commands.items[self.text_segment_cmd_index.?].segment;
    const global = try self.getEntryPoint();
    const sym = self.getSymbol(global);
    const ec = &self.load_commands.items[self.main_cmd_index.?].main;
    ec.entryoff = @intCast(u32, sym.n_value - seg.inner.vmaddr);
    ec.stacksize = self.options.stack_size orelse 0;
}

pub fn deinit(self: *MachO) void {
    const gpa = self.base.allocator;

    self.section_ordinals.deinit(gpa);
    self.tlv_ptr_entries.deinit(gpa);
    self.tlv_ptr_entries_table.deinit(gpa);
    self.got_entries.deinit(gpa);
    self.got_entries_table.deinit(gpa);
    self.stubs.deinit(gpa);
    self.stubs_table.deinit(gpa);
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

    for (self.load_commands.items) |*lc| {
        lc.deinit(gpa);
    }
    self.load_commands.deinit(gpa);

    for (self.managed_atoms.items) |atom| {
        atom.deinit(gpa);
        gpa.destroy(atom);
    }
    self.managed_atoms.deinit(gpa);
    self.atoms.deinit(gpa);
    self.atom_by_index_table.deinit(gpa);

    if (self.code_signature) |*csig| {
        csig.deinit(gpa);
    }
}

pub fn closeFiles(self: *const MachO) void {
    for (self.objects.items) |object| {
        object.file.close();
    }
    for (self.archives.items) |archive| {
        archive.file.close();
    }
    for (self.dylibs.items) |dylib| {
        dylib.file.close();
    }
}

fn populateMetadata(self: *MachO) !void {
    const cpu_arch = self.options.target.cpu_arch.?;
    const pagezero_vmsize = self.options.pagezero_size orelse default_pagezero_vmsize;
    const aligned_pagezero_vmsize = mem.alignBackwardGeneric(u64, pagezero_vmsize, self.page_size);

    if (self.pagezero_segment_cmd_index == null) blk: {
        if (self.options.output_mode == .lib) break :blk;
        if (aligned_pagezero_vmsize == 0) break :blk;
        if (aligned_pagezero_vmsize != pagezero_vmsize) {
            log.warn("requested __PAGEZERO size (0x{x}) is not page aligned", .{pagezero_vmsize});
            log.warn("  rounding down to 0x{x}", .{aligned_pagezero_vmsize});
        }
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .segment = .{
                .inner = .{
                    .segname = makeStaticString("__PAGEZERO"),
                    .vmsize = aligned_pagezero_vmsize,
                    .cmdsize = @sizeOf(macho.segment_command_64),
                },
            },
        });
    }

    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .segment = .{
                .inner = .{
                    .segname = makeStaticString("__TEXT"),
                    .vmaddr = aligned_pagezero_vmsize,
                    .maxprot = macho.PROT.READ | macho.PROT.EXEC,
                    .initprot = macho.PROT.READ | macho.PROT.EXEC,
                    .cmdsize = @sizeOf(macho.segment_command_64),
                },
            },
        });
    }

    if (self.text_section_index == null) {
        self.text_section_index = try self.initSection(
            self.text_segment_cmd_index.?,
            "__text",
            .{
                .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            },
        );
    }

    if (self.stubs_section_index == null) {
        const stub_size: u4 = switch (cpu_arch) {
            .x86_64 => 6,
            .aarch64 => 3 * @sizeOf(u32),
            else => unreachable, // unhandled architecture type
        };
        self.stubs_section_index = try self.initSection(
            self.text_segment_cmd_index.?,
            "__stubs",
            .{
                .flags = macho.S_SYMBOL_STUBS | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
                .reserved2 = stub_size,
            },
        );
    }

    if (self.stub_helper_section_index == null) {
        self.stub_helper_section_index = try self.initSection(
            self.text_segment_cmd_index.?,
            "__stub_helper",
            .{
                .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            },
        );
    }

    if (self.data_const_segment_cmd_index == null) {
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .segment = .{
                .inner = .{
                    .segname = makeStaticString("__DATA_CONST"),
                    .maxprot = macho.PROT.READ | macho.PROT.WRITE,
                    .initprot = macho.PROT.READ | macho.PROT.WRITE,
                    .cmdsize = @sizeOf(macho.segment_command_64),
                },
            },
        });
    }

    if (self.got_section_index == null) {
        self.got_section_index = try self.initSection(
            self.data_const_segment_cmd_index.?,
            "__got",
            .{
                .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
            },
        );
    }

    if (self.data_segment_cmd_index == null) {
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .segment = .{
                .inner = .{
                    .segname = makeStaticString("__DATA"),
                    .maxprot = macho.PROT.READ | macho.PROT.WRITE,
                    .initprot = macho.PROT.READ | macho.PROT.WRITE,
                    .cmdsize = @sizeOf(macho.segment_command_64),
                },
            },
        });
    }

    if (self.la_symbol_ptr_section_index == null) {
        self.la_symbol_ptr_section_index = try self.initSection(
            self.data_segment_cmd_index.?,
            "__la_symbol_ptr",
            .{
                .flags = macho.S_LAZY_SYMBOL_POINTERS,
            },
        );
    }

    if (self.data_section_index == null) {
        self.data_section_index = try self.initSection(
            self.data_segment_cmd_index.?,
            "__data",
            .{},
        );
    }

    if (self.tlv_section_index == null) {
        self.tlv_section_index = try self.initSection(
            self.data_segment_cmd_index.?,
            "__thread_vars",
            .{
                .flags = macho.S_THREAD_LOCAL_VARIABLES,
            },
        );
    }

    if (self.tlv_data_section_index == null) {
        self.tlv_data_section_index = try self.initSection(
            self.data_segment_cmd_index.?,
            "__thread_data",
            .{
                .flags = macho.S_THREAD_LOCAL_REGULAR,
            },
        );
    }

    if (self.tlv_bss_section_index == null) {
        self.tlv_bss_section_index = try self.initSection(
            self.data_segment_cmd_index.?,
            "__thread_bss",
            .{
                .flags = macho.S_THREAD_LOCAL_ZEROFILL,
            },
        );
    }

    if (self.bss_section_index == null) {
        self.bss_section_index = try self.initSection(
            self.data_segment_cmd_index.?,
            "__bss",
            .{
                .flags = macho.S_ZEROFILL,
            },
        );
    }

    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .segment = .{
                .inner = .{
                    .segname = makeStaticString("__LINKEDIT"),
                    .maxprot = macho.PROT.READ,
                    .initprot = macho.PROT.READ,
                    .cmdsize = @sizeOf(macho.segment_command_64),
                },
            },
        });
    }

    if (self.dyld_info_cmd_index == null) {
        self.dyld_info_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .dyld_info_only = .{
                .cmd = .DYLD_INFO_ONLY,
                .cmdsize = @sizeOf(macho.dyld_info_command),
                .rebase_off = 0,
                .rebase_size = 0,
                .bind_off = 0,
                .bind_size = 0,
                .weak_bind_off = 0,
                .weak_bind_size = 0,
                .lazy_bind_off = 0,
                .lazy_bind_size = 0,
                .export_off = 0,
                .export_size = 0,
            },
        });
    }

    if (self.symtab_cmd_index == null) {
        self.symtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .symtab = .{
                .cmdsize = @sizeOf(macho.symtab_command),
                .symoff = 0,
                .nsyms = 0,
                .stroff = 0,
                .strsize = 0,
            },
        });
    }

    if (self.dysymtab_cmd_index == null) {
        self.dysymtab_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .dysymtab = .{
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
            },
        });
    }

    if (self.dylinker_cmd_index == null) {
        self.dylinker_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.dylinker_command) + mem.sliceTo(default_dyld_path, 0).len,
            @sizeOf(u64),
        ));
        var dylinker_cmd = macho.emptyGenericCommandWithData(macho.dylinker_command{
            .cmd = .LOAD_DYLINKER,
            .cmdsize = cmdsize,
            .name = @sizeOf(macho.dylinker_command),
        });
        dylinker_cmd.data = try self.base.allocator.alloc(u8, cmdsize - dylinker_cmd.inner.name);
        mem.set(u8, dylinker_cmd.data, 0);
        mem.copy(u8, dylinker_cmd.data, mem.sliceTo(default_dyld_path, 0));
        try self.load_commands.append(self.base.allocator, .{ .dylinker = dylinker_cmd });
    }

    if (self.main_cmd_index == null and self.options.output_mode == .exe) {
        self.main_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .main = .{
                .cmdsize = @sizeOf(macho.entry_point_command),
                .entryoff = 0x0,
                .stacksize = 0,
            },
        });
    }

    if (self.dylib_id_cmd_index == null and self.options.output_mode == .lib) {
        self.dylib_id_cmd_index = @intCast(u16, self.load_commands.items.len);
        const install_name = self.options.install_name orelse self.options.emit.sub_path;
        const current_version = self.options.current_version orelse
            std.builtin.Version{ .major = 1, .minor = 0, .patch = 0 };
        const compat_version = self.options.compatibility_version orelse
            std.builtin.Version{ .major = 1, .minor = 0, .patch = 0 };
        var dylib_cmd = try macho.createLoadDylibCommand(
            self.base.allocator,
            .ID_DYLIB,
            install_name,
            2,
            current_version.major << 16 | current_version.minor << 8 | current_version.patch,
            compat_version.major << 16 | compat_version.minor << 8 | compat_version.patch,
        );
        errdefer dylib_cmd.deinit(self.base.allocator);
        try self.load_commands.append(self.base.allocator, .{ .dylib = dylib_cmd });
    }

    if (self.source_version_cmd_index == null) {
        self.source_version_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .source_version = .{
                .cmdsize = @sizeOf(macho.source_version_command),
                .version = 0x0,
            },
        });
    }

    if (self.build_version_cmd_index == null) {
        self.build_version_cmd_index = @intCast(u16, self.load_commands.items.len);
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.build_version_command) + @sizeOf(macho.build_tool_version),
            @sizeOf(u64),
        ));
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
        var cmd = macho.emptyGenericCommandWithData(macho.build_version_command{
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
        const ld_ver = macho.build_tool_version{
            .tool = .LD,
            .version = 0x0,
        };
        cmd.data = try self.base.allocator.alloc(u8, cmdsize - @sizeOf(macho.build_version_command));
        mem.set(u8, cmd.data, 0);
        mem.copy(u8, cmd.data, mem.asBytes(&ld_ver));
        try self.load_commands.append(self.base.allocator, .{ .build_version = cmd });
    }

    if (self.uuid_cmd_index == null) {
        self.uuid_cmd_index = @intCast(u16, self.load_commands.items.len);
        var uuid_cmd: macho.uuid_command = .{
            .cmdsize = @sizeOf(macho.uuid_command),
            .uuid = undefined,
        };
        std.crypto.random.bytes(&uuid_cmd.uuid);
        try self.load_commands.append(self.base.allocator, .{ .uuid = uuid_cmd });
    }

    if (self.function_starts_cmd_index == null) {
        self.function_starts_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .linkedit_data = .{
                .cmd = .FUNCTION_STARTS,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }

    if (self.data_in_code_cmd_index == null) {
        self.data_in_code_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .linkedit_data = .{
                .cmd = .DATA_IN_CODE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn calcMinHeaderpad(self: *MachO) u64 {
    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        if (lc.cmd() == .NONE) continue;
        sizeofcmds += lc.cmdsize();
    }

    var padding: u32 = sizeofcmds + (self.options.headerpad orelse 0);
    log.debug("minimum requested headerpad size 0x{x}", .{padding + @sizeOf(macho.mach_header_64)});

    if (self.options.headerpad_max_install_names) {
        var min_headerpad_size: u32 = 0;
        for (self.load_commands.items) |lc| switch (lc.cmd()) {
            .ID_DYLIB,
            .LOAD_WEAK_DYLIB,
            .LOAD_DYLIB,
            .REEXPORT_DYLIB,
            => {
                min_headerpad_size += @sizeOf(macho.dylib_command) + std.os.PATH_MAX + 1;
            },

            else => {},
        };
        log.debug("headerpad_max_install_names minimum headerpad size 0x{x}", .{
            min_headerpad_size + @sizeOf(macho.mach_header_64),
        });
        padding = @maximum(padding, min_headerpad_size);
    }
    const offset = @sizeOf(macho.mach_header_64) + padding;
    log.debug("actual headerpad size 0x{x}", .{offset});

    return offset;
}

pub fn allocateGotEntry(self: *MachO, target: SymbolWithLoc) !u32 {
    const gpa = self.base.allocator;
    try self.got_entries.ensureUnusedCapacity(gpa, 1);

    log.debug("  (allocating GOT entry at index {d})", .{self.got_entries.items.len});
    const index = @intCast(u32, self.got_entries.items.len);
    _ = self.got_entries.addOneAssumeCapacity();

    self.got_entries.items[index] = .{ .target = target, .sym_index = 0 };
    try self.got_entries_table.putNoClobber(gpa, target, index);

    return index;
}

pub fn allocateStubEntry(self: *MachO, target: SymbolWithLoc) !u32 {
    try self.stubs.ensureUnusedCapacity(self.base.allocator, 1);

    log.debug("  (allocating stub entry at index {d})", .{self.stubs.items.len});
    const index = @intCast(u32, self.stubs.items.len);
    _ = self.stubs.addOneAssumeCapacity();

    self.stubs.items[index] = .{ .target = target, .sym_index = 0 };
    try self.stubs_table.putNoClobber(self.base.allocator, target, index);

    return index;
}

pub fn allocateTlvPtrEntry(self: *MachO, target: SymbolWithLoc) !u32 {
    try self.tlv_ptr_entries.ensureUnusedCapacity(self.base.allocator, 1);

    log.debug("  (allocating TLV ptr entry at index {d})", .{self.tlv_ptr_entries.items.len});
    const index = @intCast(u32, self.tlv_ptr_entries.items.len);
    _ = self.tlv_ptr_entries.addOneAssumeCapacity();

    self.tlv_ptr_entries.items[index] = .{ .target = target, .sym_index = 0 };
    try self.tlv_ptr_entries_table.putNoClobber(self.base.allocator, target, index);

    return index;
}

fn allocateSymbols(self: *MachO) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const match = entry.key_ptr.*;
        var atom = entry.value_ptr.*;

        while (atom.prev) |prev| {
            atom = prev;
        }

        const n_sect = self.getSectionOrdinal(match);
        const sect = self.getSection(match);
        var base_vaddr = sect.addr;

        log.debug("allocating local symbols in sect({d}, '{s},{s}')", .{ n_sect, sect.segName(), sect.sectName() });

        while (true) {
            const alignment = try math.powi(u32, 2, atom.alignment);
            base_vaddr = mem.alignForwardGeneric(u64, base_vaddr, alignment);

            const sym = atom.getSymbolPtr(self);
            sym.n_value = base_vaddr;
            sym.n_sect = n_sect;

            log.debug("  ATOM(%{d}, '{s}') @{x}", .{ atom.sym_index, atom.getName(self), base_vaddr });

            // Update each symbol contained within the atom
            for (atom.contained.items) |sym_at_off| {
                const contained_sym = self.getSymbolPtr(.{ .sym_index = sym_at_off.sym_index, .file = atom.file });
                contained_sym.n_value = base_vaddr + sym_at_off.offset;
                contained_sym.n_sect = n_sect;
            }

            base_vaddr += atom.size;

            if (atom.next) |next| {
                atom = next;
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
        const seg = self.load_commands.items[self.text_segment_cmd_index.?].segment;
        sym.n_sect = self.getSectionOrdinal(.{
            .seg = self.text_segment_cmd_index.?,
            .sect = 0,
        });
        sym.n_value = seg.inner.vmaddr;

        log.debug("allocating {s} at the start of {s}", .{
            name,
            seg.inner.segName(),
        });
    }
}

fn writeAtoms(self: *MachO) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const sect = self.getSection(entry.key_ptr.*);
        var atom: *Atom = entry.value_ptr.*;

        if (sect.flags == macho.S_ZEROFILL or sect.flags == macho.S_THREAD_LOCAL_ZEROFILL) continue;

        var buffer = std.ArrayList(u8).init(self.base.allocator);
        defer buffer.deinit();
        try buffer.ensureTotalCapacity(math.cast(usize, sect.size) orelse return error.Overflow);

        log.debug("writing atoms in {s},{s}", .{ sect.segName(), sect.sectName() });

        while (atom.prev) |prev| {
            atom = prev;
        }

        while (true) {
            const this_sym = atom.getSymbol(self);
            const padding_size: usize = if (atom.next) |next| blk: {
                const next_sym = next.getSymbol(self);
                const size = next_sym.n_value - (this_sym.n_value + atom.size);
                break :blk math.cast(usize, size) orelse return error.Overflow;
            } else 0;

            log.debug("  (adding ATOM(%{d}, '{s}') from object({d}) to buffer)", .{
                atom.sym_index,
                atom.getName(self),
                atom.file,
            });
            if (padding_size > 0) {
                log.debug("    (with padding {x})", .{padding_size});
            }

            try atom.resolveRelocs(self);
            buffer.appendSliceAssumeCapacity(atom.code.items);

            var i: usize = 0;
            while (i < padding_size) : (i += 1) {
                // TODO with NOPs
                buffer.appendAssumeCapacity(0);
            }

            if (atom.next) |next| {
                atom = next;
            } else {
                assert(buffer.items.len == sect.size);
                log.debug("  (writing at file offset 0x{x})", .{sect.offset});
                try self.base.file.pwriteAll(buffer.items, sect.offset);
                break;
            }
        }
    }
}

fn allocateSegments(self: *MachO) !void {
    try self.allocateSegment(self.text_segment_cmd_index, &.{
        self.pagezero_segment_cmd_index,
    }, self.calcMinHeaderpad());

    if (self.text_segment_cmd_index) |index| blk: {
        const seg = &self.load_commands.items[index].segment;
        if (seg.sections.items.len == 0) break :blk;

        // Shift all sections to the back to minimize jump size between __TEXT and __DATA segments.
        var min_alignment: u32 = 0;
        for (seg.sections.items) |sect| {
            const alignment = try math.powi(u32, 2, sect.@"align");
            min_alignment = math.max(min_alignment, alignment);
        }

        assert(min_alignment > 0);
        const last_sect_idx = seg.sections.items.len - 1;
        const last_sect = seg.sections.items[last_sect_idx];
        const shift: u32 = shift: {
            const diff = seg.inner.filesize - last_sect.offset - last_sect.size;
            const factor = @divTrunc(diff, min_alignment);
            break :shift @intCast(u32, factor * min_alignment);
        };

        if (shift > 0) {
            for (seg.sections.items) |*sect| {
                sect.offset += shift;
                sect.addr += shift;
            }
        }
    }

    try self.allocateSegment(self.data_const_segment_cmd_index, &.{
        self.text_segment_cmd_index,
        self.pagezero_segment_cmd_index,
    }, 0);

    try self.allocateSegment(self.data_segment_cmd_index, &.{
        self.data_const_segment_cmd_index,
        self.text_segment_cmd_index,
        self.pagezero_segment_cmd_index,
    }, 0);

    try self.allocateSegment(self.linkedit_segment_cmd_index, &.{
        self.data_segment_cmd_index,
        self.data_const_segment_cmd_index,
        self.text_segment_cmd_index,
        self.pagezero_segment_cmd_index,
    }, 0);
}

fn allocateSegment(self: *MachO, maybe_index: ?u16, indices: []const ?u16, init_size: u64) !void {
    const index = maybe_index orelse return;
    const seg = &self.load_commands.items[index].segment;

    const base = self.getSegmentAllocBase(indices);
    seg.inner.vmaddr = base.vmaddr;
    seg.inner.fileoff = base.fileoff;
    seg.inner.filesize = init_size;
    seg.inner.vmsize = init_size;

    // Allocate the sections according to their alignment at the beginning of the segment.
    var start = init_size;
    for (seg.sections.items) |*sect| {
        const is_zerofill = sect.flags == macho.S_ZEROFILL or sect.flags == macho.S_THREAD_LOCAL_ZEROFILL;
        const alignment = try math.powi(u32, 2, sect.@"align");
        const start_aligned = mem.alignForwardGeneric(u64, start, alignment);

        // TODO handle zerofill sections in stage2
        sect.offset = if (is_zerofill)
            0
        else
            @intCast(u32, seg.inner.fileoff + start_aligned);
        sect.addr = seg.inner.vmaddr + start_aligned;

        start = start_aligned + sect.size;

        if (!is_zerofill) {
            seg.inner.filesize = start;
        }
        seg.inner.vmsize = start;
    }

    seg.inner.filesize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size);
    seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.vmsize, self.page_size);
}

const InitSectionOpts = struct {
    flags: u32 = macho.S_REGULAR,
    reserved1: u32 = 0,
    reserved2: u32 = 0,
};

fn initSection(
    self: *MachO,
    segment_id: u16,
    sectname: []const u8,
    opts: InitSectionOpts,
) !u16 {
    const seg = &self.load_commands.items[segment_id].segment;
    var sect = macho.section_64{
        .sectname = makeStaticString(sectname),
        .segname = seg.inner.segname,
        .flags = opts.flags,
        .reserved1 = opts.reserved1,
        .reserved2 = opts.reserved2,
    };

    const index = @intCast(u16, seg.sections.items.len);
    try seg.sections.append(self.base.allocator, sect);
    seg.inner.cmdsize += @sizeOf(macho.section_64);
    seg.inner.nsects += 1;

    const match = MatchingSection{
        .seg = segment_id,
        .sect = index,
    };
    _ = try self.section_ordinals.getOrPut(self.base.allocator, match);

    return index;
}

fn writeDyldInfoData(self: *MachO) !void {
    const gpa = self.base.allocator;

    var rebase_pointers = std.ArrayList(bind.Pointer).init(gpa);
    defer rebase_pointers.deinit();
    var bind_pointers = std.ArrayList(bind.Pointer).init(gpa);
    defer bind_pointers.deinit();
    var lazy_bind_pointers = std.ArrayList(bind.Pointer).init(gpa);
    defer lazy_bind_pointers.deinit();

    {
        var it = self.atoms.iterator();
        while (it.next()) |entry| {
            const match = entry.key_ptr.*;
            var atom: *Atom = entry.value_ptr.*;

            if (self.text_segment_cmd_index) |seg| {
                if (match.seg == seg) continue; // __TEXT is non-writable
            }

            const seg = self.getSegment(match);
            const sect = self.getSection(match);
            log.debug("dyld info for {s},{s}", .{ sect.segName(), sect.sectName() });

            while (true) {
                log.debug("  ATOM(%{d}, '{s}')", .{ atom.sym_index, atom.getName(self) });
                const sym = atom.getSymbol(self);
                const base_offset = sym.n_value - seg.inner.vmaddr;

                for (atom.rebases.items) |offset| {
                    log.debug("    | rebase at {x}", .{base_offset + offset});
                    try rebase_pointers.append(.{
                        .offset = base_offset + offset,
                        .segment_id = match.seg,
                    });
                }

                for (atom.bindings.items) |binding| {
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
                    try bind_pointers.append(.{
                        .offset = binding.offset + base_offset,
                        .segment_id = match.seg,
                        .dylib_ordinal = dylib_ordinal,
                        .name = bind_sym_name,
                        .bind_flags = flags,
                    });
                }

                for (atom.lazy_bindings.items) |binding| {
                    const bind_sym = self.getSymbol(binding.target);
                    const bind_sym_name = self.getSymbolName(binding.target);
                    const dylib_ordinal = @divTrunc(
                        @bitCast(i16, bind_sym.n_desc),
                        macho.N_SYMBOL_RESOLVER,
                    );
                    var flags: u4 = 0;
                    log.debug("    | lazy bind at {x} import('{s}') ord({d})", .{
                        binding.offset + base_offset,
                        bind_sym_name,
                        dylib_ordinal,
                    });
                    if (bind_sym.weakRef()) {
                        log.debug("    | marking as weak ref ", .{});
                        flags |= @truncate(u4, macho.BIND_SYMBOL_FLAGS_WEAK_IMPORT);
                    }
                    try lazy_bind_pointers.append(.{
                        .offset = binding.offset + base_offset,
                        .segment_id = match.seg,
                        .dylib_ordinal = dylib_ordinal,
                        .name = bind_sym_name,
                        .bind_flags = flags,
                    });
                }

                if (atom.prev) |prev| {
                    atom = prev;
                } else break;
            }
        }
    }

    var trie: Trie = .{};
    defer trie.deinit(gpa);

    {
        // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
        log.debug("generating export trie", .{});

        const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].segment;
        const base_address = text_segment.inner.vmaddr;

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

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].dyld_info_only;

    const rebase_off = mem.alignForwardGeneric(u64, seg.inner.fileoff, @alignOf(u64));
    const rebase_size = try bind.rebaseInfoSize(rebase_pointers.items);
    dyld_info.rebase_off = @intCast(u32, rebase_off);
    dyld_info.rebase_size = @intCast(u32, rebase_size);
    log.debug("writing rebase info from 0x{x} to 0x{x}", .{
        dyld_info.rebase_off,
        dyld_info.rebase_off + dyld_info.rebase_size,
    });

    const bind_off = mem.alignForwardGeneric(u64, dyld_info.rebase_off + dyld_info.rebase_size, @alignOf(u64));
    const bind_size = try bind.bindInfoSize(bind_pointers.items);
    dyld_info.bind_off = @intCast(u32, bind_off);
    dyld_info.bind_size = @intCast(u32, bind_size);
    log.debug("writing bind info from 0x{x} to 0x{x}", .{
        dyld_info.bind_off,
        dyld_info.bind_off + dyld_info.bind_size,
    });

    const lazy_bind_off = mem.alignForwardGeneric(u64, dyld_info.bind_off + dyld_info.bind_size, @alignOf(u64));
    const lazy_bind_size = try bind.lazyBindInfoSize(lazy_bind_pointers.items);
    dyld_info.lazy_bind_off = @intCast(u32, lazy_bind_off);
    dyld_info.lazy_bind_size = @intCast(u32, lazy_bind_size);
    log.debug("writing lazy bind info from 0x{x} to 0x{x}", .{
        dyld_info.lazy_bind_off,
        dyld_info.lazy_bind_off + dyld_info.lazy_bind_size,
    });

    const export_off = mem.alignForwardGeneric(u64, dyld_info.lazy_bind_off + dyld_info.lazy_bind_size, @alignOf(u64));
    const export_size = trie.size;
    dyld_info.export_off = @intCast(u32, export_off);
    dyld_info.export_size = @intCast(u32, export_size);
    log.debug("writing export trie from 0x{x} to 0x{x}", .{
        dyld_info.export_off,
        dyld_info.export_off + dyld_info.export_size,
    });

    seg.inner.filesize = dyld_info.export_off + dyld_info.export_size - seg.inner.fileoff;

    const needed_size = dyld_info.export_off + dyld_info.export_size - dyld_info.rebase_off;
    var buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);
    mem.set(u8, buffer, 0);

    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();

    const base_off = dyld_info.rebase_off;
    try bind.writeRebaseInfo(rebase_pointers.items, writer);
    try stream.seekTo(dyld_info.bind_off - base_off);

    try bind.writeBindInfo(bind_pointers.items, writer);
    try stream.seekTo(dyld_info.lazy_bind_off - base_off);

    try bind.writeLazyBindInfo(lazy_bind_pointers.items, writer);
    try stream.seekTo(dyld_info.export_off - base_off);

    _ = try trie.write(writer);

    log.debug("writing dyld info from 0x{x} to 0x{x}", .{
        dyld_info.rebase_off,
        dyld_info.rebase_off + needed_size,
    });

    try self.base.file.pwriteAll(buffer, dyld_info.rebase_off);
    try self.populateLazyBindOffsetsInStubHelper(
        buffer[dyld_info.lazy_bind_off - base_off ..][0..dyld_info.lazy_bind_size],
    );
}

fn populateLazyBindOffsetsInStubHelper(self: *MachO, buffer: []const u8) !void {
    const gpa = self.base.allocator;
    const text_segment_cmd_index = self.text_segment_cmd_index orelse return;
    const stub_helper_section_index = self.stub_helper_section_index orelse return;
    const last_atom = self.atoms.get(.{
        .seg = text_segment_cmd_index,
        .sect = stub_helper_section_index,
    }) orelse return;
    if (self.stub_helper_preamble_atom == null) return;
    if (last_atom == self.stub_helper_preamble_atom.?) return;

    var table = std.AutoHashMap(i64, *Atom).init(gpa);
    defer table.deinit();

    {
        var stub_atom = last_atom;
        var laptr_atom = self.atoms.get(.{
            .seg = self.data_segment_cmd_index.?,
            .sect = self.la_symbol_ptr_section_index.?,
        }).?;
        const base_addr = blk: {
            const seg = self.load_commands.items[self.data_segment_cmd_index.?].segment;
            break :blk seg.inner.vmaddr;
        };

        while (true) {
            const laptr_off = blk: {
                const sym = laptr_atom.getSymbol(self);
                break :blk @intCast(i64, sym.n_value - base_addr);
            };
            try table.putNoClobber(laptr_off, stub_atom);
            if (laptr_atom.prev) |prev| {
                laptr_atom = prev;
                stub_atom = stub_atom.prev.?;
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

    const sect = self.getSection(.{
        .seg = text_segment_cmd_index,
        .sect = stub_helper_section_index,
    });
    const stub_offset: u4 = switch (self.options.target.cpu_arch.?) {
        .x86_64 => 1,
        .aarch64 => 2 * @sizeOf(u32),
        else => unreachable,
    };
    var buf: [@sizeOf(u32)]u8 = undefined;
    _ = offsets.pop();

    while (offsets.popOrNull()) |bind_offset| {
        const atom = table.get(bind_offset.sym_offset).?;
        const sym = atom.getSymbol(self);
        const file_offset = sect.offset + sym.n_value - sect.addr + stub_offset;
        mem.writeIntLittle(u32, &buf, bind_offset.offset);
        log.debug("writing lazy bind offset in stub helper of 0x{x} for symbol {s} at offset 0x{x}", .{
            bind_offset.offset,
            atom.getName(self),
            file_offset,
        });
        try self.base.file.pwriteAll(&buf, file_offset);
    }
}

const asc_u64 = std.sort.asc(u64);

fn writeFunctionStarts(self: *MachO) !void {
    const text_seg_index = self.text_segment_cmd_index orelse return;
    const text_sect_index = self.text_section_index orelse return;
    const text_seg = self.load_commands.items[text_seg_index].segment;

    const gpa = self.base.allocator;

    // We need to sort by address first
    var addresses = std.ArrayList(u64).init(gpa);
    defer addresses.deinit();
    try addresses.ensureTotalCapacityPrecise(self.globals.count());

    for (self.globals.values()) |global| {
        const sym = self.getSymbol(global);
        if (sym.undf()) continue;
        if (sym.n_desc == N_DESC_GCED) continue;
        const match = self.getMatchingSectionFromOrdinal(sym.n_sect);
        if (match.seg != text_seg_index or match.sect != text_sect_index) continue;

        addresses.appendAssumeCapacity(sym.n_value);
    }

    std.sort.sort(u64, addresses.items, {}, asc_u64);

    var offsets = std.ArrayList(u32).init(gpa);
    defer offsets.deinit();
    try offsets.ensureTotalCapacityPrecise(addresses.items.len);

    var last_off: u32 = 0;
    for (addresses.items) |addr| {
        const offset = @intCast(u32, addr - text_seg.inner.vmaddr);
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

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    const fn_cmd = &self.load_commands.items[self.function_starts_cmd_index.?].linkedit_data;

    const dataoff = mem.alignForwardGeneric(u64, seg.inner.fileoff + seg.inner.filesize, @alignOf(u64));
    const datasize = buffer.items.len;
    fn_cmd.dataoff = @intCast(u32, dataoff);
    fn_cmd.datasize = @intCast(u32, datasize);
    seg.inner.filesize = fn_cmd.dataoff + fn_cmd.datasize - seg.inner.fileoff;

    log.debug("writing function starts info from 0x{x} to 0x{x}", .{
        fn_cmd.dataoff,
        fn_cmd.dataoff + fn_cmd.datasize,
    });

    try self.base.file.pwriteAll(buffer.items, fn_cmd.dataoff);
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

fn writeDataInCode(self: *MachO) !void {
    var out_dice = std.ArrayList(macho.data_in_code_entry).init(self.base.allocator);
    defer out_dice.deinit();

    const text_sect = self.getSection(.{
        .seg = self.text_segment_cmd_index orelse return,
        .sect = self.text_section_index orelse return,
    });

    for (self.objects.items) |object| {
        const dice = object.parseDataInCode() orelse continue;
        try out_dice.ensureUnusedCapacity(dice.len);

        for (object.managed_atoms.items) |atom| {
            const sym = atom.getSymbol(self);
            if (sym.n_desc == N_DESC_GCED) continue;

            const match = self.getMatchingSectionFromOrdinal(sym.n_sect);
            if (match.seg != self.text_segment_cmd_index.? and match.sect != self.text_section_index.?) {
                continue;
            }

            const source_sym = object.getSourceSymbol(atom.sym_index) orelse continue;
            const source_addr = math.cast(u32, source_sym.n_value) orelse return error.Overflow;
            const filtered_dice = filterDataInCode(dice, source_addr, source_addr + atom.size);
            const base = math.cast(u32, sym.n_value - text_sect.addr + text_sect.offset) orelse
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

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    const dice_cmd = &self.load_commands.items[self.data_in_code_cmd_index.?].linkedit_data;

    const dataoff = mem.alignForwardGeneric(u64, seg.inner.fileoff + seg.inner.filesize, @alignOf(u64));
    const datasize = out_dice.items.len * @sizeOf(macho.data_in_code_entry);
    dice_cmd.dataoff = @intCast(u32, dataoff);
    dice_cmd.datasize = @intCast(u32, datasize);
    seg.inner.filesize = dice_cmd.dataoff + dice_cmd.datasize - seg.inner.fileoff;

    log.debug("writing data-in-code from 0x{x} to 0x{x}", .{
        dice_cmd.dataoff,
        dice_cmd.dataoff + dice_cmd.datasize,
    });

    try self.base.file.pwriteAll(mem.sliceAsBytes(out_dice.items), dice_cmd.dataoff);
}

fn writeSymtab(self: *MachO) !void {
    const gpa = self.base.allocator;
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].symtab;
    const symoff = mem.alignForwardGeneric(u64, seg.inner.fileoff + seg.inner.filesize, @alignOf(macho.nlist_64));
    symtab.symoff = @intCast(u32, symoff);

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
    defer imports_table.deinit();

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

    const nlocals = locals.items.len;
    const nexports = exports.items.len;
    const nimports = imports.items.len;
    symtab.nsyms = @intCast(u32, nlocals + nexports + nimports);

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(symtab.nsyms * @sizeOf(macho.nlist_64));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(locals.items));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(exports.items));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(imports.items));

    log.debug("writing symtab from 0x{x} to 0x{x}", .{ symtab.symoff, symtab.symoff + buffer.items.len });
    try self.base.file.pwriteAll(buffer.items, symtab.symoff);

    seg.inner.filesize = symtab.symoff + buffer.items.len - seg.inner.fileoff;

    // Update dynamic symbol table.
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].dysymtab;
    dysymtab.nlocalsym = @intCast(u32, nlocals);
    dysymtab.iextdefsym = dysymtab.nlocalsym;
    dysymtab.nextdefsym = @intCast(u32, nexports);
    dysymtab.iundefsym = dysymtab.nlocalsym + dysymtab.nextdefsym;
    dysymtab.nundefsym = @intCast(u32, nimports);

    const nstubs = @intCast(u32, self.stubs_table.count());
    const ngot_entries = @intCast(u32, self.got_entries_table.count());

    const indirectsymoff = mem.alignForwardGeneric(u64, seg.inner.fileoff + seg.inner.filesize, @alignOf(u64));
    dysymtab.indirectsymoff = @intCast(u32, indirectsymoff);
    dysymtab.nindirectsyms = nstubs * 2 + ngot_entries;

    seg.inner.filesize = dysymtab.indirectsymoff + dysymtab.nindirectsyms * @sizeOf(u32) - seg.inner.fileoff;

    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{
        dysymtab.indirectsymoff,
        dysymtab.indirectsymoff + dysymtab.nindirectsyms * @sizeOf(u32),
    });

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();
    try buf.ensureTotalCapacity(dysymtab.nindirectsyms * @sizeOf(u32));
    const writer = buf.writer();

    if (self.text_segment_cmd_index) |text_segment_cmd_index| blk: {
        const stubs_section_index = self.stubs_section_index orelse break :blk;
        const stubs = self.getSectionPtr(.{
            .seg = text_segment_cmd_index,
            .sect = stubs_section_index,
        });
        stubs.reserved1 = 0;
        for (self.stubs.items) |entry| {
            if (entry.sym_index == 0) continue;
            const atom_sym = entry.getSymbol(self);
            if (atom_sym.n_desc == N_DESC_GCED) continue;
            const target_sym = self.getSymbol(entry.target);
            assert(target_sym.undf());
            try writer.writeIntLittle(u32, dysymtab.iundefsym + imports_table.get(entry.target).?);
        }
    }

    if (self.data_const_segment_cmd_index) |data_const_segment_cmd_index| blk: {
        const got_section_index = self.got_section_index orelse break :blk;
        const got = self.getSectionPtr(.{
            .seg = data_const_segment_cmd_index,
            .sect = got_section_index,
        });
        got.reserved1 = nstubs;
        for (self.got_entries.items) |entry| {
            if (entry.sym_index == 0) continue;
            const atom_sym = entry.getSymbol(self);
            if (atom_sym.n_desc == N_DESC_GCED) continue;
            const target_sym = self.getSymbol(entry.target);
            if (target_sym.undf()) {
                try writer.writeIntLittle(u32, dysymtab.iundefsym + imports_table.get(entry.target).?);
            } else {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            }
        }
    }

    if (self.data_segment_cmd_index) |data_segment_cmd_index| blk: {
        const la_symbol_ptr_section_index = self.la_symbol_ptr_section_index orelse break :blk;
        const la_symbol_ptr = self.getSectionPtr(.{
            .seg = data_segment_cmd_index,
            .sect = la_symbol_ptr_section_index,
        });
        la_symbol_ptr.reserved1 = nstubs + ngot_entries;
        for (self.stubs.items) |entry| {
            if (entry.sym_index == 0) continue;
            const atom_sym = entry.getSymbol(self);
            if (atom_sym.n_desc == N_DESC_GCED) continue;
            const target_sym = self.getSymbol(entry.target);
            assert(target_sym.undf());
            try writer.writeIntLittle(u32, dysymtab.iundefsym + imports_table.get(entry.target).?);
        }
    }

    assert(buf.items.len == dysymtab.nindirectsyms * @sizeOf(u32));

    try self.base.file.pwriteAll(buf.items, dysymtab.indirectsymoff);
}

fn writeStrtab(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].symtab;
    const stroff = mem.alignForwardGeneric(u64, seg.inner.fileoff + seg.inner.filesize, @alignOf(u64));

    const strsize = self.strtab.buffer.items.len;
    symtab.stroff = @intCast(u32, stroff);
    symtab.strsize = @intCast(u32, strsize);
    seg.inner.filesize = symtab.stroff + symtab.strsize - seg.inner.fileoff;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.base.file.pwriteAll(self.strtab.buffer.items, symtab.stroff);
}

fn writeLinkeditSegment(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    seg.inner.filesize = 0;

    try self.writeDyldInfoData();
    try self.writeFunctionStarts();
    try self.writeDataInCode();
    try self.writeSymtab();
    try self.writeStrtab();

    seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size);
}

fn writeCodeSignaturePadding(self: *MachO, code_sig: *CodeSignature) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].segment;
    const cs_cmd = &self.load_commands.items[self.code_signature_cmd_index.?].linkedit_data;
    // Code signature data has to be 16-bytes aligned for Apple tools to recognize the file
    // https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/libstuff/checkout.c#L271
    const dataoff = mem.alignForwardGeneric(u64, seg.inner.fileoff + seg.inner.filesize, 16);
    const datasize = code_sig.estimateSize(dataoff);
    cs_cmd.dataoff = @intCast(u32, dataoff);
    cs_cmd.datasize = @intCast(u32, code_sig.estimateSize(dataoff));

    // Advance size of __LINKEDIT segment
    seg.inner.filesize = cs_cmd.dataoff + cs_cmd.datasize - seg.inner.fileoff;
    seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size);
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ dataoff, dataoff + datasize });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.base.file.pwriteAll(&[_]u8{0}, dataoff + datasize - 1);
}

fn writeCodeSignature(self: *MachO, code_sig: *CodeSignature) !void {
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd_index.?].linkedit_data;
    const seg = self.load_commands.items[self.text_segment_cmd_index.?].segment;

    var buffer = std.ArrayList(u8).init(self.base.allocator);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(code_sig.size());
    try code_sig.writeAdhocSignature(self.base.allocator, .{
        .file = self.base.file,
        .exec_seg_base = seg.inner.fileoff,
        .exec_seg_limit = seg.inner.filesize,
        .code_sig_cmd = code_sig_cmd,
        .output_mode = self.options.output_mode,
    }, buffer.writer());
    assert(buffer.items.len == code_sig.size());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{
        code_sig_cmd.dataoff,
        code_sig_cmd.dataoff + buffer.items.len,
    });

    try self.base.file.pwriteAll(buffer.items, code_sig_cmd.dataoff);
}

/// Writes all load commands and section headers.
fn writeLoadCommands(self: *MachO) !void {
    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        if (lc.cmd() == .NONE) continue;
        sizeofcmds += lc.cmdsize();
    }

    var buffer = try self.base.allocator.alloc(u8, sizeofcmds);
    defer self.base.allocator.free(buffer);
    var fib = std.io.fixedBufferStream(buffer);
    const writer = fib.writer();
    for (self.load_commands.items) |lc| {
        if (lc.cmd() == .NONE) continue;
        try lc.write(writer);
    }

    const off = @sizeOf(macho.mach_header_64);

    log.debug("writing load commands from 0x{x} to 0x{x}", .{ off, off + sizeofcmds });

    try self.base.file.pwriteAll(buffer, off);
}

/// Writes Mach-O file header.
fn writeHeader(self: *MachO) !void {
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

    if (self.tlv_section_index) |_| {
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
    }

    header.ncmds = 0;
    header.sizeofcmds = 0;

    for (self.load_commands.items) |cmd| {
        if (cmd.cmd() == .NONE) continue;
        header.sizeofcmds += cmd.cmdsize();
        header.ncmds += 1;
    }

    log.debug("writing Mach-O header {}", .{header});

    try self.base.file.pwriteAll(mem.asBytes(&header), 0);
}

pub fn makeStaticString(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    assert(bytes.len <= buf.len);
    mem.copy(u8, &buf, bytes);
    return buf;
}

pub fn getSectionOrdinal(self: *MachO, match: MatchingSection) u8 {
    return @intCast(u8, self.section_ordinals.getIndex(match).?) + 1;
}

pub fn getMatchingSectionFromOrdinal(self: *MachO, ord: u8) MatchingSection {
    const index = ord - 1;
    assert(index < self.section_ordinals.count());
    return self.section_ordinals.keys()[index];
}

pub fn getSegmentPtr(self: *MachO, match: MatchingSection) *macho.SegmentCommand {
    assert(match.seg < self.load_commands.items.len);
    return &self.load_commands.items[match.seg].segment;
}

pub fn getSegment(self: *MachO, match: MatchingSection) macho.SegmentCommand {
    return self.getSegmentPtr(match).*;
}

pub fn getSectionPtr(self: *MachO, match: MatchingSection) *macho.section_64 {
    const seg = self.getSegmentPtr(match);
    assert(match.sect < seg.sections.items.len);
    return &seg.sections.items[match.sect];
}

pub fn getSection(self: *MachO, match: MatchingSection) macho.section_64 {
    return self.getSectionPtr(match).*;
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
pub fn getAtomForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?*Atom {
    if (sym_with_loc.file) |file| {
        const object = self.objects.items[file];
        return object.getAtomForSymbol(sym_with_loc.sym_index);
    } else {
        return self.atom_by_index_table.get(sym_with_loc.sym_index);
    }
}

/// Returns GOT atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getGotAtomForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?*Atom {
    const got_index = self.got_entries_table.get(sym_with_loc) orelse return null;
    return self.got_entries.items[got_index].getAtom(self);
}

/// Returns stubs atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getStubsAtomForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?*Atom {
    const stubs_index = self.stubs_table.get(sym_with_loc) orelse return null;
    return self.stubs.items[stubs_index].getAtom(self);
}

/// Returns TLV pointer atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getTlvPtrAtomForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?*Atom {
    const tlv_ptr_index = self.tlv_ptr_entries_table.get(sym_with_loc) orelse return null;
    return self.tlv_ptr_entries.items[tlv_ptr_index].getAtom(self);
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

pub fn findFirst(comptime T: type, haystack: []const T, start: usize, predicate: anytype) usize {
    if (!@hasDecl(@TypeOf(predicate), "predicate"))
        @compileError("Predicate is required to define fn predicate(@This(), T) bool");

    if (start == haystack.len) return start;

    var i = start;
    while (i < haystack.len) : (i += 1) {
        if (predicate.predicate(haystack[i])) break;
    }
    return i;
}

const DebugInfo = struct {
    inner: dwarf.DwarfInfo,
    debug_info: []const u8,
    debug_abbrev: []const u8,
    debug_str: []const u8,
    debug_line: []const u8,
    debug_line_str: []const u8,
    debug_ranges: []const u8,

    pub fn parse(allocator: Allocator, object: Object) !?DebugInfo {
        var debug_info = blk: {
            const index = object.dwarf_debug_info_index orelse return null;
            break :blk try object.getSectionContents(index);
        };
        var debug_abbrev = blk: {
            const index = object.dwarf_debug_abbrev_index orelse return null;
            break :blk try object.getSectionContents(index);
        };
        var debug_str = blk: {
            const index = object.dwarf_debug_str_index orelse return null;
            break :blk try object.getSectionContents(index);
        };
        var debug_line = blk: {
            const index = object.dwarf_debug_line_index orelse return null;
            break :blk try object.getSectionContents(index);
        };
        var debug_line_str = blk: {
            if (object.dwarf_debug_line_str_index) |ind| {
                break :blk try object.getSectionContents(ind);
            }
            break :blk &[0]u8{};
        };
        var debug_ranges = blk: {
            if (object.dwarf_debug_ranges_index) |ind| {
                break :blk try object.getSectionContents(ind);
            }
            break :blk &[0]u8{};
        };

        var inner: dwarf.DwarfInfo = .{
            .endian = .Little,
            .debug_info = debug_info,
            .debug_abbrev = debug_abbrev,
            .debug_str = debug_str,
            .debug_line = debug_line,
            .debug_line_str = debug_line_str,
            .debug_ranges = debug_ranges,
        };
        try dwarf.openDwarfDebugInfo(&inner, allocator);

        return DebugInfo{
            .inner = inner,
            .debug_info = debug_info,
            .debug_abbrev = debug_abbrev,
            .debug_str = debug_str,
            .debug_line = debug_line,
            .debug_line_str = debug_line_str,
            .debug_ranges = debug_ranges,
        };
    }

    pub fn deinit(self: *DebugInfo, allocator: Allocator) void {
        self.inner.deinit(allocator);
    }
};

pub fn generateSymbolStabs(
    self: *MachO,
    object: Object,
    locals: *std.ArrayList(macho.nlist_64),
) !void {
    assert(!self.options.strip);

    const gpa = self.base.allocator;

    log.debug("parsing debug info in '{s}'", .{object.name});

    var debug_info = (try DebugInfo.parse(gpa, object)) orelse return;
    defer debug_info.deinit(gpa);

    // We assume there is only one CU.
    const compile_unit = debug_info.inner.findCompileUnit(0x0) catch |err| switch (err) {
        error.MissingDebugInfo => {
            // TODO audit cases with missing debug info and audit our dwarf.zig module.
            log.debug("invalid or missing debug info in {s}; skipping", .{object.name});
            return;
        },
        else => |e| return e,
    };
    const tu_name = try compile_unit.die.getAttrString(&debug_info.inner, dwarf.AT.name);
    const tu_comp_dir = try compile_unit.die.getAttrString(&debug_info.inner, dwarf.AT.comp_dir);

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

    for (object.managed_atoms.items) |atom| {
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
    debug_info: DebugInfo,
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
        for (debug_info.inner.func_list.items) |func| {
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
            self.strtab.get(sym.n_strx),
            sym.n_value,
            where,
            def_index,
            logSymAttributes(sym, &buf),
        });
    }

    log.debug("globals table:", .{});
    for (self.globals.keys()) |name, id| {
        const value = self.globals.values()[id];
        log.debug("  {s} => %{d} in object({d})", .{ name, value.sym_index, value.file });
    }

    log.debug("GOT entries:", .{});
    for (self.got_entries.items) |entry, i| {
        const atom_sym = entry.getSymbol(self);
        if (atom_sym.n_desc == N_DESC_GCED) continue;
        const target_sym = self.getSymbol(entry.target);
        if (target_sym.undf()) {
            log.debug("  {d}@{x} => import('{s}')", .{
                i,
                atom_sym.n_value,
                self.getSymbolName(entry.target),
            });
        } else {
            log.debug("  {d}@{x} => local(%{d}) in object({d}) {s}", .{
                i,
                atom_sym.n_value,
                entry.target.sym_index,
                entry.target.file,
                logSymAttributes(target_sym, &buf),
            });
        }
    }

    log.debug("__thread_ptrs entries:", .{});
    for (self.tlv_ptr_entries.items) |entry, i| {
        const atom_sym = entry.getSymbol(self);
        if (atom_sym.n_desc == N_DESC_GCED) continue;
        const target_sym = self.getSymbol(entry.target);
        assert(target_sym.undf());
        log.debug("  {d}@{x} => import('{s}')", .{
            i,
            atom_sym.n_value,
            self.getSymbolName(entry.target),
        });
    }

    log.debug("stubs entries:", .{});
    for (self.stubs.items) |entry, i| {
        const target_sym = self.getSymbol(entry.target);
        const atom_sym = entry.getSymbol(self);
        assert(target_sym.undf());
        log.debug("  {d}@{x} => import('{s}')", .{
            i,
            atom_sym.n_value,
            self.getSymbolName(entry.target),
        });
    }
}

fn logSectionOrdinals(self: *MachO) void {
    for (self.section_ordinals.keys()) |match, i| {
        const sect = self.getSection(match);
        log.debug("sect({d}, '{s},{s}')", .{ i + 1, sect.segName(), sect.sectName() });
    }
}

fn logAtoms(self: *MachO) void {
    log.debug("atoms:", .{});
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const match = entry.key_ptr.*;
        var atom = entry.value_ptr.*;

        while (atom.prev) |prev| {
            atom = prev;
        }

        const sect = self.getSection(match);
        log.debug("{s},{s}", .{ sect.segName(), sect.sectName() });

        while (true) {
            self.logAtom(atom);
            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }
}

pub fn logAtom(self: *MachO, atom: *const Atom) void {
    const sym = atom.getSymbol(self);
    const sym_name = atom.getName(self);
    log.debug("  ATOM(%{d}, '{s}') @ {x} (sizeof({x}), alignof({x})) in object({d}) in sect({d})", .{
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
