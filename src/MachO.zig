const MachO = @This();

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.zld);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const aarch64 = @import("aarch64.zig");
const bind = @import("MachO/bind.zig");
const commands = @import("MachO/commands.zig");

const Allocator = mem.Allocator;
const Archive = @import("MachO/Archive.zig");
const Atom = @import("MachO/Atom.zig");
const CodeSignature = @import("MachO/CodeSignature.zig");
const Dylib = @import("MachO/Dylib.zig");
const Object = @import("MachO/Object.zig");
const LibStub = @import("tapi.zig").LibStub;
const LoadCommand = commands.LoadCommand;
const SegmentCommand = commands.SegmentCommand;
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;
const Trie = @import("MachO/Trie.zig");
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.macho;

base: Zld,

/// Page size is dependent on the target cpu architecture.
/// For x86_64 that's 4KB, whereas for aarch64, that's 16KB.
page_size: u16,

/// TODO Should we figure out embedding code signatures for other Apple platforms as part of the linker?
/// Or should this be a separate tool?
/// https://github.com/ziglang/zig/issues/9567
requires_adhoc_codesig: bool,

/// We commit 0x1000 = 4096 bytes of space to the header and
/// the table of load commands. This should be plenty for any
/// potential future extensions.
header_pad: u16 = 0x1000,

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
la_symbol_ptr_section_index: ?u16 = null,
data_section_index: ?u16 = null,
bss_section_index: ?u16 = null,

objc_const_section_index: ?u16 = null,
objc_selrefs_section_index: ?u16 = null,
objc_classrefs_section_index: ?u16 = null,
objc_data_section_index: ?u16 = null,

locals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
globals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
undefs: std.ArrayListUnmanaged(macho.nlist_64) = .{},
symbol_resolver: std.AutoHashMapUnmanaged(u32, SymbolWithLoc) = .{},
unresolved: std.AutoArrayHashMapUnmanaged(u32, void) = .{},
tentatives: std.AutoArrayHashMapUnmanaged(u32, void) = .{},

dyld_stub_binder_index: ?u32 = null,
dyld_private_atom: ?*Atom = null,
stub_helper_preamble_atom: ?*Atom = null,

strtab: std.ArrayListUnmanaged(u8) = .{},
strtab_dir: std.HashMapUnmanaged(u32, void, StringIndexContext, std.hash_map.default_max_load_percentage) = .{},

got_entries_map: std.AutoArrayHashMapUnmanaged(GotIndirectionKey, *Atom) = .{},
stubs_map: std.AutoArrayHashMapUnmanaged(u32, *Atom) = .{},

has_dices: bool = false,
has_stabs: bool = false,

section_ordinals: std.AutoArrayHashMapUnmanaged(MatchingSection, void) = .{},

/// Pointer to the last allocated atom
atoms: std.AutoHashMapUnmanaged(MatchingSection, *Atom) = .{},

/// List of atoms that are owned directly by the linker.
/// Currently these are only atoms that are the result of linking
/// object files. Atoms which take part in incremental linking are
/// at present owned by Module.Decl.
/// TODO consolidate this.
managed_atoms: std.ArrayListUnmanaged(*Atom) = .{},

const SymbolWithLoc = struct {
    // Table where the symbol can be found.
    where: enum {
        global,
        undef,
    },
    where_index: u32,
    local_sym_index: u32 = 0,
    file: ?u16 = null, // null means Zig module
};

pub const GotIndirectionKey = struct {
    where: enum {
        local,
        undef,
    },
    where_index: u32,
};

/// Default path to dyld
const default_dyld_path: [*:0]const u8 = "/usr/lib/dyld";

/// Virtual memory offset corresponds to the size of __PAGEZERO segment and start of
/// __TEXT segment.
const pagezero_vmsize: u64 = 0x100000000;

pub fn openPath(allocator: *Allocator, options: Zld.Options) !*MachO {
    const file = try options.emit.directory.createFile(options.emit.sub_path, .{
        .truncate = true,
        .read = false,
        .mode = 0o777,
    });
    errdefer file.close();

    const self = try createEmpty(allocator, options);
    errdefer self.base.destroy();

    self.base.file = file;

    return self;
}

fn createEmpty(gpa: *Allocator, options: Zld.Options) !*MachO {
    const self = try gpa.create(MachO);
    const cpu_arch = options.target.cpu.arch;
    const os_tag = options.target.os.tag;
    const abi = options.target.abi;
    const page_size: u16 = if (cpu_arch == .aarch64) 0x4000 else 0x1000;
    // Adhoc code signature is required when targeting aarch64-macos either directly or indirectly via the simulator
    // ABI such as aarch64-ios-simulator, etc.
    const requires_adhoc_codesig = cpu_arch == .aarch64 and (os_tag == .macos or abi == .simulator);

    self.* = .{
        .base = .{
            .tag = .macho,
            .options = options,
            .allocator = gpa,
            .file = undefined,
        },
        .page_size = page_size,
        .requires_adhoc_codesig = requires_adhoc_codesig,
    };

    return self;
}

pub fn flush(self: *MachO) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(self.base.allocator);
    defer arena_allocator.deinit();
    const arena = &arena_allocator.allocator;

    var lib_dirs = std.ArrayList([]const u8).init(arena);
    for (self.base.options.lib_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, self.base.options.syslibroot)) |search_dir| {
            try lib_dirs.append(search_dir);
        } else {
            log.warn("directory not found for '-L{s}'", .{dir});
        }
    }

    var libs = std.ArrayList([]const u8).init(arena);
    var lib_not_found = false;
    for (self.base.options.libs) |lib_name| {
        // Assume ld64 default: -search_paths_first
        // Look in each directory for a dylib (stub first), and then for archive
        // TODO implement alternative: -search_dylibs_first
        for (&[_][]const u8{ ".tbd", ".dylib", ".a" }) |ext| {
            if (try resolveLib(arena, lib_dirs.items, lib_name, ext)) |full_path| {
                try libs.append(full_path);
                break;
            }
        } else {
            log.warn("library not found for '-l{s}'", .{lib_name});
            lib_not_found = true;
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
    for (self.base.options.framework_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, self.base.options.syslibroot)) |search_dir| {
            try framework_dirs.append(search_dir);
        } else {
            log.warn("directory not found for '-F{s}'", .{dir});
        }
    }

    var framework_not_found = false;
    for (self.base.options.frameworks) |framework| {
        for (&[_][]const u8{ ".tbd", ".dylib", "" }) |ext| {
            if (try resolveFramework(arena, framework_dirs.items, framework, ext)) |full_path| {
                try libs.append(full_path);
                break;
            }
        } else {
            log.warn("framework not found for '-framework {s}'", .{framework});
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
    for (self.base.options.rpath_list) |rpath| {
        if (rpath_table.contains(rpath)) continue;
        try rpath_table.putNoClobber(rpath, {});
    }

    try self.strtab.append(self.base.allocator, 0);
    try self.populateMetadata();
    try self.parseInputFiles(self.base.options.positionals, self.base.options.syslibroot);
    try self.parseLibs(libs.items, self.base.options.syslibroot);

    for (self.objects.items) |_, object_id| {
        try self.resolveSymbolsInObject(@intCast(u16, object_id));
    }

    try self.resolveSymbolsInArchives();
    try self.resolveDyldStubBinder();
    try self.createDyldPrivateAtom();
    try self.createStubHelperPreambleAtom();
    try self.resolveSymbolsInDylibs();
    try self.createDsoHandleAtom();

    for (self.unresolved.keys()) |index| {
        const sym = self.undefs.items[index];
        const sym_name = self.getString(sym.n_strx);
        const resolv = self.symbol_resolver.get(sym.n_strx) orelse unreachable;

        log.err("undefined reference to symbol '{s}'", .{sym_name});
        if (resolv.file) |file| {
            log.err("  first referenced in '{s}'", .{self.objects.items[file].name});
        }
    }
    if (self.unresolved.count() > 0) {
        return error.UndefinedSymbolReference;
    }

    try self.createTentativeDefAtoms();
    for (self.objects.items) |*object| {
        try object.parseIntoAtoms(self.base.allocator, self);
    }

    try self.sortSections();
    try self.addRpathLCs(rpath_table.keys());
    try self.addLoadDylibLCs();
    try self.addDataInCodeLC();
    try self.addCodeSignatureLC();
    try self.allocateTextSegment();
    try self.allocateDataConstSegment();
    try self.allocateDataSegment();
    self.allocateLinkeditSegment();
    try self.allocateAtoms();
    try self.writeAtoms();

    if (self.bss_section_index) |idx| {
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[idx];
        sect.offset = 0;
    }
    if (self.tlv_bss_section_index) |idx| {
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        const sect = &seg.sections.items[idx];
        sect.offset = 0;
    }

    try self.setEntryPoint();
    try self.writeLinkeditSegment();

    if (self.requires_adhoc_codesig) {
        // Preallocate space for the code signature.
        // We need to do this at this stage so that we have the load commands with proper values
        // written out to the file.
        // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
        // where the code signature goes into.
        try self.writeCodeSignaturePadding();
    }

    try self.writeLoadCommands();
    try self.writeHeader();

    if (self.requires_adhoc_codesig) {
        try self.writeCodeSignature(); // code signing always comes last
    }
}

fn resolveSearchDir(
    arena: *Allocator,
    dir: []const u8,
    syslibroot: ?[]const u8,
) !?[]const u8 {
    var candidates = std.ArrayList([]const u8).init(arena);

    if (fs.path.isAbsolute(dir)) {
        if (syslibroot) |root| {
            const common_dir = if (std.Target.current.os.tag == .windows) blk: {
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

fn resolveLib(
    arena: *Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "lib{s}{s}", .{ name, ext });

    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, search_name });

        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return full_path;
    }

    return null;
}

fn resolveFramework(
    arena: *Allocator,
    search_dirs: []const []const u8,
    name: []const u8,
    ext: []const u8,
) !?[]const u8 {
    const search_name = try std.fmt.allocPrint(arena, "{s}{s}", .{ name, ext });
    const prefix_path = try std.fmt.allocPrint(arena, "{s}.framework", .{name});

    for (search_dirs) |dir| {
        const full_path = try fs.path.join(arena, &[_][]const u8{ dir, prefix_path, search_name });

        // Check if the file exists.
        const tmp = fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer tmp.close();

        return full_path;
    }

    return null;
}

fn parseObject(self: *MachO, path: []const u8) !bool {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    var object = Object{
        .name = name,
        .file = file,
    };

    object.parse(self.base.allocator, self.base.options.target) catch |err| switch (err) {
        error.EndOfStream, error.NotObject => {
            object.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.objects.append(self.base.allocator, object);

    return true;
}

fn parseArchive(self: *MachO, path: []const u8) !bool {
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

    archive.parse(self.base.allocator, self.base.options.target) catch |err| switch (err) {
        error.EndOfStream, error.NotArchive => {
            archive.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.archives.append(self.base.allocator, archive);

    return true;
}

const ParseDylibError = error{
    OutOfMemory,
    EmptyStubFile,
    MismatchedCpuArchitecture,
    UnsupportedCpuArchitecture,
} || fs.File.OpenError || std.os.PReadError || Dylib.Id.ParseError;

const DylibCreateOpts = struct {
    syslibroot: ?[]const u8 = null,
    id: ?Dylib.Id = null,
    is_dependent: bool = false,
};

pub fn parseDylib(self: *MachO, path: []const u8, opts: DylibCreateOpts) ParseDylibError!bool {
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    errdefer file.close();

    const name = try self.base.allocator.dupe(u8, path);
    errdefer self.base.allocator.free(name);

    var dylib = Dylib{
        .name = name,
        .file = file,
    };

    dylib.parse(self.base.allocator, self.base.options.target) catch |err| switch (err) {
        error.EndOfStream, error.NotDylib => {
            try file.seekTo(0);

            var lib_stub = LibStub.loadFromFile(self.base.allocator, file) catch {
                dylib.deinit(self.base.allocator);
                return false;
            };
            defer lib_stub.deinit();

            try dylib.parseFromStub(self.base.allocator, self.base.options.target, lib_stub);
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

    if (self.dylibs_map.contains(dylib.id.?.name)) {
        // Hmm, seems we already parsed this dylib.
        return true;
    }

    const dylib_id = @intCast(u16, self.dylibs.items.len);
    try self.dylibs.append(self.base.allocator, dylib);
    try self.dylibs_map.putNoClobber(self.base.allocator, dylib.id.?.name, dylib_id);

    if (!(opts.is_dependent or self.referenced_dylibs.contains(dylib_id))) {
        try self.referenced_dylibs.putNoClobber(self.base.allocator, dylib_id, {});
    }

    // TODO this should not be performed if the user specifies `-flat_namespace` flag.
    // See ld64 manpages.
    try dylib.parseDependentLibs(self, opts.syslibroot);

    return true;
}

fn parseInputFiles(self: *MachO, files: []const []const u8, syslibroot: ?[]const u8) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };
        defer self.base.allocator.free(full_path);
        log.debug("parsing input file path '{s}'", .{full_path});

        if (try self.parseObject(full_path)) continue;
        if (try self.parseArchive(full_path)) continue;
        if (try self.parseDylib(full_path, .{
            .syslibroot = syslibroot,
        })) continue;

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseLibs(self: *MachO, libs: []const []const u8, syslibroot: ?[]const u8) !void {
    for (libs) |lib| {
        log.debug("parsing lib path '{s}'", .{lib});
        if (try self.parseDylib(lib, .{
            .syslibroot = syslibroot,
        })) continue;
        if (try self.parseArchive(lib)) continue;

        log.warn("unknown filetype for a library: '{s}'", .{lib});
    }
}

pub const MatchingSection = struct {
    seg: u16,
    sect: u16,
};

pub fn getMatchingSection(self: *MachO, sect: macho.section_64) !?MatchingSection {
    const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const segname = commands.segmentName(sect);
    const sectname = commands.sectionName(sect);

    const res: ?MatchingSection = blk: {
        switch (commands.sectionType(sect)) {
            macho.S_4BYTE_LITERALS, macho.S_8BYTE_LITERALS, macho.S_16BYTE_LITERALS => {
                if (self.text_const_section_index == null) {
                    self.text_const_section_index = @intCast(u16, text_seg.sections.items.len);
                    try text_seg.addSection(self.base.allocator, "__const", .{});
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
                        self.objc_methname_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.base.allocator, "__objc_methname", .{
                            .flags = macho.S_CSTRING_LITERALS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_methname_section_index.?,
                    };
                } else if (mem.eql(u8, sectname, "__objc_methtype")) {
                    if (self.objc_methtype_section_index == null) {
                        self.objc_methtype_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.base.allocator, "__objc_methtype", .{
                            .flags = macho.S_CSTRING_LITERALS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_methtype_section_index.?,
                    };
                } else if (mem.eql(u8, sectname, "__objc_classname")) {
                    if (self.objc_classname_section_index == null) {
                        self.objc_classname_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.base.allocator, "__objc_classname", .{});
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.objc_classname_section_index.?,
                    };
                }

                if (self.cstring_section_index == null) {
                    self.cstring_section_index = @intCast(u16, text_seg.sections.items.len);
                    try text_seg.addSection(self.base.allocator, "__cstring", .{
                        .flags = macho.S_CSTRING_LITERALS,
                    });
                }

                break :blk .{
                    .seg = self.text_segment_cmd_index.?,
                    .sect = self.cstring_section_index.?,
                };
            },
            macho.S_LITERAL_POINTERS => {
                if (mem.eql(u8, segname, "__DATA") and mem.eql(u8, sectname, "__objc_selrefs")) {
                    if (self.objc_selrefs_section_index == null) {
                        self.objc_selrefs_section_index = @intCast(u16, data_seg.sections.items.len);
                        try data_seg.addSection(self.base.allocator, "__objc_selrefs", .{
                            .flags = macho.S_LITERAL_POINTERS,
                        });
                    }

                    break :blk .{
                        .seg = self.data_segment_cmd_index.?,
                        .sect = self.objc_selrefs_section_index.?,
                    };
                }

                // TODO investigate
                break :blk null;
            },
            macho.S_MOD_INIT_FUNC_POINTERS => {
                if (self.mod_init_func_section_index == null) {
                    self.mod_init_func_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.base.allocator, "__mod_init_func", .{
                        .flags = macho.S_MOD_INIT_FUNC_POINTERS,
                    });
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.mod_init_func_section_index.?,
                };
            },
            macho.S_MOD_TERM_FUNC_POINTERS => {
                if (self.mod_term_func_section_index == null) {
                    self.mod_term_func_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.base.allocator, "__mod_term_func", .{
                        .flags = macho.S_MOD_TERM_FUNC_POINTERS,
                    });
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.mod_term_func_section_index.?,
                };
            },
            macho.S_ZEROFILL => {
                if (self.bss_section_index == null) {
                    self.bss_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.base.allocator, "__bss", .{
                        .flags = macho.S_ZEROFILL,
                    });
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.bss_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_VARIABLES => {
                if (self.tlv_section_index == null) {
                    self.tlv_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.base.allocator, "__thread_vars", .{
                        .flags = macho.S_THREAD_LOCAL_VARIABLES,
                    });
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_REGULAR => {
                if (self.tlv_data_section_index == null) {
                    self.tlv_data_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.base.allocator, "__thread_data", .{
                        .flags = macho.S_THREAD_LOCAL_REGULAR,
                    });
                }

                break :blk .{
                    .seg = self.data_segment_cmd_index.?,
                    .sect = self.tlv_data_section_index.?,
                };
            },
            macho.S_THREAD_LOCAL_ZEROFILL => {
                if (self.tlv_bss_section_index == null) {
                    self.tlv_bss_section_index = @intCast(u16, data_seg.sections.items.len);
                    try data_seg.addSection(self.base.allocator, "__thread_bss", .{
                        .flags = macho.S_THREAD_LOCAL_ZEROFILL,
                    });
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
                        self.eh_frame_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.base.allocator, "__eh_frame", .{});
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.eh_frame_section_index.?,
                    };
                }

                // TODO audit this: is this the right mapping?
                if (self.data_const_section_index == null) {
                    self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                    try data_const_seg.addSection(self.base.allocator, "__const", .{});
                }

                break :blk .{
                    .seg = self.data_const_segment_cmd_index.?,
                    .sect = self.data_const_section_index.?,
                };
            },
            macho.S_REGULAR => {
                if (commands.sectionIsCode(sect)) {
                    if (self.text_section_index == null) {
                        self.text_section_index = @intCast(u16, text_seg.sections.items.len);
                        try text_seg.addSection(self.base.allocator, "__text", .{
                            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
                        });
                    }

                    break :blk .{
                        .seg = self.text_segment_cmd_index.?,
                        .sect = self.text_section_index.?,
                    };
                }
                if (commands.sectionIsDebug(sect)) {
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
                            self.ustring_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__ustring", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.ustring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__gcc_except_tab")) {
                        if (self.gcc_except_tab_section_index == null) {
                            self.gcc_except_tab_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__gcc_except_tab", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.gcc_except_tab_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_methlist")) {
                        if (self.objc_methlist_section_index == null) {
                            self.objc_methlist_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__objc_methlist", .{});
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
                            self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else {
                        if (self.text_const_section_index == null) {
                            self.text_const_section_index = @intCast(u16, text_seg.sections.items.len);
                            try text_seg.addSection(self.base.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.text_segment_cmd_index.?,
                            .sect = self.text_const_section_index.?,
                        };
                    }
                }

                if (mem.eql(u8, segname, "__DATA_CONST")) {
                    if (self.data_const_section_index == null) {
                        self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                        try data_const_seg.addSection(self.base.allocator, "__const", .{});
                    }

                    break :blk .{
                        .seg = self.data_const_segment_cmd_index.?,
                        .sect = self.data_const_section_index.?,
                    };
                }

                if (mem.eql(u8, segname, "__DATA")) {
                    if (mem.eql(u8, sectname, "__const")) {
                        if (self.data_const_section_index == null) {
                            self.data_const_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__const", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.data_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__cfstring")) {
                        if (self.objc_cfstring_section_index == null) {
                            self.objc_cfstring_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__cfstring", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_cfstring_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classlist")) {
                        if (self.objc_classlist_section_index == null) {
                            self.objc_classlist_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__objc_classlist", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_classlist_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_imageinfo")) {
                        if (self.objc_imageinfo_section_index == null) {
                            self.objc_imageinfo_section_index = @intCast(u16, data_const_seg.sections.items.len);
                            try data_const_seg.addSection(self.base.allocator, "__objc_imageinfo", .{});
                        }

                        break :blk .{
                            .seg = self.data_const_segment_cmd_index.?,
                            .sect = self.objc_imageinfo_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_const")) {
                        if (self.objc_const_section_index == null) {
                            self.objc_const_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__objc_const", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_const_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_classrefs")) {
                        if (self.objc_classrefs_section_index == null) {
                            self.objc_classrefs_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__objc_classrefs", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_classrefs_section_index.?,
                        };
                    } else if (mem.eql(u8, sectname, "__objc_data")) {
                        if (self.objc_data_section_index == null) {
                            self.objc_data_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__objc_data", .{});
                        }

                        break :blk .{
                            .seg = self.data_segment_cmd_index.?,
                            .sect = self.objc_data_section_index.?,
                        };
                    } else {
                        if (self.data_section_index == null) {
                            self.data_section_index = @intCast(u16, data_seg.sections.items.len);
                            try data_seg.addSection(self.base.allocator, "__data", .{});
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

    if (res) |match| {
        _ = try self.section_ordinals.getOrPut(self.base.allocator, match);
    }

    return res;
}

fn sortSections(self: *MachO) !void {
    var text_index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer text_index_mapping.deinit();
    var data_const_index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer data_const_index_mapping.deinit();
    var data_index_mapping = std.AutoHashMap(u16, u16).init(self.base.allocator);
    defer data_index_mapping.deinit();

    {
        // __TEXT segment
        const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.base.allocator);
        defer self.base.allocator.free(sections);
        try seg.sections.ensureCapacity(self.base.allocator, sections.len);

        const indices = &[_]*?u16{
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
        };
        for (indices) |maybe_index| {
            const new_index: u16 = if (maybe_index.*) |index| blk: {
                const idx = @intCast(u16, seg.sections.items.len);
                seg.sections.appendAssumeCapacity(sections[index]);
                try text_index_mapping.putNoClobber(index, idx);
                break :blk idx;
            } else continue;
            maybe_index.* = new_index;
        }
    }

    {
        // __DATA_CONST segment
        const seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.base.allocator);
        defer self.base.allocator.free(sections);
        try seg.sections.ensureCapacity(self.base.allocator, sections.len);

        const indices = &[_]*?u16{
            &self.got_section_index,
            &self.mod_init_func_section_index,
            &self.mod_term_func_section_index,
            &self.data_const_section_index,
            &self.objc_cfstring_section_index,
            &self.objc_classlist_section_index,
            &self.objc_imageinfo_section_index,
        };
        for (indices) |maybe_index| {
            const new_index: u16 = if (maybe_index.*) |index| blk: {
                const idx = @intCast(u16, seg.sections.items.len);
                seg.sections.appendAssumeCapacity(sections[index]);
                try data_const_index_mapping.putNoClobber(index, idx);
                break :blk idx;
            } else continue;
            maybe_index.* = new_index;
        }
    }

    {
        // __DATA segment
        const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        var sections = seg.sections.toOwnedSlice(self.base.allocator);
        defer self.base.allocator.free(sections);
        try seg.sections.ensureCapacity(self.base.allocator, sections.len);

        // __DATA segment
        const indices = &[_]*?u16{
            &self.la_symbol_ptr_section_index,
            &self.objc_const_section_index,
            &self.objc_selrefs_section_index,
            &self.objc_classrefs_section_index,
            &self.objc_data_section_index,
            &self.data_section_index,
            &self.tlv_section_index,
            &self.tlv_data_section_index,
            &self.tlv_bss_section_index,
            &self.bss_section_index,
        };
        for (indices) |maybe_index| {
            const new_index: u16 = if (maybe_index.*) |index| blk: {
                const idx = @intCast(u16, seg.sections.items.len);
                seg.sections.appendAssumeCapacity(sections[index]);
                try data_index_mapping.putNoClobber(index, idx);
                break :blk idx;
            } else continue;
            maybe_index.* = new_index;
        }
    }

    {
        var transient: std.AutoHashMapUnmanaged(MatchingSection, *Atom) = .{};
        try transient.ensureCapacity(self.base.allocator, self.atoms.count());

        var it = self.atoms.iterator();
        while (it.next()) |entry| {
            const old = entry.key_ptr.*;
            const sect = if (old.seg == self.text_segment_cmd_index.?)
                text_index_mapping.get(old.sect).?
            else if (old.seg == self.data_const_segment_cmd_index.?)
                data_const_index_mapping.get(old.sect).?
            else
                data_index_mapping.get(old.sect).?;
            transient.putAssumeCapacityNoClobber(.{
                .seg = old.seg,
                .sect = sect,
            }, entry.value_ptr.*);
        }

        self.atoms.clearAndFree(self.base.allocator);
        self.atoms.deinit(self.base.allocator);
        self.atoms = transient;
    }

    {
        // Create new section ordinals.
        self.section_ordinals.clearRetainingCapacity();
        const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        for (text_seg.sections.items) |_, sect_id| {
            const res = self.section_ordinals.getOrPutAssumeCapacity(.{
                .seg = self.text_segment_cmd_index.?,
                .sect = @intCast(u16, sect_id),
            });
            assert(!res.found_existing);
        }
        const data_const_seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        for (data_const_seg.sections.items) |_, sect_id| {
            const res = self.section_ordinals.getOrPutAssumeCapacity(.{
                .seg = self.data_const_segment_cmd_index.?,
                .sect = @intCast(u16, sect_id),
            });
            assert(!res.found_existing);
        }
        const data_seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        for (data_seg.sections.items) |_, sect_id| {
            const res = self.section_ordinals.getOrPutAssumeCapacity(.{
                .seg = self.data_segment_cmd_index.?,
                .sect = @intCast(u16, sect_id),
            });
            assert(!res.found_existing);
        }
    }
}

fn allocateTextSegment(self: *MachO) !void {
    const seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;

    const base_vmaddr = self.load_commands.items[self.pagezero_segment_cmd_index.?].Segment.inner.vmsize;
    seg.inner.fileoff = 0;
    seg.inner.vmaddr = base_vmaddr;

    var sizeofcmds: u64 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    try self.allocateSegment(self.text_segment_cmd_index.?, @sizeOf(macho.mach_header_64) + sizeofcmds);

    // Shift all sections to the back to minimize jump size between __TEXT and __DATA segments.
    var min_alignment: u32 = 0;
    for (seg.sections.items) |sect| {
        const alignment = try math.powi(u32, 2, sect.@"align");
        min_alignment = math.max(min_alignment, alignment);
    }

    assert(min_alignment > 0);
    const last_sect_idx = seg.sections.items.len - 1;
    const last_sect = seg.sections.items[last_sect_idx];
    const shift: u32 = blk: {
        const diff = seg.inner.filesize - last_sect.offset - last_sect.size;
        const factor = @divTrunc(diff, min_alignment);
        break :blk @intCast(u32, factor * min_alignment);
    };

    if (shift > 0) {
        for (seg.sections.items) |*sect| {
            sect.offset += shift;
            sect.addr += shift;
        }
    }
}

fn allocateDataConstSegment(self: *MachO) !void {
    const seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    seg.inner.fileoff = text_seg.inner.fileoff + text_seg.inner.filesize;
    seg.inner.vmaddr = text_seg.inner.vmaddr + text_seg.inner.vmsize;
    try self.allocateSegment(self.data_const_segment_cmd_index.?, 0);
}

fn allocateDataSegment(self: *MachO) !void {
    const seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const data_const_seg = self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    seg.inner.fileoff = data_const_seg.inner.fileoff + data_const_seg.inner.filesize;
    seg.inner.vmaddr = data_const_seg.inner.vmaddr + data_const_seg.inner.vmsize;
    try self.allocateSegment(self.data_segment_cmd_index.?, 0);
}

fn allocateLinkeditSegment(self: *MachO) void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const data_seg = self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    seg.inner.fileoff = data_seg.inner.fileoff + data_seg.inner.filesize;
    seg.inner.vmaddr = data_seg.inner.vmaddr + data_seg.inner.vmsize;
}

fn allocateSegment(self: *MachO, index: u16, offset: u64) !void {
    const seg = &self.load_commands.items[index].Segment;

    // Allocate the sections according to their alignment at the beginning of the segment.
    var start: u64 = offset;
    for (seg.sections.items) |*sect| {
        const alignment = try math.powi(u32, 2, sect.@"align");
        const start_aligned = mem.alignForwardGeneric(u64, start, alignment);
        const end_aligned = mem.alignForwardGeneric(u64, start_aligned + sect.size, alignment);
        sect.offset = @intCast(u32, seg.inner.fileoff + start_aligned);
        sect.addr = seg.inner.vmaddr + start_aligned;
        start = end_aligned;
    }

    const seg_size_aligned = mem.alignForwardGeneric(u64, start, self.page_size);
    seg.inner.filesize = seg_size_aligned;
    seg.inner.vmsize = seg_size_aligned;
}

pub fn createEmptyAtom(self: *MachO, local_sym_index: u32, size: u64, alignment: u32, match: MatchingSection) !*Atom {
    const code = try self.base.allocator.alloc(u8, size);
    defer self.base.allocator.free(code);
    mem.set(u8, code, 0);

    const atom = try self.base.allocator.create(Atom);
    errdefer self.base.allocator.destroy(atom);
    atom.* = Atom.empty;
    atom.local_sym_index = local_sym_index;
    atom.size = size;
    atom.alignment = alignment;
    try atom.code.appendSlice(self.base.allocator, code);

    // Update target section's metadata
    const tseg = &self.load_commands.items[match.seg].Segment;
    const tsect = &tseg.sections.items[match.sect];
    const new_alignment = math.max(tsect.@"align", atom.alignment);
    const new_alignment_pow_2 = try math.powi(u32, 2, new_alignment);
    const new_size = mem.alignForwardGeneric(u64, tsect.size, new_alignment_pow_2) + atom.size;
    tsect.size = new_size;
    tsect.@"align" = new_alignment;

    if (self.atoms.getPtr(match)) |last| {
        last.*.next = atom;
        atom.prev = last.*;
        last.* = atom;
    } else {
        try self.atoms.putNoClobber(self.base.allocator, match, atom);
    }
    try self.managed_atoms.append(self.base.allocator, atom);

    return atom;
}

fn allocateAtoms(self: *MachO) !void {
    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const match = entry.key_ptr.*;
        var atom: *Atom = entry.value_ptr.*;

        // Find the first atom
        while (atom.prev) |prev| {
            atom = prev;
        }

        const seg = self.load_commands.items[match.seg].Segment;
        const sect = seg.sections.items[match.sect];

        var base_addr: u64 = sect.addr;
        const n_sect = @intCast(u8, self.section_ordinals.getIndex(match).? + 1);

        log.debug("allocating atoms in {s},{s}", .{ commands.segmentName(sect), commands.sectionName(sect) });

        while (true) {
            const atom_alignment = try math.powi(u32, 2, atom.alignment);
            base_addr = mem.alignForwardGeneric(u64, base_addr, atom_alignment);

            const sym = &self.locals.items[atom.local_sym_index];
            sym.n_value = base_addr;
            sym.n_sect = n_sect;

            log.debug("  (atom {s} allocated from 0x{x} to 0x{x})", .{
                self.getString(sym.n_strx),
                base_addr,
                base_addr + atom.size,
            });

            // Update each alias (if any)
            for (atom.aliases.items) |index| {
                const alias_sym = &self.locals.items[index];
                alias_sym.n_value = base_addr;
                alias_sym.n_sect = n_sect;
            }

            // Update each symbol contained within the TextBlock
            for (atom.contained.items) |sym_at_off| {
                const contained_sym = &self.locals.items[sym_at_off.local_sym_index];
                contained_sym.n_value = base_addr + sym_at_off.offset;
                contained_sym.n_sect = n_sect;
            }

            base_addr += atom.size;

            if (atom.next) |next| {
                atom = next;
            } else break;
        }
    }

    // Update globals
    {
        var sym_it = self.symbol_resolver.valueIterator();
        while (sym_it.next()) |resolv| {
            if (resolv.where != .global) continue;
            const local_sym = self.locals.items[resolv.local_sym_index];
            const sym = &self.globals.items[resolv.where_index];
            sym.n_value = local_sym.n_value;
            sym.n_sect = local_sym.n_sect;
        }
    }
}

fn writeAtoms(self: *MachO) !void {
    var buffer = std.ArrayList(u8).init(self.base.allocator);
    defer buffer.deinit();
    var file_offset: ?u64 = null;

    var it = self.atoms.iterator();
    while (it.next()) |entry| {
        const match = entry.key_ptr.*;
        const seg = self.load_commands.items[match.seg].Segment;
        const sect = seg.sections.items[match.sect];
        var atom: *Atom = entry.value_ptr.*;

        log.debug("writing atoms in {s},{s}", .{ commands.segmentName(sect), commands.sectionName(sect) });

        while (atom.prev) |prev| {
            atom = prev;
        }

        while (true) {
            const atom_sym = self.locals.items[atom.local_sym_index];
            const padding_size: u64 = if (atom.next) |next| blk: {
                const next_sym = self.locals.items[next.local_sym_index];
                break :blk next_sym.n_value - (atom_sym.n_value + atom.size);
            } else 0;

            log.debug("  (adding atom {s} to buffer: {})", .{ self.getString(atom_sym.n_strx), atom_sym });

            try atom.resolveRelocs(self);
            try buffer.appendSlice(atom.code.items);
            try buffer.ensureUnusedCapacity(padding_size);

            var i: usize = 0;
            while (i < padding_size) : (i += 1) {
                buffer.appendAssumeCapacity(0);
            }

            if (file_offset == null) {
                file_offset = sect.offset + atom_sym.n_value - sect.addr;
            }

            if (atom.next) |next| {
                atom = next;
            } else {
                try self.base.file.pwriteAll(buffer.items, file_offset.?);
                file_offset = null;
                buffer.clearRetainingCapacity();
                break;
            }
        }
    }
}

pub fn createGotAtom(self: *MachO, key: GotIndirectionKey) !*Atom {
    const local_sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(self.base.allocator, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try self.createEmptyAtom(local_sym_index, @sizeOf(u64), 3, .{
        .seg = self.data_const_segment_cmd_index.?,
        .sect = self.got_section_index.?,
    });
    switch (key.where) {
        .local => {
            try atom.relocs.append(self.base.allocator, .{
                .offset = 0,
                .where = .local,
                .where_index = key.where_index,
                .payload = .{
                    .unsigned = .{
                        .subtractor = null,
                        .addend = 0,
                        .is_64bit = true,
                    },
                },
            });
            try atom.rebases.append(self.base.allocator, 0);
        },
        .undef => {
            try atom.bindings.append(self.base.allocator, .{
                .local_sym_index = key.where_index,
                .offset = 0,
            });
        },
    }
    return atom;
}

fn createDyldPrivateAtom(self: *MachO) !void {
    if (self.dyld_private_atom != null) return;
    const local_sym_index = @intCast(u32, self.locals.items.len);
    const sym = try self.locals.addOne(self.base.allocator);
    sym.* = .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
    const atom = try self.createEmptyAtom(local_sym_index, @sizeOf(u64), 3, .{
        .seg = self.data_segment_cmd_index.?,
        .sect = self.data_section_index.?,
    });
    self.dyld_private_atom = atom;
}

fn createStubHelperPreambleAtom(self: *MachO) !void {
    if (self.stub_helper_preamble_atom != null) return;
    const arch = self.base.options.target.cpu.arch;
    const size: u64 = switch (arch) {
        .x86_64 => 15,
        .aarch64 => 6 * @sizeOf(u32),
        else => unreachable,
    };
    const alignment: u32 = switch (arch) {
        .x86_64 => 0,
        .aarch64 => 2,
        else => unreachable,
    };
    const local_sym_index = @intCast(u32, self.locals.items.len);
    const sym = try self.locals.addOne(self.base.allocator);
    sym.* = .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    };
    const atom = try self.createEmptyAtom(local_sym_index, size, alignment, .{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stub_helper_section_index.?,
    });
    const dyld_private_sym_index = self.dyld_private_atom.?.local_sym_index;
    switch (arch) {
        .x86_64 => {
            try atom.relocs.ensureUnusedCapacity(self.base.allocator, 2);
            // lea %r11, [rip + disp]
            atom.code.items[0] = 0x4c;
            atom.code.items[1] = 0x8d;
            atom.code.items[2] = 0x1d;
            atom.relocs.appendAssumeCapacity(.{
                .offset = 3,
                .where = .local,
                .where_index = dyld_private_sym_index,
                .payload = .{
                    .signed = .{
                        .addend = 0,
                        .correction = 0,
                    },
                },
            });
            // push %r11
            atom.code.items[7] = 0x41;
            atom.code.items[8] = 0x53;
            // jmp [rip + disp]
            atom.code.items[9] = 0xff;
            atom.code.items[10] = 0x25;
            atom.relocs.appendAssumeCapacity(.{
                .offset = 11,
                .where = .undef,
                .where_index = self.dyld_stub_binder_index.?,
                .payload = .{
                    .load = .{
                        .kind = .got,
                        .addend = 0,
                    },
                },
            });
        },
        .aarch64 => {
            try atom.relocs.ensureUnusedCapacity(self.base.allocator, 4);
            // adrp x17, 0
            mem.writeIntLittle(u32, atom.code.items[0..][0..4], aarch64.Instruction.adrp(.x17, 0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 0,
                .where = .local,
                .where_index = dyld_private_sym_index,
                .payload = .{
                    .page = .{
                        .kind = .page,
                        .addend = 0,
                    },
                },
            });
            // add x17, x17, 0
            mem.writeIntLittle(u32, atom.code.items[4..][0..4], aarch64.Instruction.add(.x17, .x17, 0, false).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 4,
                .where = .local,
                .where_index = dyld_private_sym_index,
                .payload = .{
                    .page_off = .{
                        .kind = .page,
                        .addend = 0,
                        .op_kind = .arithmetic,
                    },
                },
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
                .where = .undef,
                .where_index = self.dyld_stub_binder_index.?,
                .payload = .{
                    .page = .{
                        .kind = .got,
                        .addend = 0,
                    },
                },
            });
            // ldr x16, [x16, 0]
            mem.writeIntLittle(u32, atom.code.items[16..][0..4], aarch64.Instruction.ldr(.x16, .{
                .register = .{
                    .rn = .x16,
                    .offset = aarch64.Instruction.LoadStoreOffset.imm(0),
                },
            }).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 16,
                .where = .undef,
                .where_index = self.dyld_stub_binder_index.?,
                .payload = .{
                    .page_off = .{
                        .kind = .got,
                        .addend = 0,
                    },
                },
            });
            // br x16
            mem.writeIntLittle(u32, atom.code.items[20..][0..4], aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }
    self.stub_helper_preamble_atom = atom;
}

pub fn createStubHelperAtom(self: *MachO) !*Atom {
    const arch = self.base.options.target.cpu.arch;
    const stub_size: u4 = switch (arch) {
        .x86_64 => 10,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable,
    };
    const alignment: u2 = switch (arch) {
        .x86_64 => 0,
        .aarch64 => 2,
        else => unreachable,
    };
    const local_sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(self.base.allocator, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try self.createEmptyAtom(local_sym_index, stub_size, alignment, .{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stub_helper_section_index.?,
    });
    try atom.relocs.ensureTotalCapacity(self.base.allocator, 1);

    switch (arch) {
        .x86_64 => {
            // pushq
            atom.code.items[0] = 0x68;
            // Next 4 bytes 1..4 are just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
            // jmpq
            atom.code.items[5] = 0xe9;
            atom.relocs.appendAssumeCapacity(.{
                .offset = 6,
                .where = .local,
                .where_index = self.stub_helper_preamble_atom.?.local_sym_index,
                .payload = .{
                    .branch = .{ .arch = arch },
                },
            });
        },
        .aarch64 => {
            const literal = blk: {
                const div_res = try math.divExact(u64, stub_size - @sizeOf(u32), 4);
                break :blk try math.cast(u18, div_res);
            };
            // ldr w16, literal
            mem.writeIntLittle(u32, atom.code.items[0..4], aarch64.Instruction.ldr(.w16, .{
                .literal = literal,
            }).toU32());
            // b disp
            mem.writeIntLittle(u32, atom.code.items[4..8], aarch64.Instruction.b(0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 4,
                .where = .local,
                .where_index = self.stub_helper_preamble_atom.?.local_sym_index,
                .payload = .{
                    .branch = .{ .arch = arch },
                },
            });
            // Next 4 bytes 8..12 are just a placeholder populated in `populateLazyBindOffsetsInStubHelper`.
        },
        else => unreachable,
    }

    return atom;
}

pub fn createLazyPointerAtom(self: *MachO, stub_sym_index: u32, lazy_binding_sym_index: u32) !*Atom {
    const local_sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(self.base.allocator, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try self.createEmptyAtom(local_sym_index, @sizeOf(u64), 3, .{
        .seg = self.data_segment_cmd_index.?,
        .sect = self.la_symbol_ptr_section_index.?,
    });
    try atom.relocs.append(self.base.allocator, .{
        .offset = 0,
        .where = .local,
        .where_index = stub_sym_index,
        .payload = .{
            .unsigned = .{
                .subtractor = null,
                .addend = 0,
                .is_64bit = true,
            },
        },
    });
    try atom.rebases.append(self.base.allocator, 0);
    try atom.lazy_bindings.append(self.base.allocator, .{
        .local_sym_index = lazy_binding_sym_index,
        .offset = 0,
    });
    return atom;
}

pub fn createStubAtom(self: *MachO, laptr_sym_index: u32) !*Atom {
    const arch = self.base.options.target.cpu.arch;
    const alignment: u2 = switch (arch) {
        .x86_64 => 0,
        .aarch64 => 2,
        else => unreachable, // unhandled architecture type
    };
    const stub_size: u4 = switch (arch) {
        .x86_64 => 6,
        .aarch64 => 3 * @sizeOf(u32),
        else => unreachable, // unhandled architecture type
    };
    const local_sym_index = @intCast(u32, self.locals.items.len);
    try self.locals.append(self.base.allocator, .{
        .n_strx = 0,
        .n_type = macho.N_SECT,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    const atom = try self.createEmptyAtom(local_sym_index, stub_size, alignment, .{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stubs_section_index.?,
    });
    switch (arch) {
        .x86_64 => {
            // jmp
            atom.code.items[0] = 0xff;
            atom.code.items[1] = 0x25;
            try atom.relocs.append(self.base.allocator, .{
                .offset = 2,
                .where = .local,
                .where_index = laptr_sym_index,
                .payload = .{
                    .branch = .{ .arch = arch },
                },
            });
        },
        .aarch64 => {
            try atom.relocs.ensureTotalCapacity(self.base.allocator, 2);
            // adrp x16, pages
            mem.writeIntLittle(u32, atom.code.items[0..4], aarch64.Instruction.adrp(.x16, 0).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 0,
                .where = .local,
                .where_index = laptr_sym_index,
                .payload = .{
                    .page = .{
                        .kind = .page,
                        .addend = 0,
                    },
                },
            });
            // ldr x16, x16, offset
            mem.writeIntLittle(u32, atom.code.items[4..8], aarch64.Instruction.ldr(.x16, .{
                .register = .{
                    .rn = .x16,
                    .offset = aarch64.Instruction.LoadStoreOffset.imm(0),
                },
            }).toU32());
            atom.relocs.appendAssumeCapacity(.{
                .offset = 4,
                .where = .local,
                .where_index = laptr_sym_index,
                .payload = .{
                    .page_off = .{
                        .kind = .page,
                        .addend = 0,
                        .op_kind = .load,
                    },
                },
            });
            // br x16
            mem.writeIntLittle(u32, atom.code.items[8..12], aarch64.Instruction.br(.x16).toU32());
        },
        else => unreachable,
    }
    return atom;
}

fn createTentativeDefAtoms(self: *MachO) !void {
    if (self.tentatives.count() == 0) return;
    // Convert any tentative definition into a regular symbol and allocate
    // text blocks for each tentative defintion.
    while (self.tentatives.popOrNull()) |entry| {
        const match = MatchingSection{
            .seg = self.data_segment_cmd_index.?,
            .sect = self.bss_section_index.?,
        };
        _ = try self.section_ordinals.getOrPut(self.base.allocator, match);

        const global_sym = &self.globals.items[entry.key];
        const size = global_sym.n_value;
        const alignment = (global_sym.n_desc >> 8) & 0x0f;

        global_sym.n_value = 0;
        global_sym.n_desc = 0;
        global_sym.n_sect = @intCast(u8, self.section_ordinals.getIndex(match).? + 1);

        const local_sym_index = @intCast(u32, self.locals.items.len);
        const local_sym = try self.locals.addOne(self.base.allocator);
        local_sym.* = .{
            .n_strx = global_sym.n_strx,
            .n_type = macho.N_SECT,
            .n_sect = global_sym.n_sect,
            .n_desc = 0,
            .n_value = 0,
        };

        const resolv = self.symbol_resolver.getPtr(local_sym.n_strx) orelse unreachable;
        resolv.local_sym_index = local_sym_index;

        _ = try self.createEmptyAtom(local_sym_index, size, alignment, match);
    }
}

fn createDsoHandleAtom(self: *MachO) !void {
    if (self.strtab_dir.getKeyAdapted(@as([]const u8, "___dso_handle"), StringIndexAdapter{
        .bytes = &self.strtab,
    })) |n_strx| blk: {
        const resolv = self.symbol_resolver.getPtr(n_strx) orelse break :blk;
        if (resolv.where != .undef) break :blk;

        const undef = &self.undefs.items[resolv.where_index];
        const match: MatchingSection = .{
            .seg = self.text_segment_cmd_index.?,
            .sect = self.text_section_index.?,
        };
        const local_sym_index = @intCast(u32, self.locals.items.len);
        var nlist = macho.nlist_64{
            .n_strx = undef.n_strx,
            .n_type = macho.N_SECT,
            .n_sect = @intCast(u8, self.section_ordinals.getIndex(match).? + 1),
            .n_desc = 0,
            .n_value = 0,
        };
        try self.locals.append(self.base.allocator, nlist);
        const global_sym_index = @intCast(u32, self.globals.items.len);
        nlist.n_type |= macho.N_EXT;
        nlist.n_desc = macho.N_WEAK_DEF;
        try self.globals.append(self.base.allocator, nlist);

        _ = self.unresolved.fetchSwapRemove(resolv.where_index);

        undef.* = .{
            .n_strx = 0,
            .n_type = macho.N_UNDF,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
        resolv.* = .{
            .where = .global,
            .where_index = global_sym_index,
            .local_sym_index = local_sym_index,
        };

        // We create an empty atom for this symbol.
        // TODO perhaps we should special-case special symbols? Create a separate
        // linked list of atoms?
        _ = try self.createEmptyAtom(local_sym_index, 0, 0, match);
    }
}

fn resolveSymbolsInObject(self: *MachO, object_id: u16) !void {
    const object = &self.objects.items[object_id];

    log.debug("resolving symbols in '{s}'", .{object.name});

    for (object.symtab.items) |sym, id| {
        const sym_id = @intCast(u32, id);
        const sym_name = object.getString(sym.n_strx);

        if (symbolIsStab(sym)) {
            log.err("unhandled symbol type: stab", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name});
            return error.UnhandledSymbolType;
        }

        if (symbolIsIndr(sym)) {
            log.err("unhandled symbol type: indirect", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name});
            return error.UnhandledSymbolType;
        }

        if (symbolIsAbs(sym)) {
            log.err("unhandled symbol type: absolute", .{});
            log.err("  symbol '{s}'", .{sym_name});
            log.err("  first definition in '{s}'", .{object.name});
            return error.UnhandledSymbolType;
        }

        const n_strx = try self.makeString(sym_name);
        if (symbolIsSect(sym)) {
            // Defined symbol regardless of scope lands in the locals symbol table.
            const local_sym_index = @intCast(u32, self.locals.items.len);
            try self.locals.append(self.base.allocator, .{
                .n_strx = n_strx,
                .n_type = macho.N_SECT,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = sym.n_value,
            });
            try object.symbol_mapping.putNoClobber(self.base.allocator, sym_id, local_sym_index);
            try object.reverse_symbol_mapping.putNoClobber(self.base.allocator, local_sym_index, sym_id);

            // If the symbol's scope is not local aka translation unit, then we need work out
            // if we should save the symbol as a global, or potentially flag the error.
            if (!symbolIsExt(sym)) continue;

            const local = self.locals.items[local_sym_index];
            const resolv = self.symbol_resolver.getPtr(n_strx) orelse {
                const global_sym_index = @intCast(u32, self.globals.items.len);
                try self.globals.append(self.base.allocator, .{
                    .n_strx = n_strx,
                    .n_type = sym.n_type,
                    .n_sect = 0,
                    .n_desc = sym.n_desc,
                    .n_value = sym.n_value,
                });
                try self.symbol_resolver.putNoClobber(self.base.allocator, n_strx, .{
                    .where = .global,
                    .where_index = global_sym_index,
                    .local_sym_index = local_sym_index,
                    .file = object_id,
                });
                continue;
            };

            switch (resolv.where) {
                .global => {
                    const global = &self.globals.items[resolv.where_index];

                    if (symbolIsTentative(global.*)) {
                        _ = self.tentatives.fetchSwapRemove(resolv.where_index);
                    } else if (!(symbolIsWeakDef(sym) or symbolIsPext(sym)) and
                        !(symbolIsWeakDef(global.*) or symbolIsPext(global.*)))
                    {
                        log.err("symbol '{s}' defined multiple times", .{sym_name});
                        if (resolv.file) |file| {
                            log.err("  first definition in '{s}'", .{self.objects.items[file].name});
                        }
                        log.err("  next definition in '{s}'", .{object.name});
                        return error.MultipleSymbolDefinitions;
                    } else if (symbolIsWeakDef(sym) or symbolIsPext(sym)) continue; // Current symbol is weak, so skip it.

                    // Otherwise, update the resolver and the global symbol.
                    global.n_type = sym.n_type;
                    resolv.local_sym_index = local_sym_index;
                    resolv.file = object_id;

                    continue;
                },
                .undef => {
                    _ = self.unresolved.fetchSwapRemove(resolv.where_index);
                },
            }

            const global_sym_index = @intCast(u32, self.globals.items.len);
            try self.globals.append(self.base.allocator, .{
                .n_strx = local.n_strx,
                .n_type = sym.n_type,
                .n_sect = 0,
                .n_desc = sym.n_desc,
                .n_value = sym.n_value,
            });
            resolv.* = .{
                .where = .global,
                .where_index = global_sym_index,
                .local_sym_index = local_sym_index,
                .file = object_id,
            };
        } else if (symbolIsTentative(sym)) {
            // Symbol is a tentative definition.
            const resolv = self.symbol_resolver.getPtr(n_strx) orelse {
                const global_sym_index = @intCast(u32, self.globals.items.len);
                try self.globals.append(self.base.allocator, .{
                    .n_strx = try self.makeString(sym_name),
                    .n_type = sym.n_type,
                    .n_sect = 0,
                    .n_desc = sym.n_desc,
                    .n_value = sym.n_value,
                });
                try self.symbol_resolver.putNoClobber(self.base.allocator, n_strx, .{
                    .where = .global,
                    .where_index = global_sym_index,
                    .file = object_id,
                });
                _ = try self.tentatives.getOrPut(self.base.allocator, global_sym_index);
                continue;
            };

            switch (resolv.where) {
                .global => {
                    const global = &self.globals.items[resolv.where_index];
                    if (!symbolIsTentative(global.*)) continue;
                    if (global.n_value >= sym.n_value) continue;

                    global.n_desc = sym.n_desc;
                    global.n_value = sym.n_value;
                    resolv.file = object_id;
                },
                .undef => {
                    const undef = &self.undefs.items[resolv.where_index];
                    const global_sym_index = @intCast(u32, self.globals.items.len);
                    try self.globals.append(self.base.allocator, .{
                        .n_strx = undef.n_strx,
                        .n_type = sym.n_type,
                        .n_sect = 0,
                        .n_desc = sym.n_desc,
                        .n_value = sym.n_value,
                    });
                    _ = try self.tentatives.getOrPut(self.base.allocator, global_sym_index);
                    resolv.* = .{
                        .where = .global,
                        .where_index = global_sym_index,
                        .file = object_id,
                    };
                    undef.* = .{
                        .n_strx = 0,
                        .n_type = macho.N_UNDF,
                        .n_sect = 0,
                        .n_desc = 0,
                        .n_value = 0,
                    };
                    _ = self.unresolved.fetchSwapRemove(resolv.where_index);
                },
            }
        } else {
            // Symbol is undefined.
            if (self.symbol_resolver.contains(n_strx)) continue;

            const undef_sym_index = @intCast(u32, self.undefs.items.len);
            try self.undefs.append(self.base.allocator, .{
                .n_strx = try self.makeString(sym_name),
                .n_type = macho.N_UNDF,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
            try self.symbol_resolver.putNoClobber(self.base.allocator, n_strx, .{
                .where = .undef,
                .where_index = undef_sym_index,
                .file = object_id,
            });
            try self.unresolved.putNoClobber(self.base.allocator, undef_sym_index, {});
        }
    }
}

fn resolveSymbolsInArchives(self: *MachO) !void {
    if (self.archives.items.len == 0) return;

    var next_sym: usize = 0;
    loop: while (next_sym < self.unresolved.count()) {
        const sym = self.undefs.items[self.unresolved.keys()[next_sym]];
        const sym_name = self.getString(sym.n_strx);

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(sym_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @intCast(u16, self.objects.items.len);
            const object = try self.objects.addOne(self.base.allocator);
            object.* = try archive.parseObject(self.base.allocator, self.base.options.target, offsets.items[0]);
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
        const sym = self.undefs.items[self.unresolved.keys()[next_sym]];
        const sym_name = self.getString(sym.n_strx);

        for (self.dylibs.items) |dylib, id| {
            if (!dylib.symbols.contains(sym_name)) continue;

            const dylib_id = @intCast(u16, id);
            if (!self.referenced_dylibs.contains(dylib_id)) {
                try self.referenced_dylibs.putNoClobber(self.base.allocator, dylib_id, {});
            }

            const ordinal = self.referenced_dylibs.getIndex(dylib_id) orelse unreachable;
            const resolv = self.symbol_resolver.getPtr(sym.n_strx) orelse unreachable;
            const undef = &self.undefs.items[resolv.where_index];
            undef.n_type |= macho.N_EXT;
            undef.n_desc = @intCast(u16, ordinal + 1) * macho.N_SYMBOL_RESOLVER;

            _ = self.unresolved.fetchSwapRemove(resolv.where_index);

            continue :loop;
        }

        next_sym += 1;
    }
}

fn resolveDyldStubBinder(self: *MachO) !void {
    if (self.dyld_stub_binder_index != null) return;

    const n_strx = try self.makeString("dyld_stub_binder");
    const sym_index = @intCast(u32, self.undefs.items.len);
    try self.undefs.append(self.base.allocator, .{
        .n_strx = n_strx,
        .n_type = macho.N_UNDF,
        .n_sect = 0,
        .n_desc = 0,
        .n_value = 0,
    });
    try self.symbol_resolver.putNoClobber(self.base.allocator, n_strx, .{
        .where = .undef,
        .where_index = sym_index,
    });
    const sym = &self.undefs.items[sym_index];
    const sym_name = self.getString(n_strx);

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

    // Add dyld_stub_binder as the final GOT entry.
    const got_entry = GotIndirectionKey{
        .where = .undef,
        .where_index = self.dyld_stub_binder_index.?,
    };
    const atom = try self.createGotAtom(got_entry);
    try self.got_entries_map.putNoClobber(self.base.allocator, got_entry, atom);
}

fn addDataInCodeLC(self: *MachO) !void {
    if (self.data_in_code_cmd_index == null) {
        self.data_in_code_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .LinkeditData = .{
                .cmd = macho.LC_DATA_IN_CODE,
                .cmdsize = @sizeOf(macho.linkedit_data_command),
                .dataoff = 0,
                .datasize = 0,
            },
        });
    }
}

fn addCodeSignatureLC(self: *MachO) !void {
    if (self.code_signature_cmd_index != null or !self.requires_adhoc_codesig) return;
    self.code_signature_cmd_index = @intCast(u16, self.load_commands.items.len);
    try self.load_commands.append(self.base.allocator, .{
        .LinkeditData = .{
            .cmd = macho.LC_CODE_SIGNATURE,
            .cmdsize = @sizeOf(macho.linkedit_data_command),
            .dataoff = 0,
            .datasize = 0,
        },
    });
}

fn addRpathLCs(self: *MachO, rpaths: []const []const u8) !void {
    for (rpaths) |rpath| {
        const cmdsize = @intCast(u32, mem.alignForwardGeneric(
            u64,
            @sizeOf(macho.rpath_command) + rpath.len + 1,
            @sizeOf(u64),
        ));
        var rpath_cmd = commands.emptyGenericCommandWithData(macho.rpath_command{
            .cmd = macho.LC_RPATH,
            .cmdsize = cmdsize,
            .path = @sizeOf(macho.rpath_command),
        });
        rpath_cmd.data = try self.base.allocator.alloc(u8, cmdsize - rpath_cmd.inner.path);
        mem.set(u8, rpath_cmd.data, 0);
        mem.copy(u8, rpath_cmd.data, rpath);
        try self.load_commands.append(self.base.allocator, .{ .Rpath = rpath_cmd });
    }
}

fn addLoadDylibLCs(self: *MachO) !void {
    for (self.referenced_dylibs.keys()) |id| {
        const dylib = self.dylibs.items[id];
        const dylib_id = dylib.id orelse unreachable;
        var dylib_cmd = try commands.createLoadDylibCommand(
            self.base.allocator,
            dylib_id.name,
            dylib_id.timestamp,
            dylib_id.current_version,
            dylib_id.compatibility_version,
        );
        errdefer dylib_cmd.deinit(self.base.allocator);
        try self.load_commands.append(self.base.allocator, .{ .Dylib = dylib_cmd });
    }
}

fn setEntryPoint(self: *MachO) !void {
    if (self.base.options.output_mode != .exe) return;

    // TODO we should respect the -entry flag passed in by the user to set a custom
    // entrypoint. For now, assume default of `_main`.
    const seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const n_strx = self.strtab_dir.getKeyAdapted(@as([]const u8, "_main"), StringIndexAdapter{
        .bytes = &self.strtab,
    }) orelse {
        log.err("'_main' export not found", .{});
        return error.MissingMainEntrypoint;
    };
    const resolv = self.symbol_resolver.get(n_strx) orelse unreachable;
    assert(resolv.where == .global);
    const sym = self.globals.items[resolv.where_index];
    const ec = &self.load_commands.items[self.main_cmd_index.?].Main;
    ec.entryoff = @intCast(u32, sym.n_value - seg.inner.vmaddr);
    ec.stacksize = self.base.options.stack_size_override orelse 0;
}

pub fn deinit(self: *MachO) void {
    self.section_ordinals.deinit(self.base.allocator);
    self.got_entries_map.deinit(self.base.allocator);
    self.stubs_map.deinit(self.base.allocator);
    self.strtab_dir.deinit(self.base.allocator);
    self.strtab.deinit(self.base.allocator);
    self.undefs.deinit(self.base.allocator);
    self.globals.deinit(self.base.allocator);
    self.locals.deinit(self.base.allocator);
    self.symbol_resolver.deinit(self.base.allocator);
    self.unresolved.deinit(self.base.allocator);
    self.tentatives.deinit(self.base.allocator);

    for (self.objects.items) |*object| {
        object.deinit(self.base.allocator);
    }
    self.objects.deinit(self.base.allocator);

    for (self.archives.items) |*archive| {
        archive.deinit(self.base.allocator);
    }
    self.archives.deinit(self.base.allocator);

    for (self.dylibs.items) |*dylib| {
        dylib.deinit(self.base.allocator);
    }
    self.dylibs.deinit(self.base.allocator);
    self.dylibs_map.deinit(self.base.allocator);
    self.referenced_dylibs.deinit(self.base.allocator);

    for (self.load_commands.items) |*lc| {
        lc.deinit(self.base.allocator);
    }
    self.load_commands.deinit(self.base.allocator);

    for (self.managed_atoms.items) |atom| {
        atom.deinit(self.base.allocator);
        self.base.allocator.destroy(atom);
    }
    self.managed_atoms.deinit(self.base.allocator);
    self.atoms.deinit(self.base.allocator);
}

pub fn closeFiles(self: MachO) void {
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
    if (self.pagezero_segment_cmd_index == null) {
        self.pagezero_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__PAGEZERO", .{
                .vmsize = 0x100000000, // size always set to 4GB
            }),
        });
    }

    if (self.text_segment_cmd_index == null) {
        self.text_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__TEXT", .{
                .vmaddr = 0x100000000, // always starts at 4GB
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_EXECUTE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_EXECUTE,
            }),
        });
    }

    if (self.text_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.text_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.base.allocator, "__text", .{
            .@"align" = alignment,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
        _ = try self.section_ordinals.getOrPut(self.base.allocator, .{
            .seg = self.text_segment_cmd_index.?,
            .sect = self.text_section_index.?,
        });
    }

    if (self.stubs_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stubs_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        const stub_size: u4 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 6,
            .aarch64 => 3 * @sizeOf(u32),
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.base.allocator, "__stubs", .{
            .@"align" = alignment,
            .flags = macho.S_SYMBOL_STUBS | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved2 = stub_size,
        });
        _ = try self.section_ordinals.getOrPut(self.base.allocator, .{
            .seg = self.text_segment_cmd_index.?,
            .sect = self.stubs_section_index.?,
        });
    }

    if (self.stub_helper_section_index == null) {
        const text_seg = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        self.stub_helper_section_index = @intCast(u16, text_seg.sections.items.len);
        const alignment: u2 = switch (self.base.options.target.cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable, // unhandled architecture type
        };
        try text_seg.addSection(self.base.allocator, "__stub_helper", .{
            .@"align" = alignment,
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
        _ = try self.section_ordinals.getOrPut(self.base.allocator, .{
            .seg = self.text_segment_cmd_index.?,
            .sect = self.stub_helper_section_index.?,
        });
    }

    if (self.data_const_segment_cmd_index == null) {
        self.data_const_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__DATA_CONST", .{
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
            }),
        });
    }

    if (self.got_section_index == null) {
        const data_const_seg = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
        self.got_section_index = @intCast(u16, data_const_seg.sections.items.len);
        try data_const_seg.addSection(self.base.allocator, "__got", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
        });
        _ = try self.section_ordinals.getOrPut(self.base.allocator, .{
            .seg = self.data_const_segment_cmd_index.?,
            .sect = self.got_section_index.?,
        });
    }

    if (self.data_segment_cmd_index == null) {
        self.data_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__DATA", .{
                .maxprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
                .initprot = macho.VM_PROT_READ | macho.VM_PROT_WRITE,
            }),
        });
    }

    if (self.la_symbol_ptr_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.la_symbol_ptr_section_index = @intCast(u16, data_seg.sections.items.len);
        try data_seg.addSection(self.base.allocator, "__la_symbol_ptr", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
            .flags = macho.S_LAZY_SYMBOL_POINTERS,
        });
        _ = try self.section_ordinals.getOrPut(self.base.allocator, .{
            .seg = self.data_segment_cmd_index.?,
            .sect = self.la_symbol_ptr_section_index.?,
        });
    }

    if (self.data_section_index == null) {
        const data_seg = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
        self.data_section_index = @intCast(u16, data_seg.sections.items.len);
        try data_seg.addSection(self.base.allocator, "__data", .{
            .@"align" = 3, // 2^3 = @sizeOf(u64)
        });
        _ = try self.section_ordinals.getOrPut(self.base.allocator, .{
            .seg = self.data_segment_cmd_index.?,
            .sect = self.data_section_index.?,
        });
    }

    if (self.linkedit_segment_cmd_index == null) {
        self.linkedit_segment_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Segment = SegmentCommand.empty("__LINKEDIT", .{
                .maxprot = macho.VM_PROT_READ,
                .initprot = macho.VM_PROT_READ,
            }),
        });
    }

    if (self.dyld_info_cmd_index == null) {
        self.dyld_info_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .DyldInfoOnly = .{
                .cmd = macho.LC_DYLD_INFO_ONLY,
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
            .Symtab = .{
                .cmd = macho.LC_SYMTAB,
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
            .Dysymtab = .{
                .cmd = macho.LC_DYSYMTAB,
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
            @sizeOf(macho.dylinker_command) + mem.lenZ(default_dyld_path),
            @sizeOf(u64),
        ));
        var dylinker_cmd = commands.emptyGenericCommandWithData(macho.dylinker_command{
            .cmd = macho.LC_LOAD_DYLINKER,
            .cmdsize = cmdsize,
            .name = @sizeOf(macho.dylinker_command),
        });
        dylinker_cmd.data = try self.base.allocator.alloc(u8, cmdsize - dylinker_cmd.inner.name);
        mem.set(u8, dylinker_cmd.data, 0);
        mem.copy(u8, dylinker_cmd.data, mem.spanZ(default_dyld_path));
        try self.load_commands.append(self.base.allocator, .{ .Dylinker = dylinker_cmd });
    }

    if (self.main_cmd_index == null and self.base.options.output_mode == .exe) {
        self.main_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .Main = .{
                .cmd = macho.LC_MAIN,
                .cmdsize = @sizeOf(macho.entry_point_command),
                .entryoff = 0x0,
                .stacksize = 0,
            },
        });
    }

    if (self.dylib_id_cmd_index == null and self.base.options.output_mode == .lib) {
        self.dylib_id_cmd_index = @intCast(u16, self.load_commands.items.len);
        const install_name = try std.fmt.allocPrint(self.base.allocator, "@rpath/{s}", .{
            self.base.options.emit.sub_path,
        });
        defer self.base.allocator.free(install_name);
        var dylib_cmd = try commands.createLoadDylibCommand(
            self.base.allocator,
            install_name,
            2,
            0x10000, // TODO forward user-provided versions
            0x10000,
        );
        errdefer dylib_cmd.deinit(self.base.allocator);
        dylib_cmd.inner.cmd = macho.LC_ID_DYLIB;
        try self.load_commands.append(self.base.allocator, .{ .Dylib = dylib_cmd });
    }

    if (self.source_version_cmd_index == null) {
        self.source_version_cmd_index = @intCast(u16, self.load_commands.items.len);
        try self.load_commands.append(self.base.allocator, .{
            .SourceVersion = .{
                .cmd = macho.LC_SOURCE_VERSION,
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
        const ver = self.base.options.target.os.version_range.semver.min;
        const version = ver.major << 16 | ver.minor << 8 | ver.patch;
        const is_simulator_abi = self.base.options.target.abi == .simulator;
        var cmd = commands.emptyGenericCommandWithData(macho.build_version_command{
            .cmd = macho.LC_BUILD_VERSION,
            .cmdsize = cmdsize,
            .platform = switch (self.base.options.target.os.tag) {
                .macos => macho.PLATFORM_MACOS,
                .ios => if (is_simulator_abi) macho.PLATFORM_IOSSIMULATOR else macho.PLATFORM_IOS,
                .watchos => if (is_simulator_abi) macho.PLATFORM_WATCHOSSIMULATOR else macho.PLATFORM_WATCHOS,
                .tvos => if (is_simulator_abi) macho.PLATFORM_TVOSSIMULATOR else macho.PLATFORM_TVOS,
                else => unreachable,
            },
            .minos = version,
            .sdk = version,
            .ntools = 1,
        });
        const ld_ver = macho.build_tool_version{
            .tool = macho.TOOL_LD,
            .version = 0x0,
        };
        cmd.data = try self.base.allocator.alloc(u8, cmdsize - @sizeOf(macho.build_version_command));
        mem.set(u8, cmd.data, 0);
        mem.copy(u8, cmd.data, mem.asBytes(&ld_ver));
        try self.load_commands.append(self.base.allocator, .{ .BuildVersion = cmd });
    }

    if (self.uuid_cmd_index == null) {
        self.uuid_cmd_index = @intCast(u16, self.load_commands.items.len);
        var uuid_cmd: macho.uuid_command = .{
            .cmd = macho.LC_UUID,
            .cmdsize = @sizeOf(macho.uuid_command),
            .uuid = undefined,
        };
        std.crypto.random.bytes(&uuid_cmd.uuid);
        try self.load_commands.append(self.base.allocator, .{ .Uuid = uuid_cmd });
    }
}

fn writeDyldInfoData(self: *MachO) !void {
    var rebase_pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer rebase_pointers.deinit();
    var bind_pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer bind_pointers.deinit();
    var lazy_bind_pointers = std.ArrayList(bind.Pointer).init(self.base.allocator);
    defer lazy_bind_pointers.deinit();

    {
        var it = self.atoms.iterator();
        while (it.next()) |entry| {
            const match = entry.key_ptr.*;
            var atom: *Atom = entry.value_ptr.*;

            if (match.seg == self.text_segment_cmd_index.?) continue; // __TEXT is non-writable

            const seg = self.load_commands.items[match.seg].Segment;

            while (true) {
                const sym = self.locals.items[atom.local_sym_index];
                const base_offset = sym.n_value - seg.inner.vmaddr;

                for (atom.rebases.items) |offset| {
                    try rebase_pointers.append(.{
                        .offset = base_offset + offset,
                        .segment_id = match.seg,
                    });
                }

                for (atom.bindings.items) |binding| {
                    const bind_sym = self.undefs.items[binding.local_sym_index];
                    try bind_pointers.append(.{
                        .offset = binding.offset + base_offset,
                        .segment_id = match.seg,
                        .dylib_ordinal = @divExact(bind_sym.n_desc, macho.N_SYMBOL_RESOLVER),
                        .name = self.getString(bind_sym.n_strx),
                    });
                }

                for (atom.lazy_bindings.items) |binding| {
                    const bind_sym = self.undefs.items[binding.local_sym_index];
                    try lazy_bind_pointers.append(.{
                        .offset = binding.offset + base_offset,
                        .segment_id = match.seg,
                        .dylib_ordinal = @divExact(bind_sym.n_desc, macho.N_SYMBOL_RESOLVER),
                        .name = self.getString(bind_sym.n_strx),
                    });
                }

                if (atom.prev) |prev| {
                    atom = prev;
                } else break;
            }
        }
    }

    var trie: Trie = .{};
    defer trie.deinit(self.base.allocator);

    {
        // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
        log.debug("generating export trie", .{});
        const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
        const base_address = text_segment.inner.vmaddr;

        for (self.globals.items) |sym| {
            if (sym.n_type == 0) continue;
            const sym_name = self.getString(sym.n_strx);
            log.debug("  (putting '{s}' defined at 0x{x})", .{ sym_name, sym.n_value });

            try trie.put(self.base.allocator, .{
                .name = sym_name,
                .vmaddr_offset = sym.n_value - base_address,
                .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
            });
        }

        try trie.finalize(self.base.allocator);
    }

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dyld_info = &self.load_commands.items[self.dyld_info_cmd_index.?].DyldInfoOnly;
    const rebase_size = try bind.rebaseInfoSize(rebase_pointers.items);
    const bind_size = try bind.bindInfoSize(bind_pointers.items);
    const lazy_bind_size = try bind.lazyBindInfoSize(lazy_bind_pointers.items);
    const export_size = trie.size;

    dyld_info.rebase_off = @intCast(u32, seg.inner.fileoff);
    dyld_info.rebase_size = @intCast(u32, mem.alignForwardGeneric(u64, rebase_size, @alignOf(u64)));
    seg.inner.filesize += dyld_info.rebase_size;

    dyld_info.bind_off = dyld_info.rebase_off + dyld_info.rebase_size;
    dyld_info.bind_size = @intCast(u32, mem.alignForwardGeneric(u64, bind_size, @alignOf(u64)));
    seg.inner.filesize += dyld_info.bind_size;

    dyld_info.lazy_bind_off = dyld_info.bind_off + dyld_info.bind_size;
    dyld_info.lazy_bind_size = @intCast(u32, mem.alignForwardGeneric(u64, lazy_bind_size, @alignOf(u64)));
    seg.inner.filesize += dyld_info.lazy_bind_size;

    dyld_info.export_off = dyld_info.lazy_bind_off + dyld_info.lazy_bind_size;
    dyld_info.export_size = @intCast(u32, mem.alignForwardGeneric(u64, export_size, @alignOf(u64)));
    seg.inner.filesize += dyld_info.export_size;

    const needed_size = dyld_info.rebase_size + dyld_info.bind_size + dyld_info.lazy_bind_size + dyld_info.export_size;
    var buffer = try self.base.allocator.alloc(u8, needed_size);
    defer self.base.allocator.free(buffer);
    mem.set(u8, buffer, 0);

    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();

    try bind.writeRebaseInfo(rebase_pointers.items, writer);
    try stream.seekBy(@intCast(i64, dyld_info.rebase_size) - @intCast(i64, rebase_size));

    try bind.writeBindInfo(bind_pointers.items, writer);
    try stream.seekBy(@intCast(i64, dyld_info.bind_size) - @intCast(i64, bind_size));

    try bind.writeLazyBindInfo(lazy_bind_pointers.items, writer);
    try stream.seekBy(@intCast(i64, dyld_info.lazy_bind_size) - @intCast(i64, lazy_bind_size));

    _ = try trie.write(writer);

    log.debug("writing dyld info from 0x{x} to 0x{x}", .{
        dyld_info.rebase_off,
        dyld_info.rebase_off + needed_size,
    });

    try self.base.file.pwriteAll(buffer, dyld_info.rebase_off);
    try self.populateLazyBindOffsetsInStubHelper(
        buffer[dyld_info.rebase_size + dyld_info.bind_size ..][0..dyld_info.lazy_bind_size],
    );
}

fn populateLazyBindOffsetsInStubHelper(self: *MachO, buffer: []const u8) !void {
    const last_atom = self.atoms.get(.{
        .seg = self.text_segment_cmd_index.?,
        .sect = self.stub_helper_section_index.?,
    }) orelse return;
    if (last_atom == self.stub_helper_preamble_atom.?) return;

    // Because we insert lazy binding opcodes in reverse order (from last to the first atom),
    // we need reverse the order of atom traversal here as well.
    // TODO figure out a less error prone mechanims for this!
    var atom = last_atom;
    while (atom.prev) |prev| {
        atom = prev;
    }
    atom = atom.next.?;

    var stream = std.io.fixedBufferStream(buffer);
    var reader = stream.reader();
    var offsets = std.ArrayList(u32).init(self.base.allocator);
    try offsets.append(0);
    defer offsets.deinit();
    var valid_block = false;

    while (true) {
        const inst = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const opcode: u8 = inst & macho.BIND_OPCODE_MASK;

        switch (opcode) {
            macho.BIND_OPCODE_DO_BIND => {
                valid_block = true;
            },
            macho.BIND_OPCODE_DONE => {
                if (valid_block) {
                    const offset = try stream.getPos();
                    try offsets.append(@intCast(u32, offset));
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
                _ = try std.leb.readULEB128(u64, reader);
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

    const seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const sect = seg.sections.items[self.stub_helper_section_index.?];
    const stub_offset: u4 = switch (self.base.options.target.cpu.arch) {
        .x86_64 => 1,
        .aarch64 => 2 * @sizeOf(u32),
        else => unreachable,
    };
    var buf: [@sizeOf(u32)]u8 = undefined;
    _ = offsets.pop();
    while (offsets.popOrNull()) |bind_offset| {
        const sym = self.locals.items[atom.local_sym_index];
        const file_offset = sect.offset + sym.n_value - sect.addr + stub_offset;
        mem.writeIntLittle(u32, &buf, bind_offset);
        log.debug("writing lazy bind offset in stub helper of 0x{x} for symbol {s} at offset 0x{x}", .{
            bind_offset,
            self.getString(sym.n_strx),
            file_offset,
        });
        try self.base.file.pwriteAll(&buf, file_offset);

        if (atom.next) |next| {
            atom = next;
        } else break;
    }
}

fn writeDices(self: *MachO) !void {
    if (!self.has_dices) return;

    var buf = std.ArrayList(u8).init(self.base.allocator);
    defer buf.deinit();

    var atom: *Atom = self.atoms.get(.{
        .seg = self.text_segment_cmd_index orelse return,
        .sect = self.text_section_index orelse return,
    }) orelse return;

    while (atom.prev) |prev| {
        atom = prev;
    }

    const text_seg = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const text_sect = text_seg.sections.items[self.text_section_index.?];

    while (true) {
        if (atom.dices.items.len > 0) {
            const sym = self.locals.items[atom.local_sym_index];
            const base_off = try math.cast(u32, sym.n_value - text_sect.addr + text_sect.offset);

            try buf.ensureUnusedCapacity(atom.dices.items.len * @sizeOf(macho.data_in_code_entry));
            for (atom.dices.items) |dice| {
                const rebased_dice = macho.data_in_code_entry{
                    .offset = base_off + dice.offset,
                    .length = dice.length,
                    .kind = dice.kind,
                };
                buf.appendSliceAssumeCapacity(mem.asBytes(&rebased_dice));
            }
        }

        if (atom.next) |next| {
            atom = next;
        } else break;
    }

    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const dice_cmd = &self.load_commands.items[self.data_in_code_cmd_index.?].LinkeditData;
    const needed_size = @intCast(u32, buf.items.len);

    dice_cmd.dataoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dice_cmd.datasize = needed_size;
    seg.inner.filesize += needed_size;

    log.debug("writing data-in-code from 0x{x} to 0x{x}", .{
        dice_cmd.dataoff,
        dice_cmd.dataoff + dice_cmd.datasize,
    });

    try self.base.file.pwriteAll(buf.items, dice_cmd.dataoff);
}

fn writeSymbolTable(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    symtab.symoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);

    var locals = std.ArrayList(macho.nlist_64).init(self.base.allocator);
    defer locals.deinit();

    for (self.locals.items) |sym| {
        if (sym.n_strx == 0) continue;
        if (symbolIsTemp(sym, self.getString(sym.n_strx))) continue;
        try locals.append(sym);
    }

    if (self.has_stabs) {
        for (self.objects.items) |object| {
            if (object.debug_info == null) continue;

            // Open scope
            try locals.ensureUnusedCapacity(3);
            locals.appendAssumeCapacity(.{
                .n_strx = try self.makeString(object.tu_comp_dir.?),
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
            locals.appendAssumeCapacity(.{
                .n_strx = try self.makeString(object.tu_name.?),
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            });
            locals.appendAssumeCapacity(.{
                .n_strx = try self.makeString(object.name),
                .n_type = macho.N_OSO,
                .n_sect = 0,
                .n_desc = 1,
                .n_value = object.mtime orelse 0,
            });

            for (object.contained_atoms.items) |atom| {
                if (atom.stab) |stab| {
                    const nlists = try stab.asNlists(atom.local_sym_index, self);
                    defer self.base.allocator.free(nlists);
                    try locals.appendSlice(nlists);
                } else {
                    for (atom.contained.items) |sym_at_off| {
                        const stab = sym_at_off.stab orelse continue;
                        const nlists = try stab.asNlists(sym_at_off.local_sym_index, self);
                        defer self.base.allocator.free(nlists);
                        try locals.appendSlice(nlists);
                    }
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
    }

    const nlocals = locals.items.len;
    const nexports = self.globals.items.len;
    const nundefs = self.undefs.items.len;

    const locals_off = symtab.symoff;
    const locals_size = nlocals * @sizeOf(macho.nlist_64);
    log.debug("writing local symbols from 0x{x} to 0x{x}", .{ locals_off, locals_size + locals_off });
    try self.base.file.pwriteAll(mem.sliceAsBytes(locals.items), locals_off);

    const exports_off = locals_off + locals_size;
    const exports_size = nexports * @sizeOf(macho.nlist_64);
    log.debug("writing exported symbols from 0x{x} to 0x{x}", .{ exports_off, exports_size + exports_off });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.globals.items), exports_off);

    const undefs_off = exports_off + exports_size;
    const undefs_size = nundefs * @sizeOf(macho.nlist_64);
    log.debug("writing undefined symbols from 0x{x} to 0x{x}", .{ undefs_off, undefs_size + undefs_off });
    try self.base.file.pwriteAll(mem.sliceAsBytes(self.undefs.items), undefs_off);

    symtab.nsyms = @intCast(u32, nlocals + nexports + nundefs);
    seg.inner.filesize += locals_size + exports_size + undefs_size;

    // Update dynamic symbol table.
    const dysymtab = &self.load_commands.items[self.dysymtab_cmd_index.?].Dysymtab;
    dysymtab.nlocalsym = @intCast(u32, nlocals);
    dysymtab.iextdefsym = dysymtab.nlocalsym;
    dysymtab.nextdefsym = @intCast(u32, nexports);
    dysymtab.iundefsym = dysymtab.nlocalsym + dysymtab.nextdefsym;
    dysymtab.nundefsym = @intCast(u32, nundefs);

    const text_segment = &self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const stubs = &text_segment.sections.items[self.stubs_section_index.?];
    const data_const_segment = &self.load_commands.items[self.data_const_segment_cmd_index.?].Segment;
    const got = &data_const_segment.sections.items[self.got_section_index.?];
    const data_segment = &self.load_commands.items[self.data_segment_cmd_index.?].Segment;
    const la_symbol_ptr = &data_segment.sections.items[self.la_symbol_ptr_section_index.?];

    const nstubs = @intCast(u32, self.stubs_map.keys().len);
    const ngot_entries = @intCast(u32, self.got_entries_map.keys().len);

    dysymtab.indirectsymoff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    dysymtab.nindirectsyms = nstubs * 2 + ngot_entries;

    const needed_size = dysymtab.nindirectsyms * @sizeOf(u32);
    seg.inner.filesize += needed_size;

    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{
        dysymtab.indirectsymoff,
        dysymtab.indirectsymoff + needed_size,
    });

    var buf = try self.base.allocator.alloc(u8, needed_size);
    defer self.base.allocator.free(buf);

    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();

    stubs.reserved1 = 0;
    for (self.stubs_map.keys()) |key| {
        try writer.writeIntLittle(u32, dysymtab.iundefsym + key);
    }

    got.reserved1 = nstubs;
    for (self.got_entries_map.keys()) |key| {
        switch (key.where) {
            .undef => {
                try writer.writeIntLittle(u32, dysymtab.iundefsym + key.where_index);
            },
            .local => {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            },
        }
    }

    la_symbol_ptr.reserved1 = got.reserved1 + ngot_entries;
    for (self.stubs_map.keys()) |key| {
        try writer.writeIntLittle(u32, dysymtab.iundefsym + key);
    }

    try self.base.file.pwriteAll(buf, dysymtab.indirectsymoff);
}

fn writeStringTable(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const symtab = &self.load_commands.items[self.symtab_cmd_index.?].Symtab;
    symtab.stroff = @intCast(u32, seg.inner.fileoff + seg.inner.filesize);
    symtab.strsize = @intCast(u32, mem.alignForwardGeneric(u64, self.strtab.items.len, @alignOf(u64)));
    seg.inner.filesize += symtab.strsize;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ symtab.stroff, symtab.stroff + symtab.strsize });

    try self.base.file.pwriteAll(self.strtab.items, symtab.stroff);

    if (symtab.strsize > self.strtab.items.len) {
        // This is potentially the last section, so we need to pad it out.
        try self.base.file.pwriteAll(&[_]u8{0}, seg.inner.fileoff + seg.inner.filesize - 1);
    }
}

fn writeLinkeditSegment(self: *MachO) !void {
    const seg = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    seg.inner.filesize = 0;

    try self.writeDyldInfoData();
    try self.writeDices();
    try self.writeSymbolTable();
    try self.writeStringTable();

    seg.inner.vmsize = mem.alignForwardGeneric(u64, seg.inner.filesize, self.page_size);
}

fn writeCodeSignaturePadding(self: *MachO) !void {
    const linkedit_segment = &self.load_commands.items[self.linkedit_segment_cmd_index.?].Segment;
    const code_sig_cmd = &self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;
    const fileoff = linkedit_segment.inner.fileoff + linkedit_segment.inner.filesize;
    const needed_size = CodeSignature.calcCodeSignaturePaddingSize(
        self.base.options.emit.sub_path,
        fileoff,
        self.page_size,
    );
    code_sig_cmd.dataoff = @intCast(u32, fileoff);
    code_sig_cmd.datasize = needed_size;

    // Advance size of __LINKEDIT segment
    linkedit_segment.inner.filesize += needed_size;
    if (linkedit_segment.inner.vmsize < linkedit_segment.inner.filesize) {
        linkedit_segment.inner.vmsize = mem.alignForwardGeneric(u64, linkedit_segment.inner.filesize, self.page_size);
    }
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ fileoff, fileoff + needed_size });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.base.file.pwriteAll(&[_]u8{0}, fileoff + needed_size - 1);
}

fn writeCodeSignature(self: *MachO) !void {
    const text_segment = self.load_commands.items[self.text_segment_cmd_index.?].Segment;
    const code_sig_cmd = self.load_commands.items[self.code_signature_cmd_index.?].LinkeditData;

    var code_sig: CodeSignature = .{};
    defer code_sig.deinit(self.base.allocator);

    try code_sig.calcAdhocSignature(
        self.base.allocator,
        self.base.file,
        self.base.options.emit.sub_path,
        text_segment.inner,
        code_sig_cmd,
        self.base.options.output_mode,
        self.page_size,
    );

    var buffer = try self.base.allocator.alloc(u8, code_sig.size());
    defer self.base.allocator.free(buffer);
    var stream = std.io.fixedBufferStream(buffer);
    try code_sig.write(stream.writer());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{ code_sig_cmd.dataoff, code_sig_cmd.dataoff + buffer.len });

    try self.base.file.pwriteAll(buffer, code_sig_cmd.dataoff);
}

/// Writes all load commands and section headers.
fn writeLoadCommands(self: *MachO) !void {
    var sizeofcmds: u32 = 0;
    for (self.load_commands.items) |lc| {
        sizeofcmds += lc.cmdsize();
    }

    var buffer = try self.base.allocator.alloc(u8, sizeofcmds);
    defer self.base.allocator.free(buffer);
    var writer = std.io.fixedBufferStream(buffer).writer();
    for (self.load_commands.items) |lc| {
        try lc.write(writer);
    }

    const off = @sizeOf(macho.mach_header_64);

    log.debug("writing {} load commands from 0x{x} to 0x{x}", .{ self.load_commands.items.len, off, off + sizeofcmds });

    try self.base.file.pwriteAll(buffer, off);
}

/// Writes Mach-O file header.
fn writeHeader(self: *MachO) !void {
    var header = commands.emptyHeader(.{
        .flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE | macho.MH_TWOLEVEL,
    });

    switch (self.base.options.target.cpu.arch) {
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

    switch (self.base.options.output_mode) {
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

    header.ncmds = @intCast(u32, self.load_commands.items.len);
    header.sizeofcmds = 0;

    for (self.load_commands.items) |cmd| {
        header.sizeofcmds += cmd.cmdsize();
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

pub fn makeString(self: *MachO, string: []const u8) !u32 {
    const gop = try self.strtab_dir.getOrPutContextAdapted(self.base.allocator, @as([]const u8, string), StringIndexAdapter{
        .bytes = &self.strtab,
    }, StringIndexContext{
        .bytes = &self.strtab,
    });
    if (gop.found_existing) {
        const off = gop.key_ptr.*;
        log.debug("reusing string '{s}' at offset 0x{x}", .{ string, off });
        return off;
    }

    try self.strtab.ensureUnusedCapacity(self.base.allocator, string.len + 1);
    const new_off = @intCast(u32, self.strtab.items.len);

    log.debug("writing new string '{s}' at offset 0x{x}", .{ string, new_off });

    self.strtab.appendSliceAssumeCapacity(string);
    self.strtab.appendAssumeCapacity(0);

    gop.key_ptr.* = new_off;

    return new_off;
}

pub fn getString(self: *MachO, off: u32) []const u8 {
    assert(off < self.strtab.items.len);
    return mem.spanZ(@ptrCast([*:0]const u8, self.strtab.items.ptr + off));
}

pub fn symbolIsStab(sym: macho.nlist_64) bool {
    return (macho.N_STAB & sym.n_type) != 0;
}

pub fn symbolIsPext(sym: macho.nlist_64) bool {
    return (macho.N_PEXT & sym.n_type) != 0;
}

pub fn symbolIsExt(sym: macho.nlist_64) bool {
    return (macho.N_EXT & sym.n_type) != 0;
}

pub fn symbolIsSect(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_SECT;
}

pub fn symbolIsUndf(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_UNDF;
}

pub fn symbolIsIndr(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_INDR;
}

pub fn symbolIsAbs(sym: macho.nlist_64) bool {
    const type_ = macho.N_TYPE & sym.n_type;
    return type_ == macho.N_ABS;
}

pub fn symbolIsWeakDef(sym: macho.nlist_64) bool {
    return (sym.n_desc & macho.N_WEAK_DEF) != 0;
}

pub fn symbolIsWeakRef(sym: macho.nlist_64) bool {
    return (sym.n_desc & macho.N_WEAK_REF) != 0;
}

pub fn symbolIsTentative(sym: macho.nlist_64) bool {
    if (!symbolIsUndf(sym)) return false;
    return sym.n_value != 0;
}

pub fn symbolIsTemp(sym: macho.nlist_64, sym_name: []const u8) bool {
    if (!symbolIsSect(sym)) return false;
    if (symbolIsExt(sym)) return false;
    return mem.startsWith(u8, sym_name, "l") or mem.startsWith(u8, sym_name, "L");
}

pub fn findFirst(comptime T: type, haystack: []T, start: usize, predicate: anytype) usize {
    if (!@hasDecl(@TypeOf(predicate), "predicate"))
        @compileError("Predicate is required to define fn predicate(@This(), T) bool");

    if (start == haystack.len) return start;

    var i = start;
    while (i < haystack.len) : (i += 1) {
        if (predicate.predicate(haystack[i])) break;
    }
    return i;
}
