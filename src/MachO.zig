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
const calcUuid = @import("MachO/uuid.zig").calcUuid;
const dead_strip = @import("MachO/dead_strip.zig");
const eh_frame = @import("MachO/eh_frame.zig");
const fat = @import("MachO/fat.zig");
const load_commands = @import("MachO/load_commands.zig");
const thunks = @import("MachO/thunks.zig");
const trace = @import("tracy.zig").trace;

const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const Archive = @import("MachO/Archive.zig");
const Atom = @import("MachO/Atom.zig");
const CodeSignature = @import("MachO/CodeSignature.zig");
const Dylib = @import("MachO/Dylib.zig");
const DwarfInfo = @import("MachO/DwarfInfo.zig");
const Md5 = std.crypto.hash.Md5;
const Object = @import("MachO/Object.zig");
pub const Options = @import("MachO/Options.zig");
const LibStub = @import("tapi.zig").LibStub;
const StringTable = @import("strtab.zig").StringTable;
const ThreadPool = std.Thread.Pool;
const Trie = @import("MachO/Trie.zig");
const UnwindInfo = @import("MachO/UnwindInfo.zig");
const Zld = @import("Zld.zig");

const Bind = @import("MachO/dyld_info/bind.zig").Bind(*const MachO, MachO.SymbolWithLoc);
const LazyBind = @import("MachO/dyld_info/bind.zig").LazyBind(*const MachO, MachO.SymbolWithLoc);
const Rebase = @import("MachO/dyld_info/Rebase.zig");

pub const base_tag = Zld.Tag.macho;

const Section = struct {
    header: macho.section_64,
    segment_index: u8,
    first_atom_index: AtomIndex,
    last_atom_index: AtomIndex,
};

base: Zld,
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

objects: std.ArrayListUnmanaged(Object) = .{},
archives: std.ArrayListUnmanaged(Archive) = .{},
dylibs: std.ArrayListUnmanaged(Dylib) = .{},
dylibs_map: std.StringHashMapUnmanaged(u16) = .{},
referenced_dylibs: std.AutoArrayHashMapUnmanaged(u16, void) = .{},

segments: std.ArrayListUnmanaged(macho.segment_command_64) = .{},
sections: std.MultiArrayList(Section) = .{},

locals: std.ArrayListUnmanaged(macho.nlist_64) = .{},
globals: std.ArrayListUnmanaged(SymbolWithLoc) = .{},

entry_index: ?u32 = null,
mh_execute_header_index: ?u32 = null,
dso_handle_index: ?u32 = null,
dyld_stub_binder_index: ?u32 = null,
dyld_private_sym_index: ?u32 = null,
stub_helper_preamble_sym_index: ?u32 = null,

strtab: StringTable(.strtab) = .{},

tlv_ptr_entries: std.ArrayListUnmanaged(IndirectPointer) = .{},
tlv_ptr_table: std.AutoHashMapUnmanaged(SymbolWithLoc, u32) = .{},

got_entries: std.ArrayListUnmanaged(IndirectPointer) = .{},
got_table: std.AutoHashMapUnmanaged(SymbolWithLoc, u32) = .{},

stubs: std.ArrayListUnmanaged(IndirectPointer) = .{},
stubs_table: std.AutoHashMapUnmanaged(SymbolWithLoc, u32) = .{},

thunk_table: std.AutoHashMapUnmanaged(AtomIndex, thunks.ThunkIndex) = .{},
thunks: std.ArrayListUnmanaged(thunks.Thunk) = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

pub const AtomIndex = u32;

pub const IndirectPointer = struct {
    target: SymbolWithLoc,
    atom_index: AtomIndex,

    pub fn getTargetSymbol(self: @This(), macho_file: *MachO) macho.nlist_64 {
        return macho_file.getSymbol(self.target);
    }

    pub fn getTargetSymbolName(self: @This(), macho_file: *MachO) []const u8 {
        return macho_file.getSymbolName(self.target);
    }

    pub fn getAtomSymbol(self: @This(), macho_file: *MachO) macho.nlist_64 {
        const atom = macho_file.getAtom(self.atom_index);
        return macho_file.getSymbol(atom.getSymbolWithLoc());
    }
};

pub const SymbolWithLoc = extern struct {
    // Index into the respective symbol table.
    sym_index: u32,

    // 0 means it's a synthetic global.
    file: u32 = 0,

    pub fn getFile(self: SymbolWithLoc) ?u32 {
        if (self.file == 0) return null;
        return self.file - 1;
    }

    pub fn eql(self: SymbolWithLoc, other: SymbolWithLoc) bool {
        return self.file == other.file and self.sym_index == other.sym_index;
    }
};

pub const SymbolResolver = struct {
    arena: Allocator,
    table: std.StringHashMap(u32),
    unresolved: std.AutoArrayHashMap(u32, void),
};

pub const LinkObject = struct {
    path: []const u8 = "",
    tag: enum { obj, lib, framework },
    needed: bool = false,
    weak: bool = false,
    must_link: bool = false,
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

pub const N_DEAD: u16 = @as(u16, @bitCast(@as(i16, -1)));

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
        .options = options,
    };
    return self;
}

pub fn flush(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    var arena_allocator = ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const syslibroot = self.options.syslibroot;

    try self.atoms.append(gpa, Atom.empty); // AtomIndex at 0 is reserved as null atom
    try self.strtab.buffer.append(gpa, 0);

    // Resolve paths
    var lib_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.lib_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try lib_dirs.append(search_dir);
        } else {
            self.base.warn("directory not found for '-L{s}'", .{dir});
        }
    }

    var framework_dirs = std.ArrayList([]const u8).init(arena);
    for (self.options.framework_dirs) |dir| {
        if (try resolveSearchDir(arena, dir, syslibroot)) |search_dir| {
            try framework_dirs.append(search_dir);
        } else {
            self.base.warn("directory not found for '-F{s}'", .{dir});
        }
    }

    var objects = std.ArrayList(LinkObject).init(arena);
    try objects.ensureTotalCapacityPrecise(self.options.objects.len);
    for (self.options.objects) |obj| {
        try self.resolveLinkObjectPath(arena, obj, lib_dirs.items, framework_dirs.items, &objects);
    }

    if (self.base.errors.items.len > 0) {
        {
            const err = try self.base.addErrorWithNotes(lib_dirs.items.len);
            try err.addMsg("Library search paths", .{});
            for (lib_dirs.items) |dir| {
                try err.addNote("{s}", .{dir});
            }
        }

        {
            const err = try self.base.addErrorWithNotes(framework_dirs.items.len);
            try err.addMsg("Framework search paths", .{});
            for (framework_dirs.items) |dir| {
                try err.addNote("{s}", .{dir});
            }
        }
    }

    self.base.reportWarningsAndErrorsAndExit();

    // Parse input objects
    for (objects.items) |obj| {
        try self.parseObject(obj);
    }

    var dependent_libs = std.fifo.LinearFifo(struct {
        id: Dylib.Id,
        parent: u16,
    }, .Dynamic).init(arena);

    for (objects.items) |obj| {
        try self.parseLibrary(obj, &dependent_libs);
    }

    try self.parseDependentLibs(syslibroot, &dependent_libs);

    var resolver = SymbolResolver{
        .arena = arena,
        .table = std.StringHashMap(u32).init(arena),
        .unresolved = std.AutoArrayHashMap(u32, void).init(arena),
    };
    try self.resolveSymbols(&resolver);
    try self.reportUndefs(&resolver);
    self.base.reportWarningsAndErrorsAndExit();

    if (self.options.output_mode == .exe) {
        const entry_name = self.options.entry orelse default_entry_point;
        const global_index = resolver.table.get(entry_name).?; // Error was flagged earlier
        self.entry_index = global_index;
    }

    try self.splitIntoAtoms();

    if (self.options.dead_strip) {
        try dead_strip.gcAtoms(self, &resolver);
    }

    try self.createDyldPrivateAtom();
    try self.createTentativeDefAtoms();
    try self.createStubHelperPreambleAtom();

    if (self.options.output_mode == .exe) {
        const global = self.getEntryPoint();
        if (self.getSymbol(global).undf()) {
            // We do one additional check here in case the entry point was found in one of the dylibs.
            // (I actually have no idea what this would imply but it is a possible outcome and so we
            // support it.)
            try Atom.addStub(self, global);
        }
    }

    for (self.objects.items) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());
            const header = self.sections.items(.header)[sym.n_sect - 1];
            if (header.isZerofill()) continue;

            const relocs = Atom.getAtomRelocs(self, atom_index);
            try Atom.scanAtomRelocs(self, atom_index, relocs);
        }
    }

    try eh_frame.scanRelocs(self);
    try UnwindInfo.scanRelocs(self);

    self.base.reportWarningsAndErrorsAndExit();

    try self.createDyldStubBinderGotAtom();

    try self.calcSectionSizes();

    var unwind_info = UnwindInfo{ .gpa = self.base.allocator };
    defer unwind_info.deinit();
    try unwind_info.collect(self);

    try eh_frame.calcSectionSize(self, &unwind_info);
    try unwind_info.calcSectionSize(self);

    try self.pruneAndSortSections();
    try self.createSegments();
    try self.allocateSegments();

    try self.allocateSpecialSymbols();

    if (build_options.enable_logging) {
        self.logSymtab();
        self.logSegments();
        self.logSections();
        self.logAtoms();
    }

    try self.writeAtoms();
    try eh_frame.write(self, &unwind_info);
    try unwind_info.write(self);
    try self.writeLinkeditSegmentData();

    // If the last section of __DATA segment is zerofill section, we need to ensure
    // that the free space between the end of the last non-zerofill section of __DATA
    // segment and the beginning of __LINKEDIT segment is zerofilled as the loader will
    // copy-paste this space into memory for quicker zerofill operation.
    if (self.getSegmentByName("__DATA")) |data_seg_id| blk: {
        var physical_zerofill_start: ?u64 = null;
        const section_indexes = self.getSectionIndexes(data_seg_id);
        for (self.sections.items(.header)[section_indexes.start..section_indexes.end]) |header| {
            if (header.isZerofill() and header.size > 0) break;
            physical_zerofill_start = header.offset + header.size;
        } else break :blk;
        const start = physical_zerofill_start orelse break :blk;
        const linkedit = self.getLinkeditSegmentPtr();
        const size = linkedit.fileoff - start;
        if (size > 0) {
            log.debug("zeroing out zerofill area of length {x} at {x}", .{ size, start });
            var padding = try self.base.allocator.alloc(u8, size);
            defer self.base.allocator.free(padding);
            @memset(padding, 0);
            try self.base.file.pwriteAll(padding, start);
        }
    }

    var codesig: ?CodeSignature = if (self.requiresCodeSig()) blk: {
        // Preallocate space for the code signature.
        // We need to do this at this stage so that we have the load commands with proper values
        // written out to the file.
        // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
        // where the code signature goes into.
        var codesig = CodeSignature.init(self.getPageSize());
        codesig.code_directory.ident = fs.path.basename(self.options.emit.sub_path);
        if (self.options.entitlements) |path| {
            try codesig.addEntitlements(gpa, path);
        }
        try self.writeCodeSignaturePadding(&codesig);
        break :blk codesig;
    } else null;
    defer if (codesig) |*csig| csig.deinit(gpa);

    // Write load commands
    var lc_buffer = std.ArrayList(u8).init(arena);
    const lc_writer = lc_buffer.writer();

    try self.writeSegmentHeaders(lc_writer);
    try lc_writer.writeStruct(self.dyld_info_cmd);
    try lc_writer.writeStruct(self.function_starts_cmd);
    try lc_writer.writeStruct(self.data_in_code_cmd);
    try lc_writer.writeStruct(self.symtab_cmd);
    try lc_writer.writeStruct(self.dysymtab_cmd);
    try load_commands.writeDylinkerLC(lc_writer);

    if (self.options.output_mode == .exe) {
        const seg_id = self.getSegmentByName("__TEXT").?;
        const seg = self.segments.items[seg_id];
        const global = self.getEntryPoint();
        const sym = self.getSymbol(global);

        const addr: u64 = if (sym.undf()) blk: {
            // In this case, the symbol has been resolved in one of dylibs and so we point
            // to the stub as its vmaddr value.
            const stub_atom_index = self.getStubsAtomIndexForSymbol(global).?;
            const stub_atom = self.getAtom(stub_atom_index);
            const stub_sym = self.getSymbol(stub_atom.getSymbolWithLoc());
            break :blk stub_sym.n_value;
        } else sym.n_value;

        try lc_writer.writeStruct(macho.entry_point_command{
            .entryoff = @as(u32, @intCast(addr - seg.vmaddr)),
            .stacksize = self.options.stack_size orelse 0,
        });
    } else {
        assert(self.options.output_mode == .lib);
        try load_commands.writeDylibIdLC(&self.options, lc_writer);
    }

    try load_commands.writeRpathLCs(self.base.allocator, &self.options, lc_writer);
    try lc_writer.writeStruct(macho.source_version_command{
        .version = 0,
    });
    try load_commands.writeBuildVersionLC(&self.options, lc_writer);

    const uuid_cmd_offset = @sizeOf(macho.mach_header_64) + @as(u32, @intCast(lc_buffer.items.len));
    try lc_writer.writeStruct(self.uuid_cmd);

    try load_commands.writeLoadDylibLCs(self.dylibs.items, self.referenced_dylibs.keys(), lc_writer);

    if (self.requiresCodeSig()) {
        try lc_writer.writeStruct(self.codesig_cmd);
    }

    const ncmds = load_commands.calcNumOfLCs(lc_buffer.items);
    try self.base.file.pwriteAll(lc_buffer.items, @sizeOf(macho.mach_header_64));
    try self.writeHeader(ncmds, @as(u32, @intCast(lc_buffer.items.len)));

    try self.writeUuid(uuid_cmd_offset, self.requiresCodeSig());

    if (codesig) |*csig| {
        try self.writeCodeSignature(csig); // code signing always comes last

        if (comptime builtin.target.isDarwin()) {
            const dir = self.options.emit.directory;
            const path = self.options.emit.sub_path;
            try dir.copyFile(path, dir, path, .{});
        }
    }

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
    const search_strategy = self.options.search_strategy orelse .paths_first;
    switch (search_strategy) {
        .paths_first => return try resolvePathsFirst(arena, search_dirs, name),
        .dylibs_first => return try resolveDylibsFirst(arena, search_dirs, name),
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

fn resolveLinkObjectPath(
    self: *MachO,
    arena: Allocator,
    obj: LinkObject,
    lib_dirs: []const []const u8,
    framework_dirs: []const []const u8,
    resolved: *std.ArrayList(LinkObject),
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const full_path = blk: {
        switch (obj.tag) {
            .obj => {
                var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
                log.debug("resolving file path '{s}'", .{obj.path});
                const full_path = try std.fs.realpath(obj.path, &buffer);
                break :blk try arena.dupe(u8, full_path);
            },
            .lib => {
                const full_path = (try self.resolveLib(arena, lib_dirs, obj.path)) orelse
                    return self.base.fatal("library not found for -l{s}", .{obj.path});
                break :blk full_path;
            },
            .framework => {
                const full_path = (try self.resolveFramework(arena, framework_dirs, obj.path)) orelse
                    return self.base.fatal("framework not found for -framework {s}", .{obj.path});
                break :blk full_path;
            },
        }
    };
    resolved.appendAssumeCapacity(.{
        .path = full_path,
        .tag = obj.tag,
        .needed = obj.needed,
        .weak = obj.weak,
        .must_link = obj.must_link,
    });
}

fn parseObject(self: *MachO, obj: LinkObject) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer file.close();

    if (!Object.isObject(file)) return;

    const mtime: u64 = mtime: {
        const stat = file.stat() catch break :mtime 0;
        break :mtime @as(u64, @intCast(@divFloor(stat.mtime, 1_000_000_000)));
    };
    const file_stat = try file.stat();
    const file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;
    const contents = try file.readToEndAllocOptions(gpa, file_size, file_size, @alignOf(u64), null);

    var object = Object{
        .name = try gpa.dupe(u8, obj.path),
        .mtime = mtime,
        .contents = contents,
    };
    errdefer object.deinit(gpa);
    try object.parse(gpa);
    try self.objects.append(gpa, object);

    const cpu_arch: std.Target.Cpu.Arch = switch (object.header.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => unreachable,
    };
    const self_cpu_arch = self.options.cpu_arch orelse blk: {
        self.options.cpu_arch = cpu_arch;
        break :blk self.options.cpu_arch.?;
    };
    if (self_cpu_arch != cpu_arch) {
        self.base.fatal("{s}: invalid architecture '{s}', expected '{s}'", .{
            obj.path,
            @tagName(cpu_arch),
            @tagName(self_cpu_arch),
        });
    }
}

fn parseLibrary(self: *MachO, obj: LinkObject, dependent_libs: anytype) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    defer if (!Archive.isArchive(file)) file.close();

    if (Object.isObject(file)) return;

    if (Archive.isArchive(file)) {
        const offset: ?u64 = if (fat.isFatLibrary(file)) blk: {
            const offset = self.parseFatLibrary(obj.path, file) catch |err| switch (err) {
                error.NoArchSpecified, error.MissingArch => return,
                else => |e| return e,
            };
            try file.seekTo(offset);
            break :blk offset;
        } else null;

        if (self.options.cpu_arch == null) {
            return self.base.fatal("{s}: ignoring library as no architecture specified", .{obj.path});
        }

        var archive = Archive{
            .file = file,
            .fat_offset = offset orelse 0,
            .name = try gpa.dupe(u8, obj.path),
        };
        errdefer archive.deinit(gpa);

        try archive.parse(gpa, file.reader(), self);

        if (obj.must_link) {
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
    } else if (Dylib.isDylib(file)) {
        try self.parseDylib(obj.path, file, dependent_libs, .{
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
            error.NotLibStub => return self.base.fatal("{s}: unknown file type", .{obj.path}),
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

const DylibOpts = struct {
    syslibroot: ?[]const u8,
    id: ?Dylib.Id = null,
    dependent: bool = false,
    needed: bool = false,
    weak: bool = false,
};

fn parseDylib(self: *MachO, path: []const u8, file: std.fs.File, dependent_libs: anytype, opts: DylibOpts) !void {
    const gpa = self.base.allocator;
    const offset: ?u64 = if (fat.isFatLibrary(file)) blk: {
        const offset = self.parseFatLibrary(path, file) catch |err| switch (err) {
            error.NoArchSpecified, error.MissingArch => return,
            else => |e| return e,
        };
        try file.seekTo(offset);
        break :blk offset;
    } else null;

    const self_cpu_arch = self.options.cpu_arch orelse
        return self.base.fatal("{s}: ignoring library as no architecture specified", .{path});

    const file_stat = try file.stat();
    var file_size = math.cast(usize, file_stat.size) orelse return error.Overflow;

    file_size -= (offset orelse 0);

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

    self.addDylib(dylib, .{
        .syslibroot = self.options.syslibroot,
        .needed = opts.needed,
        .weak = opts.weak,
    }) catch |err| switch (err) {
        error.DylibAlreadyExists => dylib.deinit(gpa),
        else => |e| return e,
    };
}

fn parseLibStub(self: *MachO, path: []const u8, file: std.fs.File, dependent_libs: anytype, opts: DylibOpts) !void {
    var lib_stub = try LibStub.loadFromFile(self.base.allocator, file);
    defer lib_stub.deinit();

    if (lib_stub.inner.len == 0) return error.NotLibStub;

    const cpu_arch = self.options.cpu_arch orelse
        return self.base.fatal("{s}: ignoring library as no architecture specified", .{path});
    const platform = self.options.platform.?.platform;

    var matcher = try Dylib.TargetMatcher.init(self.base.allocator, cpu_arch, platform);
    defer matcher.deinit();

    for (lib_stub.inner) |elem| {
        if (try matcher.matchesTargetTbd(elem)) break;
    } else {
        const target = try Dylib.TargetMatcher.targetToAppleString(self.base.allocator, cpu_arch, platform);
        defer self.base.allocator.free(target);
        self.base.fatal("{s}: missing target in stub file: expected {s}", .{ path, target });
    }

    var dylib = Dylib{ .weak = opts.weak };
    errdefer dylib.deinit(self.base.allocator);

    try dylib.parseFromStub(
        self.base.allocator,
        cpu_arch,
        self.options.platform.?.platform,
        lib_stub,
        @intCast(self.dylibs.items.len),
        dependent_libs,
        path,
    );

    self.addDylib(dylib, .{
        .syslibroot = self.options.syslibroot,
        .needed = opts.needed,
        .weak = opts.weak,
    }) catch |err| switch (err) {
        error.DylibAlreadyExists => dylib.deinit(self.base.allocator),
        else => |e| return e,
    };
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

            const file = std.fs.cwd().openFile(full_path, .{}) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            defer file.close();

            log.debug("trying dependency at fully resolved path {s}", .{full_path});

            if (Dylib.isDylib(file)) {
                try self.parseDylib(full_path, file, dependent_libs, .{
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
                    error.NotLibStub => self.base.fatal("{s}: unable to resolve dependency", .{dep_id.id.name}),
                    else => |e| return e,
                };
            }
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
        // We handle unwind info separately.
        if (mem.eql(u8, "__TEXT", segname) and mem.eql(u8, "__eh_frame", sectname)) {
            break :blk null;
        }
        if (mem.eql(u8, "__LD", segname) and mem.eql(u8, "__compact_unwind", sectname)) {
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
            break :blk null;
        }

        switch (sect.type()) {
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
                        break :blk self.getSectionByName("__TEXT", sectname) orelse try self.initSection(
                            "__TEXT",
                            sectname,
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
                        break :blk self.getSectionByName("__DATA_CONST", sectname) orelse try self.initSection(
                            "__DATA_CONST",
                            sectname,
                            .{},
                        );
                    } else if (mem.eql(u8, sectname, "__data")) {
                        break :blk self.getSectionByName("__DATA", "__data") orelse try self.initSection(
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

pub fn addAtomToSection(self: *MachO, atom_index: AtomIndex) void {
    const atom = self.getAtomPtr(atom_index);
    const sym = self.getSymbol(atom.getSymbolWithLoc());
    var section = self.sections.get(sym.n_sect - 1);
    if (section.header.size > 0) {
        const last_atom = self.getAtomPtr(section.last_atom_index);
        last_atom.next_index = atom_index;
        atom.prev_index = section.last_atom_index;
    } else {
        section.first_atom_index = atom_index;
    }
    section.last_atom_index = atom_index;
    section.header.size += atom.size;
    self.sections.set(sym.n_sect - 1, section);
}

pub fn createEmptyAtom(self: *MachO, sym_index: u32, size: u64, alignment: u32) !AtomIndex {
    const gpa = self.base.allocator;
    const index = @as(AtomIndex, @intCast(self.atoms.items.len));
    const atom = try self.atoms.addOne(gpa);
    atom.* = Atom.empty;
    atom.sym_index = sym_index;
    atom.size = size;
    atom.alignment = alignment;

    log.debug("creating ATOM(%{d}) at index {d}", .{ sym_index, index });

    return index;
}

pub fn createGotAtom(self: *MachO) !AtomIndex {
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_type = macho.N_SECT;

    const sect_id = self.getSectionByName("__DATA_CONST", "__got") orelse
        try self.initSection("__DATA_CONST", "__got", .{
        .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
    });
    sym.n_sect = sect_id + 1;

    self.addAtomToSection(atom_index);

    return atom_index;
}

fn writeGotPointer(self: *MachO, got_index: u32, writer: anytype) !void {
    const target_addr = blk: {
        const entry = self.got_entries.items[got_index];
        const sym = entry.getTargetSymbol(self);
        break :blk sym.n_value;
    };
    try writer.writeIntLittle(u64, target_addr);
}

pub fn createTlvPtrAtom(self: *MachO) !AtomIndex {
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_type = macho.N_SECT;

    const sect_id = (try self.getOutputSection(.{
        .segname = makeStaticString("__DATA"),
        .sectname = makeStaticString("__thread_ptrs"),
        .flags = macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
    })).?;
    sym.n_sect = sect_id + 1;

    self.addAtomToSection(atom_index);

    return atom_index;
}

fn createDyldStubBinderGotAtom(self: *MachO) !void {
    const sym_index = self.dyld_stub_binder_index orelse return;
    const gpa = self.base.allocator;
    const target = SymbolWithLoc{ .sym_index = sym_index };
    const atom_index = try self.createGotAtom();
    const got_index = @as(u32, @intCast(self.got_entries.items.len));
    try self.got_entries.append(gpa, .{
        .target = target,
        .atom_index = atom_index,
    });
    try self.got_table.putNoClobber(gpa, target, got_index);
}

fn createDyldPrivateAtom(self: *MachO) !void {
    if (self.dyld_stub_binder_index == null) return;

    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_type = macho.N_SECT;

    const sect_id = self.getSectionByName("__DATA", "__data") orelse try self.initSection("__DATA", "__data", .{});
    sym.n_sect = sect_id + 1;

    self.dyld_private_sym_index = sym_index;

    self.addAtomToSection(atom_index);
}

fn createStubHelperPreambleAtom(self: *MachO) !void {
    if (self.dyld_stub_binder_index == null) return;

    const cpu_arch = self.options.cpu_arch.?;
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
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_type = macho.N_SECT;

    const sect_id = self.getSectionByName("__TEXT", "__stub_helper") orelse
        try self.initSection("__TEXT", "__stub_helper", .{
        .flags = macho.S_REGULAR |
            macho.S_ATTR_PURE_INSTRUCTIONS |
            macho.S_ATTR_SOME_INSTRUCTIONS,
    });
    sym.n_sect = sect_id + 1;

    self.stub_helper_preamble_sym_index = sym_index;

    self.addAtomToSection(atom_index);
}

fn writeStubHelperPreambleCode(self: *MachO, writer: anytype) !void {
    const cpu_arch = self.options.cpu_arch.?;
    const source_addr = blk: {
        const sym = self.getSymbol(.{ .sym_index = self.stub_helper_preamble_sym_index.? });
        break :blk sym.n_value;
    };
    const dyld_private_addr = blk: {
        const sym = self.getSymbol(.{ .sym_index = self.dyld_private_sym_index.? });
        break :blk sym.n_value;
    };
    const dyld_stub_binder_got_addr = blk: {
        const index = self.got_table.get(.{ .sym_index = self.dyld_stub_binder_index.? }).?;
        const entry = self.got_entries.items[index];
        break :blk entry.getAtomSymbol(self).n_value;
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
    const cpu_arch = self.options.cpu_arch.?;
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
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_sect = macho.N_SECT;

    const sect_id = self.getSectionByName("__TEXT", "__stub_helper").?;
    sym.n_sect = sect_id + 1;

    self.addAtomToSection(atom_index);

    return atom_index;
}

fn writeStubHelperCode(self: *MachO, atom_index: AtomIndex, writer: anytype) !void {
    const cpu_arch = self.options.cpu_arch.?;
    const source_addr = blk: {
        const atom = self.getAtom(atom_index);
        const sym = self.getSymbol(atom.getSymbolWithLoc());
        break :blk sym.n_value;
    };
    const target_addr = blk: {
        const sym = self.getSymbol(.{ .sym_index = self.stub_helper_preamble_sym_index.? });
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
    const sym_index = try self.allocateSymbol();
    const atom_index = try self.createEmptyAtom(sym_index, @sizeOf(u64), 3);
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_type = macho.N_SECT;

    const sect_id = self.getSectionByName("__DATA", "__la_symbol_ptr") orelse
        try self.initSection("__DATA", "__la_symbol_ptr", .{
        .flags = macho.S_LAZY_SYMBOL_POINTERS,
    });
    sym.n_sect = sect_id + 1;

    self.addAtomToSection(atom_index);

    return atom_index;
}

fn writeLazyPointer(self: *MachO, stub_helper_index: u32, writer: anytype) !void {
    const target_addr = blk: {
        const sect_id = self.getSectionByName("__TEXT", "__stub_helper").?;
        var atom_index = self.sections.items(.first_atom_index)[sect_id];
        var count: u32 = 0;
        while (count < stub_helper_index + 1) : (count += 1) {
            const atom = self.getAtom(atom_index);
            if (atom.next_index) |next_index| {
                atom_index = next_index;
            }
        }
        const atom = self.getAtom(atom_index);
        const sym = self.getSymbol(atom.getSymbolWithLoc());
        break :blk sym.n_value;
    };
    try writer.writeIntLittle(u64, target_addr);
}

pub fn createStubAtom(self: *MachO) !AtomIndex {
    const cpu_arch = self.options.cpu_arch.?;
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
    const sym = self.getSymbolPtr(.{ .sym_index = sym_index });
    sym.n_type = macho.N_SECT;

    const sect_id = self.getSectionByName("__TEXT", "__stubs") orelse
        try self.initSection("__TEXT", "__stubs", .{
        .flags = macho.S_SYMBOL_STUBS |
            macho.S_ATTR_PURE_INSTRUCTIONS |
            macho.S_ATTR_SOME_INSTRUCTIONS,
        .reserved2 = stub_size,
    });
    sym.n_sect = sect_id + 1;

    self.addAtomToSection(atom_index);

    return atom_index;
}

fn writeStubCode(self: *MachO, atom_index: AtomIndex, stub_index: u32, writer: anytype) !void {
    const cpu_arch = self.options.cpu_arch.?;
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

    for (self.globals.items) |global| {
        const sym = self.getSymbolPtr(global);
        if (!sym.tentative()) continue;
        if (sym.n_desc == N_DEAD) continue;

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
        })).? + 1;

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

        self.addAtomToSection(atom_index);

        assert(global.getFile() != null);
        const object = &self.objects.items[global.getFile().?];
        try object.atoms.append(gpa, atom_index);
        object.atom_by_index_table[global.sym_index] = atom_index;
    }
}

fn forceSymbolDefined(self: *MachO, name: []const u8, resolver: *SymbolResolver) !void {
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(self.base.allocator, name);
    sym.n_type = macho.N_UNDF | macho.N_EXT;
    const global_index = try self.addGlobal(sym_loc);
    try resolver.table.putNoClobber(name, global_index);
    try resolver.unresolved.putNoClobber(global_index, {});
}

fn resolveSymbols(self: *MachO, resolver: *SymbolResolver) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // We add the specified entrypoint as the first unresolved symbols so that
    // we search for it in libraries should there be no object files specified
    // on the linker line.
    if (self.options.output_mode == .exe) {
        const entry_name = self.options.entry orelse default_entry_point;
        try self.forceSymbolDefined(entry_name, resolver);
    }

    // Force resolution of any symbols requested by the user.
    for (self.options.force_undefined_symbols.keys()) |sym_name| {
        try self.forceSymbolDefined(sym_name, resolver);
    }

    for (self.objects.items, 0..) |_, object_id| {
        try self.resolveSymbolsInObject(@as(u16, @intCast(object_id)), resolver);
    }

    try self.resolveSymbolsInArchives(resolver);
    self.base.reportWarningsAndErrorsAndExit();
    try self.resolveDyldStubBinder(resolver);
    try self.resolveSymbolsInDylibs(resolver);
    try self.createMhExecuteHeaderSymbol(resolver);
    try self.createDsoHandleSymbol(resolver);
    try self.resolveSymbolsAtLoading(resolver);
}

fn resolveSymbolsInObject(self: *MachO, object_id: u16, resolver: *SymbolResolver) !void {
    const object = &self.objects.items[object_id];
    const in_symtab = object.in_symtab orelse return;

    log.debug("resolving symbols in '{s}'", .{object.name});

    var sym_index: u32 = 0;
    while (sym_index < in_symtab.len) : (sym_index += 1) {
        const sym = &object.symtab[sym_index];
        const sym_name = object.getSymbolName(sym_index);

        if (sym.stab()) {
            self.base.fatal("{s}: unhandled symbol type stab:{s}", .{ object.name, sym_name });
        }

        if (sym.indr()) {
            self.base.fatal("{s}: unhandled symbol type indirect:{s}", .{ object.name, sym_name });
        }

        if (sym.abs()) {
            self.base.fatal("{s}: unhandled symbol type absolute:{s}", .{ object.name, sym_name });
        }

        if (sym.sect() and !sym.ext()) {
            log.debug("symbol '{s}' local to object {s}; skipping...", .{
                sym_name,
                object.name,
            });
            continue;
        }

        const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = object_id + 1 };

        const global_index = resolver.table.get(sym_name) orelse {
            const global_index = try self.addGlobal(sym_loc);
            try resolver.table.putNoClobber(sym_name, global_index);
            if (sym.undf() and !sym.tentative()) {
                try resolver.unresolved.putNoClobber(global_index, {});
            }
            continue;
        };
        const global = &self.globals.items[global_index];
        const global_sym = self.getSymbol(global.*);

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
            const nnotes = if (global.getFile() == null) @as(usize, 1) else 2;
            const err = try self.base.addErrorWithNotes(nnotes);
            try err.addMsg("symbol {s} defined multiple times", .{sym_name});
            if (global.getFile()) |file| {
                try err.addNote("first definition in {s}", .{self.objects.items[file].name});
            }
            try err.addNote("next definition in {s}", .{self.objects.items[object_id].name});
        }

        const update_global = blk: {
            if (global_is_strong) break :blk false;
            if (sym_is_weak and global_is_weak) break :blk false;
            if (sym.tentative() and global_sym.tentative()) {
                if (global_sym.n_value >= sym.n_value) break :blk false;
            }
            if (sym.undf() and !sym.tentative()) break :blk false;
            break :blk true;
        };

        if (update_global) {
            if (global.getFile()) |file| {
                const global_object = &self.objects.items[file];
                global_object.globals_lookup[global.sym_index] = global_index;
            }
            _ = resolver.unresolved.swapRemove(resolver.table.get(sym_name).?);
            global.* = sym_loc;
        } else {
            object.globals_lookup[sym_index] = global_index;
        }
    }
}

fn resolveSymbolsInArchives(self: *MachO, resolver: *SymbolResolver) !void {
    if (self.archives.items.len == 0) return;

    const gpa = self.base.allocator;
    var next_sym: usize = 0;
    loop: while (next_sym < resolver.unresolved.count()) {
        const global = self.globals.items[resolver.unresolved.keys()[next_sym]];
        const sym_name = self.getSymbolName(global);

        for (self.archives.items) |archive| {
            // Check if the entry exists in a static archive.
            const offsets = archive.toc.get(sym_name) orelse {
                // No hit.
                continue;
            };
            assert(offsets.items.len > 0);

            const object_id = @as(u16, @intCast(self.objects.items.len));
            const object = try archive.parseObject(gpa, offsets.items[0]);
            try self.objects.append(gpa, object);
            try self.resolveSymbolsInObject(object_id, resolver);

            continue :loop;
        }

        next_sym += 1;
    }
}

fn resolveSymbolsInDylibs(self: *MachO, resolver: *SymbolResolver) !void {
    if (self.dylibs.items.len == 0) return;

    var next_sym: usize = 0;
    loop: while (next_sym < resolver.unresolved.count()) {
        const global_index = resolver.unresolved.keys()[next_sym];
        const global = self.globals.items[global_index];
        const sym = self.getSymbolPtr(global);
        const sym_name = self.getSymbolName(global);

        for (self.dylibs.items, 0..) |dylib, id| {
            if (!dylib.symbols.contains(sym_name)) continue;

            const dylib_id = @as(u16, @intCast(id));
            if (!self.referenced_dylibs.contains(dylib_id)) {
                try self.referenced_dylibs.putNoClobber(self.base.allocator, dylib_id, {});
            }

            const ordinal = self.referenced_dylibs.getIndex(dylib_id) orelse unreachable;
            sym.n_type |= macho.N_EXT;
            sym.n_desc = @as(u16, @intCast(ordinal + 1)) * macho.N_SYMBOL_RESOLVER;

            if (dylib.weak) {
                sym.n_desc |= macho.N_WEAK_REF;
            }

            assert(resolver.unresolved.swapRemove(global_index));
            continue :loop;
        }

        next_sym += 1;
    }
}

fn resolveSymbolsAtLoading(self: *MachO, resolver: *SymbolResolver) !void {
    var next_sym: usize = 0;
    while (next_sym < resolver.unresolved.count()) {
        const global_index = resolver.unresolved.keys()[next_sym];
        const global = self.globals.items[global_index];
        const sym = self.getSymbolPtr(global);

        if (sym.discarded()) {
            sym.* = .{
                .n_strx = 0,
                .n_type = macho.N_UNDF,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            _ = resolver.unresolved.swapRemove(global_index);
            continue;
        } else if (self.options.allow_undef) {
            const n_desc = @as(
                u16,
                @bitCast(macho.BIND_SPECIAL_DYLIB_FLAT_LOOKUP * @as(i16, @intCast(macho.N_SYMBOL_RESOLVER))),
            );
            sym.n_type = macho.N_EXT;
            sym.n_desc = n_desc;
            _ = resolver.unresolved.swapRemove(global_index);
            continue;
        }

        next_sym += 1;
    }
}

fn reportUndefs(self: *MachO, resolver: *const SymbolResolver) !void {
    for (resolver.unresolved.keys()) |global_index| {
        const global = self.globals.items[global_index];
        const sym_name = self.getSymbolName(global);

        const nnotes: usize = if (global.getFile() == null) @as(usize, 0) else 1;
        const err = try self.base.addErrorWithNotes(nnotes);
        try err.addMsg("undefined symbol: {s}", .{sym_name});

        if (global.getFile()) |file| {
            try err.addNote("referenced in {s}", .{self.objects.items[file].name});
        }
    }
}

fn createMhExecuteHeaderSymbol(self: *MachO, resolver: *SymbolResolver) !void {
    if (self.options.output_mode != .exe) return;
    if (resolver.table.get("__mh_execute_header")) |global_index| {
        const global = self.globals.items[global_index];
        const sym = self.getSymbol(global);
        self.mh_execute_header_index = global_index;
        if (!sym.undf() and !(sym.pext() or sym.weakDef())) return;
    }

    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(gpa, "__mh_execute_header");
    sym.n_type = macho.N_SECT | macho.N_EXT;
    sym.n_desc = macho.REFERENCED_DYNAMICALLY;

    if (resolver.table.get("__mh_execute_header")) |global_index| {
        const global = &self.globals.items[global_index];
        const global_object = &self.objects.items[global.getFile().?];
        global_object.globals_lookup[global.sym_index] = global_index;
        global.* = sym_loc;
        self.mh_execute_header_index = global_index;
    } else {
        self.mh_execute_header_index = try self.addGlobal(sym_loc);
    }
}

fn createDsoHandleSymbol(self: *MachO, resolver: *SymbolResolver) !void {
    const global_index = resolver.table.get("___dso_handle") orelse return;
    const global = &self.globals.items[global_index];
    self.dso_handle_index = global_index;
    if (!self.getSymbol(global.*).undf()) return;

    const gpa = self.base.allocator;
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(gpa, "___dso_handle");
    sym.n_type = macho.N_SECT | macho.N_EXT;
    sym.n_desc = macho.N_WEAK_DEF;

    const global_object = &self.objects.items[global.getFile().?];
    global_object.globals_lookup[global.sym_index] = global_index;
    _ = resolver.unresolved.swapRemove(resolver.table.get("___dso_handle").?);
    global.* = sym_loc;
}

fn resolveDyldStubBinder(self: *MachO, resolver: *SymbolResolver) !void {
    if (self.dyld_stub_binder_index != null) return;
    if (resolver.unresolved.count() == 0) return; // no need for a stub binder if we don't have any imports

    const gpa = self.base.allocator;
    const sym_name = "dyld_stub_binder";
    const sym_index = try self.allocateSymbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index };
    const sym = self.getSymbolPtr(sym_loc);
    sym.n_strx = try self.strtab.insert(gpa, sym_name);
    sym.n_type = macho.N_UNDF;

    const global = SymbolWithLoc{ .sym_index = sym_index };
    try self.globals.append(gpa, global);

    for (self.dylibs.items, 0..) |dylib, id| {
        if (!dylib.symbols.contains(sym_name)) continue;

        const dylib_id = @as(u16, @intCast(id));
        if (!self.referenced_dylibs.contains(dylib_id)) {
            try self.referenced_dylibs.putNoClobber(gpa, dylib_id, {});
        }

        const ordinal = self.referenced_dylibs.getIndex(dylib_id) orelse unreachable;
        sym.n_type |= macho.N_EXT;
        sym.n_desc = @as(u16, @intCast(ordinal + 1)) * macho.N_SYMBOL_RESOLVER;
        self.dyld_stub_binder_index = sym_index;

        break;
    }

    if (self.dyld_stub_binder_index == null) {
        self.base.fatal("undefined reference to symbol '{s}'", .{sym_name});
    }
}

pub fn deinit(self: *MachO) void {
    const gpa = self.base.allocator;

    self.tlv_ptr_entries.deinit(gpa);
    self.tlv_ptr_table.deinit(gpa);
    self.got_entries.deinit(gpa);
    self.got_table.deinit(gpa);
    self.stubs.deinit(gpa);
    self.stubs_table.deinit(gpa);
    self.thunk_table.deinit(gpa);

    for (self.thunks.items) |*thunk| {
        thunk.deinit(gpa);
    }
    self.thunks.deinit(gpa);

    self.strtab.deinit(gpa);
    self.locals.deinit(gpa);
    self.globals.deinit(gpa);

    for (self.objects.items) |*object| {
        object.deinit(gpa);
    }
    self.objects.deinit(gpa);
    for (self.archives.items) |*archive| {
        archive.file.close();
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
    self.atoms.deinit(gpa);
}

fn createSegments(self: *MachO) !void {
    const pagezero_vmsize = self.options.pagezero_size orelse default_pagezero_vmsize;
    const aligned_pagezero_vmsize = mem.alignBackward(u64, pagezero_vmsize, self.getPageSize());
    if (self.options.output_mode != .lib and aligned_pagezero_vmsize > 0) {
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

    // __TEXT segment is non-optional
    {
        const protection = getSegmentMemoryProtection("__TEXT");
        try self.segments.append(self.base.allocator, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString("__TEXT"),
            .maxprot = protection,
            .initprot = protection,
        });
    }

    for (self.sections.items(.header), 0..) |header, sect_id| {
        if (header.size == 0) continue; // empty section

        const segname = header.segName();
        const segment_id = self.getSegmentByName(segname) orelse blk: {
            log.debug("creating segment '{s}'", .{segname});
            const segment_id = @as(u8, @intCast(self.segments.items.len));
            const protection = getSegmentMemoryProtection(segname);
            try self.segments.append(self.base.allocator, .{
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
        self.sections.items(.segment_index)[sect_id] = segment_id;
    }

    // __LINKEDIT always comes last
    {
        const protection = getSegmentMemoryProtection("__LINKEDIT");
        try self.segments.append(self.base.allocator, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = makeStaticString("__LINKEDIT"),
            .maxprot = protection,
            .initprot = protection,
        });
    }
}

pub fn allocateSymbol(self: *MachO) !u32 {
    try self.locals.ensureUnusedCapacity(self.base.allocator, 1);
    log.debug("  (allocating symbol index {d})", .{self.locals.items.len});
    const index = @as(u32, @intCast(self.locals.items.len));
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

fn addGlobal(self: *MachO, sym_loc: SymbolWithLoc) !u32 {
    const global_index = @as(u32, @intCast(self.globals.items.len));
    try self.globals.append(self.base.allocator, sym_loc);
    return global_index;
}

fn allocateSpecialSymbols(self: *MachO) !void {
    for (&[_]?u32{
        self.dso_handle_index,
        self.mh_execute_header_index,
    }) |maybe_index| {
        const global_index = maybe_index orelse continue;
        const global = self.globals.items[global_index];
        if (global.getFile() != null) continue;
        const name = self.getSymbolName(global);
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

fn splitIntoAtoms(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items, 0..) |*object, object_id| {
        try object.splitIntoAtoms(self, @as(u31, @intCast(object_id)));
    }
}

fn writeAtoms(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const slice = self.sections.slice();

    for (slice.items(.first_atom_index), 0..) |first_atom_index, sect_id| {
        const header = slice.items(.header)[sect_id];
        var atom_index = first_atom_index;

        if (atom_index == 0) continue;
        if (header.isZerofill()) continue;

        var buffer = std.ArrayList(u8).init(gpa);
        defer buffer.deinit();
        try buffer.ensureTotalCapacity(math.cast(usize, header.size) orelse return error.Overflow);

        log.debug("writing atoms in {s},{s}", .{ header.segName(), header.sectName() });

        var count: u32 = 0;
        while (true) : (count += 1) {
            const atom = self.getAtom(atom_index);
            const this_sym = self.getSymbol(atom.getSymbolWithLoc());
            const padding_size: usize = if (atom.next_index) |next_index| blk: {
                const next_sym = self.getSymbol(self.getAtom(next_index).getSymbolWithLoc());
                const size = next_sym.n_value - (this_sym.n_value + atom.size);
                break :blk math.cast(usize, size) orelse return error.Overflow;
            } else 0;

            log.debug("  (adding ATOM(%{d}, '{s}') from object({?}) to buffer)", .{
                atom.sym_index,
                self.getSymbolName(atom.getSymbolWithLoc()),
                atom.getFile(),
            });
            if (padding_size > 0) {
                log.debug("    (with padding {x})", .{padding_size});
            }

            const offset = buffer.items.len;

            // TODO: move writing synthetic sections into a separate function
            if (atom.getFile() == null) outer: {
                if (self.dyld_private_sym_index) |sym_index| {
                    if (atom.sym_index == sym_index) {
                        buffer.appendSliceAssumeCapacity(&[_]u8{0} ** @sizeOf(u64));
                        break :outer;
                    }
                }
                switch (header.type()) {
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
                        if (header.type() == macho.S_SYMBOL_STUBS) {
                            try self.writeStubCode(atom_index, count, buffer.writer());
                        } else if (mem.eql(u8, header.sectName(), "__stub_helper")) {
                            try self.writeStubHelperCode(atom_index, buffer.writer());
                        } else if (header.isCode()) {
                            // A thunk
                            try thunks.writeThunkCode(self, atom_index, buffer.writer());
                        } else unreachable;
                    },
                }
            } else {
                const code = Atom.getAtomCode(self, atom_index);
                const relocs = Atom.getAtomRelocs(self, atom_index);
                buffer.appendSliceAssumeCapacity(code);
                try Atom.resolveRelocs(
                    self,
                    atom_index,
                    buffer.items[offset..][0..atom.size],
                    relocs,
                );
            }

            var i: usize = 0;
            while (i < padding_size) : (i += 1) {
                // TODO with NOPs
                buffer.appendAssumeCapacity(0);
            }

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else {
                assert(buffer.items.len == header.size);
                log.debug("  (writing at file offset 0x{x})", .{header.offset});
                try self.base.file.pwriteAll(buffer.items, header.offset);
                break;
            }
        }
    }
}

fn pruneAndSortSections(self: *MachO) !void {
    const gpa = self.base.allocator;

    const SortSection = struct {
        pub fn lessThan(_: void, lhs: Section, rhs: Section) bool {
            return getSectionPrecedence(lhs.header) < getSectionPrecedence(rhs.header);
        }
    };

    const slice = self.sections.slice();
    var sections = std.ArrayList(Section).init(gpa);
    defer sections.deinit();
    try sections.ensureTotalCapacity(slice.len);

    {
        var i: u8 = 0;
        while (i < slice.len) : (i += 1) {
            const section = self.sections.get(i);
            log.debug("section {s},{s} {d}", .{
                section.header.segName(),
                section.header.sectName(),
                section.first_atom_index,
            });
            if (section.header.size == 0) {
                log.debug("pruning section {s},{s}", .{
                    section.header.segName(),
                    section.header.sectName(),
                });
                continue;
            }
            sections.appendAssumeCapacity(section);
        }
    }

    mem.sort(Section, sections.items, {}, SortSection.lessThan);

    self.sections.shrinkRetainingCapacity(0);
    for (sections.items) |out| {
        self.sections.appendAssumeCapacity(out);
    }
}

fn calcSectionSizes(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const slice = self.sections.slice();
    for (slice.items(.header), 0..) |*header, sect_id| {
        if (header.size == 0) continue;
        if (self.requiresThunks()) {
            if (header.isCode() and !(header.type() == macho.S_SYMBOL_STUBS) and !mem.eql(u8, header.sectName(), "__stub_helper")) continue;
        }

        var atom_index = slice.items(.first_atom_index)[sect_id];
        if (atom_index == 0) continue;

        header.size = 0;
        header.@"align" = 0;

        while (true) {
            const atom = self.getAtom(atom_index);
            const atom_alignment = try math.powi(u32, 2, atom.alignment);
            const atom_offset = mem.alignForward(u64, header.size, atom_alignment);
            const padding = atom_offset - header.size;

            const sym = self.getSymbolPtr(atom.getSymbolWithLoc());
            sym.n_value = atom_offset;

            header.size += padding + atom.size;
            header.@"align" = @max(header.@"align", atom.alignment);

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    if (self.requiresThunks()) {
        for (slice.items(.header), 0..) |header, sect_id| {
            if (!header.isCode()) continue;
            if (header.type() == macho.S_SYMBOL_STUBS) continue;
            if (mem.eql(u8, header.sectName(), "__stub_helper")) continue;

            // Create jump/branch range extenders if needed.
            try thunks.createThunks(self, @as(u8, @intCast(sect_id)));
        }
    }

    // Update offsets of all symbols contained within each Atom.
    // We need to do this since our unwind info synthesiser relies on
    // traversing the symbols when synthesising unwind info and DWARF CFI records.
    for (slice.items(.first_atom_index)) |first_atom_index| {
        if (first_atom_index == 0) continue;
        var atom_index = first_atom_index;

        while (true) {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());

            if (atom.getFile() != null) {
                // Update each symbol contained within the atom
                var it = Atom.getInnerSymbolsIterator(self, atom_index);
                while (it.next()) |sym_loc| {
                    const inner_sym = self.getSymbolPtr(sym_loc);
                    inner_sym.n_value = sym.n_value + Atom.calcInnerSymbolOffset(
                        self,
                        atom_index,
                        sym_loc.sym_index,
                    );
                }

                // If there is a section alias, update it now too
                if (Atom.getSectionAlias(self, atom_index)) |sym_loc| {
                    const alias = self.getSymbolPtr(sym_loc);
                    alias.n_value = sym.n_value;
                }
            }

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }
}

fn allocateSegments(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.segments.items, 0..) |*segment, segment_index| {
        const is_text_segment = mem.eql(u8, segment.segName(), "__TEXT");
        const base_size = if (is_text_segment) try load_commands.calcMinHeaderPad(self) else 0;
        try self.allocateSegment(@as(u8, @intCast(segment_index)), base_size);

        // TODO
        // if (is_text_segment) blk: {
        //     const indexes = self.getSectionIndexes(@intCast(u8, segment_index));
        //     if (indexes.start == indexes.end) break :blk;

        //     // Shift all sections to the back to minimize jump size between __TEXT and __DATA segments.
        //     var min_alignment: u32 = 0;
        //     for (self.sections.items(.header)[indexes.start..indexes.end]) |header| {
        //         const alignment = try math.powi(u32, 2, header.@"align");
        //         min_alignment = math.max(min_alignment, alignment);
        //     }

        //     assert(min_alignment > 0);
        //     const last_header = self.sections.items(.header)[indexes.end - 1];
        //     const shift: u32 = shift: {
        //         const diff = segment.filesize - last_header.offset - last_header.size;
        //         const factor = @divTrunc(diff, min_alignment);
        //         break :shift @intCast(u32, factor * min_alignment);
        //     };

        //     if (shift > 0) {
        //         for (self.sections.items(.header)[indexes.start..indexes.end]) |*header| {
        //             header.offset += shift;
        //             header.addr += shift;
        //         }
        //     }
        // }
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
    for (slice.items(.header)[indexes.start..indexes.end], 0..) |*header, sect_id| {
        const alignment = try math.powi(u32, 2, header.@"align");
        const start_aligned = mem.alignForward(u64, start, alignment);
        const n_sect = @as(u8, @intCast(indexes.start + sect_id + 1));

        header.offset = if (header.isZerofill())
            0
        else
            @as(u32, @intCast(segment.fileoff + start_aligned));
        header.addr = segment.vmaddr + start_aligned;

        var atom_index = slice.items(.first_atom_index)[indexes.start + sect_id];
        if (atom_index > 0) {
            log.debug("allocating local symbols in sect({d}, '{s},{s}')", .{
                n_sect,
                header.segName(),
                header.sectName(),
            });

            while (true) {
                const atom = self.getAtom(atom_index);
                const sym = self.getSymbolPtr(atom.getSymbolWithLoc());
                sym.n_value += header.addr;
                sym.n_sect = n_sect;

                log.debug("  ATOM(%{d}, '{s}') @{x}", .{
                    atom.sym_index,
                    self.getSymbolName(atom.getSymbolWithLoc()),
                    sym.n_value,
                });

                if (atom.getFile() != null) {
                    // Update each symbol contained within the atom
                    var it = Atom.getInnerSymbolsIterator(self, atom_index);
                    while (it.next()) |sym_loc| {
                        const inner_sym = self.getSymbolPtr(sym_loc);
                        inner_sym.n_value = sym.n_value + Atom.calcInnerSymbolOffset(
                            self,
                            atom_index,
                            sym_loc.sym_index,
                        );
                        inner_sym.n_sect = n_sect;
                    }

                    // If there is a section alias, update it now too
                    if (Atom.getSectionAlias(self, atom_index)) |sym_loc| {
                        const alias = self.getSymbolPtr(sym_loc);
                        alias.n_value = sym.n_value;
                        alias.n_sect = n_sect;
                    }
                }

                if (atom.next_index) |next_index| {
                    atom_index = next_index;
                } else break;
            }
        }

        start = start_aligned + header.size;

        if (!header.isZerofill()) {
            segment.filesize = start;
        }
        segment.vmsize = start;
    }

    segment.filesize = mem.alignForward(u64, segment.filesize, self.getPageSize());
    segment.vmsize = mem.alignForward(u64, segment.vmsize, self.getPageSize());
}

const InitSectionOpts = struct {
    flags: u32 = macho.S_REGULAR,
    reserved1: u32 = 0,
    reserved2: u32 = 0,
};

pub fn initSection(
    self: *MachO,
    segname: []const u8,
    sectname: []const u8,
    opts: InitSectionOpts,
) !u8 {
    const gpa = self.base.allocator;
    log.debug("creating section '{s},{s}'", .{ segname, sectname });
    const index = @as(u8, @intCast(self.sections.slice().len));
    try self.sections.append(gpa, .{
        .segment_index = undefined, // Segments will be created automatically later down the pipeline.
        .header = .{
            .sectname = makeStaticString(sectname),
            .segname = makeStaticString(segname),
            .flags = opts.flags,
            .reserved1 = opts.reserved1,
            .reserved2 = opts.reserved2,
        },
        .first_atom_index = 0,
        .last_atom_index = 0,
    });
    return index;
}

fn getSegmentPrecedence(segname: []const u8) u4 {
    if (mem.eql(u8, segname, "__PAGEZERO")) return 0x0;
    if (mem.eql(u8, segname, "__TEXT")) return 0x1;
    if (mem.eql(u8, segname, "__DATA_CONST")) return 0x2;
    if (mem.eql(u8, segname, "__DATA")) return 0x3;
    if (mem.eql(u8, segname, "__LINKEDIT")) return 0x5;
    return 0x4;
}

fn getSegmentMemoryProtection(segname: []const u8) macho.vm_prot_t {
    if (mem.eql(u8, segname, "__PAGEZERO")) return macho.PROT.NONE;
    if (mem.eql(u8, segname, "__TEXT")) return macho.PROT.READ | macho.PROT.EXEC;
    if (mem.eql(u8, segname, "__LINKEDIT")) return macho.PROT.READ;
    return macho.PROT.READ | macho.PROT.WRITE;
}

fn getSectionPrecedence(header: macho.section_64) u8 {
    const segment_precedence: u4 = getSegmentPrecedence(header.segName());
    const section_precedence: u4 = blk: {
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
    return (@as(u8, @intCast(segment_precedence)) << 4) + section_precedence;
}

fn writeSegmentHeaders(self: *MachO, writer: anytype) !void {
    for (self.segments.items, 0..) |seg, i| {
        const indexes = self.getSectionIndexes(@as(u8, @intCast(i)));
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
    }
}

fn writeLinkeditSegmentData(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    try self.writeDyldInfoData();
    try self.writeFunctionStarts();
    try self.writeDataInCode();
    try self.writeSymtabs();

    const seg = self.getLinkeditSegmentPtr();
    seg.vmsize = mem.alignForward(u64, seg.filesize, self.getPageSize());
}

fn collectRebaseDataFromContainer(
    self: *MachO,
    sect_id: u8,
    rebase: *Rebase,
    container: anytype,
) !void {
    const slice = self.sections.slice();
    const segment_index = slice.items(.segment_index)[sect_id];
    const seg = self.getSegment(sect_id);

    try rebase.entries.ensureUnusedCapacity(self.base.allocator, container.items.len);

    for (container.items) |entry| {
        const target_sym = entry.getTargetSymbol(self);
        if (target_sym.undf()) continue;

        const atom_sym = entry.getAtomSymbol(self);
        const base_offset = atom_sym.n_value - seg.vmaddr;

        log.debug("    | rebase at {x}", .{atom_sym.n_value});

        rebase.entries.appendAssumeCapacity(.{
            .offset = base_offset,
            .segment_id = segment_index,
        });
    }
}

fn collectRebaseData(self: *MachO, rebase: *Rebase) !void {
    log.debug("collecting rebase data", .{});

    // First, unpack GOT entries
    if (self.getSectionByName("__DATA_CONST", "__got")) |sect_id| {
        try self.collectRebaseDataFromContainer(sect_id, rebase, self.got_entries);
    }

    const gpa = self.base.allocator;
    const slice = self.sections.slice();

    // Next, unpact lazy pointers
    // TODO: save la_ptr in a container so that we can re-use the helper
    if (self.getSectionByName("__DATA", "__la_symbol_ptr")) |sect_id| {
        const segment_index = slice.items(.segment_index)[sect_id];
        const seg = self.getSegment(sect_id);
        var atom_index = slice.items(.first_atom_index)[sect_id];

        try rebase.entries.ensureUnusedCapacity(gpa, self.stubs.items.len);

        while (true) {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());
            const base_offset = sym.n_value - seg.vmaddr;

            log.debug("    | rebase at {x}", .{sym.n_value});

            rebase.entries.appendAssumeCapacity(.{
                .offset = base_offset,
                .segment_id = segment_index,
            });

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    // Finally, unpack the rest.
    for (slice.items(.header), 0..) |header, sect_id| {
        switch (header.type()) {
            macho.S_LITERAL_POINTERS,
            macho.S_REGULAR,
            macho.S_MOD_INIT_FUNC_POINTERS,
            macho.S_MOD_TERM_FUNC_POINTERS,
            => {},
            else => continue,
        }

        const segment_index = slice.items(.segment_index)[sect_id];
        const segment = self.getSegment(@as(u8, @intCast(sect_id)));
        if (segment.maxprot & macho.PROT.WRITE == 0) continue;

        log.debug("{s},{s}", .{ header.segName(), header.sectName() });

        const cpu_arch = self.options.cpu_arch.?;
        var atom_index = slice.items(.first_atom_index)[sect_id];
        if (atom_index == 0) continue;

        while (true) {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());

            const should_rebase = blk: {
                if (self.dyld_private_sym_index) |sym_index| {
                    if (atom.getFile() == null and atom.sym_index == sym_index) break :blk false;
                }
                break :blk !sym.undf();
            };

            if (should_rebase) {
                log.debug("  ATOM({d}, %{d}, '{s}')", .{
                    atom_index,
                    atom.sym_index,
                    self.getSymbolName(atom.getSymbolWithLoc()),
                });

                const code = Atom.getAtomCode(self, atom_index);
                const relocs = Atom.getAtomRelocs(self, atom_index);
                const ctx = Atom.getRelocContext(self, atom_index);

                for (relocs) |rel| {
                    switch (cpu_arch) {
                        .aarch64 => {
                            const rel_type = @as(macho.reloc_type_arm64, @enumFromInt(rel.r_type));
                            if (rel_type != .ARM64_RELOC_UNSIGNED) continue;
                            if (rel.r_length != 3) continue;
                        },
                        .x86_64 => {
                            const rel_type = @as(macho.reloc_type_x86_64, @enumFromInt(rel.r_type));
                            if (rel_type != .X86_64_RELOC_UNSIGNED) continue;
                            if (rel.r_length != 3) continue;
                        },
                        else => unreachable,
                    }
                    const target = Atom.parseRelocTarget(self, .{
                        .object_id = atom.getFile().?,
                        .rel = rel,
                        .code = code,
                        .base_offset = ctx.base_offset,
                        .base_addr = ctx.base_addr,
                    });
                    const target_sym = self.getSymbol(target);
                    if (target_sym.undf()) continue;

                    const base_offset = @as(i32, @intCast(sym.n_value - segment.vmaddr));
                    const rel_offset = rel.r_address - ctx.base_offset;
                    const offset = @as(u64, @intCast(base_offset + rel_offset));
                    log.debug("    | rebase at {x}", .{offset + segment.vmaddr});

                    try rebase.entries.append(gpa, .{
                        .offset = offset,
                        .segment_id = segment_index,
                    });
                }
            }

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    try rebase.finalize(gpa);
}

fn collectBindDataFromContainer(self: *MachO, sect_id: u8, bind: *Bind, container: anytype) !void {
    const slice = self.sections.slice();
    const segment_index = slice.items(.segment_index)[sect_id];
    const seg = self.getSegment(sect_id);

    const gpa = self.base.allocator;
    try bind.entries.ensureUnusedCapacity(gpa, container.items.len);

    for (container.items) |entry| {
        const bind_sym_name = entry.getTargetSymbolName(self);
        const bind_sym = entry.getTargetSymbol(self);
        if (bind_sym.sect()) continue;

        const sym = entry.getAtomSymbol(self);
        const base_offset = sym.n_value - seg.vmaddr;
        const dylib_ordinal = @divTrunc(@as(i16, @bitCast(bind_sym.n_desc)), macho.N_SYMBOL_RESOLVER);
        log.debug("bind at {x}, import('{s}') in dylib({d})", .{
            seg.vmaddr + base_offset,
            bind_sym_name,
            dylib_ordinal,
        });
        if (bind_sym.weakRef()) {
            log.debug("    | marking as weak ref ", .{});
        }
        bind.entries.appendAssumeCapacity(.{
            .target = entry.target,
            .offset = base_offset,
            .segment_id = segment_index,
            .addend = 0,
        });
    }
}

fn collectBindData(self: *MachO, bind: *Bind) !void {
    log.debug("collecting bind data", .{});

    const gpa = self.base.allocator;

    // First, unpack GOT section
    if (self.getSectionByName("__DATA_CONST", "__got")) |sect_id| {
        try self.collectBindDataFromContainer(sect_id, bind, self.got_entries);
    }

    // Next, unpack TLV pointers section
    if (self.getSectionByName("__DATA", "__thread_ptrs")) |sect_id| {
        try self.collectBindDataFromContainer(sect_id, bind, self.tlv_ptr_entries);
    }

    // Finally, unpack the rest.
    const slice = self.sections.slice();
    for (slice.items(.header), 0..) |header, sect_id| {
        switch (header.type()) {
            macho.S_LITERAL_POINTERS,
            macho.S_REGULAR,
            macho.S_MOD_INIT_FUNC_POINTERS,
            macho.S_MOD_TERM_FUNC_POINTERS,
            => {},
            else => continue,
        }

        const segment_index = slice.items(.segment_index)[sect_id];
        const segment = self.getSegment(@as(u8, @intCast(sect_id)));
        if (segment.maxprot & macho.PROT.WRITE == 0) continue;

        log.debug("{s},{s}", .{ header.segName(), header.sectName() });

        const cpu_arch = self.options.cpu_arch.?;
        var atom_index = slice.items(.first_atom_index)[sect_id];
        if (atom_index == 0) continue;

        while (true) {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());

            log.debug("  ATOM({d}, %{d}, '{s}')", .{ atom_index, atom.sym_index, self.getSymbolName(atom.getSymbolWithLoc()) });

            const should_bind = blk: {
                if (self.dyld_private_sym_index) |sym_index| {
                    if (atom.getFile() == null and atom.sym_index == sym_index) break :blk false;
                }
                break :blk true;
            };

            if (should_bind) {
                const code = Atom.getAtomCode(self, atom_index);
                const relocs = Atom.getAtomRelocs(self, atom_index);
                const ctx = Atom.getRelocContext(self, atom_index);

                for (relocs) |rel| {
                    switch (cpu_arch) {
                        .aarch64 => {
                            const rel_type = @as(macho.reloc_type_arm64, @enumFromInt(rel.r_type));
                            if (rel_type != .ARM64_RELOC_UNSIGNED) continue;
                            if (rel.r_length != 3) continue;
                        },
                        .x86_64 => {
                            const rel_type = @as(macho.reloc_type_x86_64, @enumFromInt(rel.r_type));
                            if (rel_type != .X86_64_RELOC_UNSIGNED) continue;
                            if (rel.r_length != 3) continue;
                        },
                        else => unreachable,
                    }

                    const global = Atom.parseRelocTarget(self, .{
                        .object_id = atom.getFile().?,
                        .rel = rel,
                        .code = code,
                        .base_offset = ctx.base_offset,
                        .base_addr = ctx.base_addr,
                    });
                    const bind_sym_name = self.getSymbolName(global);
                    const bind_sym = self.getSymbol(global);
                    if (!bind_sym.undf()) continue;

                    const base_offset = sym.n_value - segment.vmaddr;
                    const rel_offset = @as(u32, @intCast(rel.r_address - ctx.base_offset));
                    const offset = @as(u64, @intCast(base_offset + rel_offset));
                    const addend = mem.readIntLittle(i64, code[rel_offset..][0..8]);

                    const dylib_ordinal = @divTrunc(@as(i16, @bitCast(bind_sym.n_desc)), macho.N_SYMBOL_RESOLVER);
                    log.debug("bind at {x}, import('{s}') in dylib({d})", .{
                        segment.vmaddr + offset,
                        bind_sym_name,
                        dylib_ordinal,
                    });
                    log.debug("    | with addend {x}", .{addend});
                    if (bind_sym.weakRef()) {
                        log.debug("    | marking as weak ref ", .{});
                    }
                    try bind.entries.append(gpa, .{
                        .target = global,
                        .offset = offset,
                        .segment_id = segment_index,
                        .addend = addend,
                    });
                }
            }
            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    try bind.finalize(gpa, self);
}

fn collectLazyBindData(self: *MachO, lazy_bind: *LazyBind) !void {
    const sect_id = self.getSectionByName("__DATA", "__la_symbol_ptr") orelse return;

    log.debug("collecting lazy bind data", .{});

    const slice = self.sections.slice();
    const segment_index = slice.items(.segment_index)[sect_id];
    const seg = self.getSegment(sect_id);
    var atom_index = slice.items(.first_atom_index)[sect_id];

    // TODO: we actually don't need to store lazy pointer atoms as they are synthetically generated by the linker
    const gpa = self.base.allocator;
    try lazy_bind.entries.ensureUnusedCapacity(gpa, self.stubs.items.len);

    var count: u32 = 0;
    while (true) : (count += 1) {
        const atom = self.getAtom(atom_index);

        log.debug("  ATOM(%{d}, '{s}')", .{ atom.sym_index, self.getSymbolName(atom.getSymbolWithLoc()) });

        const sym = self.getSymbol(atom.getSymbolWithLoc());
        const base_offset = sym.n_value - seg.vmaddr;

        const stub_entry = self.stubs.items[count];
        const bind_sym = stub_entry.getTargetSymbol(self);
        const bind_sym_name = stub_entry.getTargetSymbolName(self);
        const dylib_ordinal = @divTrunc(@as(i16, @bitCast(bind_sym.n_desc)), macho.N_SYMBOL_RESOLVER);
        log.debug("    | lazy bind at {x}, import('{s}') in dylib({d})", .{
            base_offset,
            bind_sym_name,
            dylib_ordinal,
        });
        if (bind_sym.weakRef()) {
            log.debug("    | marking as weak ref ", .{});
        }
        lazy_bind.entries.appendAssumeCapacity(.{
            .offset = base_offset,
            .segment_id = segment_index,
            .target = stub_entry.target,
            .addend = 0,
        });

        if (atom.next_index) |next_index| {
            atom_index = next_index;
        } else break;
    }

    try lazy_bind.finalize(gpa, self);
}

fn collectExportData(self: *MachO, trie: *Trie) !void {
    const gpa = self.base.allocator;

    // TODO handle macho.EXPORT_SYMBOL_FLAGS_REEXPORT and macho.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER.
    log.debug("collecting export data", .{});

    const segment_index = self.getSegmentByName("__TEXT").?;
    const exec_segment = self.segments.items[segment_index];
    const base_address = exec_segment.vmaddr;

    for (self.globals.items) |global| {
        const sym = self.getSymbol(global);
        if (sym.undf()) continue;
        if (sym.n_desc == N_DEAD) continue;

        const sym_name = self.getSymbolName(global);
        log.debug("  (putting '{s}' defined at 0x{x})", .{ sym_name, sym.n_value });
        try trie.put(gpa, .{
            .name = sym_name,
            .vmaddr_offset = sym.n_value - base_address,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }

    try trie.finalize(gpa);
}

fn writeDyldInfoData(self: *MachO) !void {
    const gpa = self.base.allocator;

    var rebase = Rebase{};
    defer rebase.deinit(gpa);
    try self.collectRebaseData(&rebase);

    var bind = Bind{};
    defer bind.deinit(gpa);
    try self.collectBindData(&bind);

    var lazy_bind = LazyBind{};
    defer lazy_bind.deinit(gpa);
    try self.collectLazyBindData(&lazy_bind);

    var trie = Trie{};
    defer trie.deinit(gpa);
    try trie.init(gpa);
    try self.collectExportData(&trie);

    const link_seg = self.getLinkeditSegmentPtr();
    assert(mem.isAlignedGeneric(u64, link_seg.fileoff, @alignOf(u64)));
    const rebase_off = link_seg.fileoff;
    const rebase_size = rebase.size();
    const rebase_size_aligned = mem.alignForward(u64, rebase_size, @alignOf(u64));
    log.debug("writing rebase info from 0x{x} to 0x{x}", .{ rebase_off, rebase_off + rebase_size_aligned });

    const bind_off = rebase_off + rebase_size_aligned;
    const bind_size = bind.size();
    const bind_size_aligned = mem.alignForward(u64, bind_size, @alignOf(u64));
    log.debug("writing bind info from 0x{x} to 0x{x}", .{ bind_off, bind_off + bind_size_aligned });

    const lazy_bind_off = bind_off + bind_size_aligned;
    const lazy_bind_size = lazy_bind.size();
    const lazy_bind_size_aligned = mem.alignForward(u64, lazy_bind_size, @alignOf(u64));
    log.debug("writing lazy bind info from 0x{x} to 0x{x}", .{
        lazy_bind_off,
        lazy_bind_off + lazy_bind_size_aligned,
    });

    const export_off = lazy_bind_off + lazy_bind_size_aligned;
    const export_size = trie.size;
    const export_size_aligned = mem.alignForward(u64, export_size, @alignOf(u64));
    log.debug("writing export trie from 0x{x} to 0x{x}", .{ export_off, export_off + export_size_aligned });

    const needed_size = export_off + export_size_aligned - rebase_off;
    link_seg.filesize = needed_size;
    assert(mem.isAlignedGeneric(u64, link_seg.fileoff + link_seg.filesize, @alignOf(u64)));

    var buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);
    @memset(buffer, 0);

    var stream = std.io.fixedBufferStream(buffer);
    const writer = stream.writer();

    try rebase.write(writer);
    try stream.seekTo(bind_off - rebase_off);

    try bind.write(writer);
    try stream.seekTo(lazy_bind_off - rebase_off);

    try lazy_bind.write(writer);
    try stream.seekTo(export_off - rebase_off);

    _ = try trie.write(writer);

    log.debug("writing dyld info from 0x{x} to 0x{x}", .{
        rebase_off,
        rebase_off + needed_size,
    });

    try self.base.file.pwriteAll(buffer, rebase_off);
    try self.populateLazyBindOffsetsInStubHelper(lazy_bind);

    self.dyld_info_cmd.rebase_off = @as(u32, @intCast(rebase_off));
    self.dyld_info_cmd.rebase_size = @as(u32, @intCast(rebase_size_aligned));
    self.dyld_info_cmd.bind_off = @as(u32, @intCast(bind_off));
    self.dyld_info_cmd.bind_size = @as(u32, @intCast(bind_size_aligned));
    self.dyld_info_cmd.lazy_bind_off = @as(u32, @intCast(lazy_bind_off));
    self.dyld_info_cmd.lazy_bind_size = @as(u32, @intCast(lazy_bind_size_aligned));
    self.dyld_info_cmd.export_off = @as(u32, @intCast(export_off));
    self.dyld_info_cmd.export_size = @as(u32, @intCast(export_size_aligned));
}

fn populateLazyBindOffsetsInStubHelper(self: *MachO, lazy_bind: LazyBind) !void {
    if (lazy_bind.size() == 0) return;

    const stub_helper_section_index = self.getSectionByName("__TEXT", "__stub_helper").?;
    assert(self.stub_helper_preamble_sym_index != null);

    const section = self.sections.get(stub_helper_section_index);
    const stub_offset: u4 = switch (self.options.cpu_arch.?) {
        .x86_64 => 1,
        .aarch64 => 2 * @sizeOf(u32),
        else => unreachable,
    };
    const header = section.header;
    var atom_index = section.first_atom_index;
    atom_index = self.getAtom(atom_index).next_index.?; // skip preamble

    var index: usize = 0;
    while (true) {
        const atom = self.getAtom(atom_index);
        const atom_sym = self.getSymbol(atom.getSymbolWithLoc());
        const file_offset = header.offset + atom_sym.n_value - header.addr + stub_offset;
        const bind_offset = lazy_bind.offsets.items[index];

        log.debug("writing lazy bind offset 0x{x} in stub helper at 0x{x}", .{ bind_offset, file_offset });

        try self.base.file.pwriteAll(mem.asBytes(&bind_offset), file_offset);

        if (atom.next_index) |next_index| {
            atom_index = next_index;
            index += 1;
        } else break;
    }
}

const asc_u64 = std.sort.asc(u64);

fn addSymbolToFunctionStarts(self: *MachO, sym_loc: SymbolWithLoc, addresses: *std.ArrayList(u64)) !void {
    const sym = self.getSymbol(sym_loc);
    if (sym.n_strx == 0) return;
    if (sym.n_desc == N_DEAD) return;
    if (self.symbolIsTemp(sym_loc)) return;
    try addresses.append(sym.n_value);
}

fn writeFunctionStarts(self: *MachO) !void {
    const text_seg_index = self.getSegmentByName("__TEXT") orelse return;
    const text_seg = self.segments.items[text_seg_index];

    const gpa = self.base.allocator;

    // We need to sort by address first
    var addresses = std.ArrayList(u64).init(gpa);
    defer addresses.deinit();

    for (self.objects.items) |object| {
        for (object.exec_atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index);
            const sym_loc = atom.getSymbolWithLoc();
            try self.addSymbolToFunctionStarts(sym_loc, &addresses);

            var it = Atom.getInnerSymbolsIterator(self, atom_index);
            while (it.next()) |inner_sym_loc| {
                try self.addSymbolToFunctionStarts(inner_sym_loc, &addresses);
            }
        }
    }

    mem.sort(u64, addresses.items, {}, asc_u64);

    var offsets = std.ArrayList(u32).init(gpa);
    defer offsets.deinit();
    try offsets.ensureTotalCapacityPrecise(addresses.items.len);

    var last_off: u32 = 0;
    for (addresses.items) |addr| {
        const offset = @as(u32, @intCast(addr - text_seg.vmaddr));
        const diff = offset - last_off;

        if (diff == 0) continue;

        offsets.appendAssumeCapacity(diff);
        last_off = offset;
    }

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const max_size = @as(usize, @intCast(offsets.items.len * @sizeOf(u64)));
    try buffer.ensureTotalCapacity(max_size);

    for (offsets.items) |offset| {
        try std.leb.writeULEB128(buffer.writer(), offset);
    }

    const link_seg = self.getLinkeditSegmentPtr();
    const offset = link_seg.fileoff + link_seg.filesize;
    assert(mem.isAlignedGeneric(u64, offset, @alignOf(u64)));
    const needed_size = buffer.items.len;
    const needed_size_aligned = mem.alignForward(u64, needed_size, @alignOf(u64));
    const padding = needed_size_aligned - needed_size;
    if (padding > 0) {
        try buffer.ensureUnusedCapacity(padding);
        buffer.appendNTimesAssumeCapacity(0, padding);
    }
    link_seg.filesize = offset + needed_size_aligned - link_seg.fileoff;

    log.debug("writing function starts info from 0x{x} to 0x{x}", .{ offset, offset + needed_size_aligned });

    try self.base.file.pwriteAll(buffer.items, offset);

    self.function_starts_cmd.dataoff = @as(u32, @intCast(offset));
    self.function_starts_cmd.datasize = @as(u32, @intCast(needed_size_aligned));
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

    const start = Zld.linearSearch(macho.data_in_code_entry, dices, Predicate{ .addr = start_addr });
    const end = Zld.linearSearch(macho.data_in_code_entry, dices[start..], Predicate{ .addr = end_addr }) + start;

    return dices[start..end];
}

fn writeDataInCode(self: *MachO) !void {
    var out_dice = std.ArrayList(macho.data_in_code_entry).init(self.base.allocator);
    defer out_dice.deinit();

    const text_sect_id = self.getSectionByName("__TEXT", "__text") orelse return;
    const text_sect_header = self.sections.items(.header)[text_sect_id];

    for (self.objects.items) |object| {
        if (!object.hasDataInCode()) continue;
        const dice = object.data_in_code.items;
        try out_dice.ensureUnusedCapacity(dice.len);

        for (object.exec_atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index);
            const sym = self.getSymbol(atom.getSymbolWithLoc());
            if (sym.n_desc == N_DEAD) continue;

            const source_addr = if (object.getSourceSymbol(atom.sym_index)) |source_sym|
                source_sym.n_value
            else blk: {
                const nbase = @as(u32, @intCast(object.in_symtab.?.len));
                const source_sect_id = @as(u8, @intCast(atom.sym_index - nbase));
                break :blk object.getSourceSection(source_sect_id).addr;
            };
            const filtered_dice = filterDataInCode(dice, source_addr, source_addr + atom.size);
            const base = math.cast(u32, sym.n_value - text_sect_header.addr + text_sect_header.offset) orelse
                return error.Overflow;

            for (filtered_dice) |single| {
                const offset = math.cast(u32, single.offset - source_addr + base) orelse
                    return error.Overflow;
                out_dice.appendAssumeCapacity(.{
                    .offset = offset,
                    .length = single.length,
                    .kind = single.kind,
                });
            }
        }
    }

    const seg = self.getLinkeditSegmentPtr();
    const offset = seg.fileoff + seg.filesize;
    assert(mem.isAlignedGeneric(u64, offset, @alignOf(u64)));
    const needed_size = out_dice.items.len * @sizeOf(macho.data_in_code_entry);
    const needed_size_aligned = mem.alignForward(u64, needed_size, @alignOf(u64));
    seg.filesize = offset + needed_size_aligned - seg.fileoff;

    const buffer = try self.base.allocator.alloc(u8, needed_size_aligned);
    defer self.base.allocator.free(buffer);
    @memset(buffer, 0);
    @memcpy(buffer, mem.sliceAsBytes(out_dice.items));

    log.debug("writing data-in-code from 0x{x} to 0x{x}", .{ offset, offset + needed_size_aligned });

    try self.base.file.pwriteAll(buffer, offset);

    self.data_in_code_cmd.dataoff = @as(u32, @intCast(offset));
    self.data_in_code_cmd.datasize = @as(u32, @intCast(needed_size_aligned));
}

fn writeSymtabs(self: *MachO) !void {
    var ctx = try self.writeSymtab();
    defer ctx.imports_table.deinit();
    try self.writeDysymtab(ctx);
    try self.writeStrtab();
}

fn addLocalToSymtab(self: *MachO, sym_loc: SymbolWithLoc, locals: *std.ArrayList(macho.nlist_64)) !void {
    const sym = self.getSymbol(sym_loc);
    if (sym.n_strx == 0) return; // no name, skip
    if (sym.n_desc == N_DEAD) return; // garbage-collected, skip
    if (sym.ext()) return; // an export lands in its own symtab section, skip
    if (self.symbolIsTemp(sym_loc)) return; // local temp symbol, skip

    var out_sym = sym;
    out_sym.n_strx = try self.strtab.insert(self.base.allocator, self.getSymbolName(sym_loc));
    try locals.append(out_sym);
}

fn writeSymtab(self: *MachO) !SymtabCtx {
    const gpa = self.base.allocator;

    var locals = std.ArrayList(macho.nlist_64).init(gpa);
    defer locals.deinit();

    for (self.objects.items) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.getAtom(atom_index);
            const sym_loc = atom.getSymbolWithLoc();
            try self.addLocalToSymtab(sym_loc, &locals);

            var it = Atom.getInnerSymbolsIterator(self, atom_index);
            while (it.next()) |inner_sym_loc| {
                try self.addLocalToSymtab(inner_sym_loc, &locals);
            }
        }
    }

    var exports = std.ArrayList(macho.nlist_64).init(gpa);
    defer exports.deinit();

    for (self.globals.items) |global| {
        const sym = self.getSymbol(global);
        if (sym.undf()) continue; // import, skip
        if (sym.n_desc == N_DEAD) continue;

        var out_sym = sym;
        out_sym.n_strx = try self.strtab.insert(gpa, self.getSymbolName(global));
        try exports.append(out_sym);
    }

    var imports = std.ArrayList(macho.nlist_64).init(gpa);
    defer imports.deinit();

    var imports_table = std.AutoHashMap(SymbolWithLoc, u32).init(gpa);

    for (self.globals.items) |global| {
        const sym = self.getSymbol(global);
        if (!sym.undf()) continue; // not an import, skip
        if (sym.n_desc == N_DEAD) continue;

        const new_index = @as(u32, @intCast(imports.items.len));
        var out_sym = sym;
        out_sym.n_strx = try self.strtab.insert(gpa, self.getSymbolName(global));
        try imports.append(out_sym);
        try imports_table.putNoClobber(global, new_index);
    }

    // We generate stabs last in order to ensure that the strtab always has debug info
    // strings trailing
    if (!self.options.strip) {
        for (self.objects.items) |object| {
            try self.generateSymbolStabs(object, &locals);
        }
    }

    const nlocals = @as(u32, @intCast(locals.items.len));
    const nexports = @as(u32, @intCast(exports.items.len));
    const nimports = @as(u32, @intCast(imports.items.len));
    const nsyms = nlocals + nexports + nimports;

    const seg = self.getLinkeditSegmentPtr();
    const offset = seg.fileoff + seg.filesize;
    assert(mem.isAlignedGeneric(u64, offset, @alignOf(u64)));
    const needed_size = nsyms * @sizeOf(macho.nlist_64);
    seg.filesize = offset + needed_size - seg.fileoff;
    assert(mem.isAlignedGeneric(u64, seg.fileoff + seg.filesize, @alignOf(u64)));

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(needed_size);
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(locals.items));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(exports.items));
    buffer.appendSliceAssumeCapacity(mem.sliceAsBytes(imports.items));

    log.debug("writing symtab from 0x{x} to 0x{x}", .{ offset, offset + needed_size });
    try self.base.file.pwriteAll(buffer.items, offset);

    self.symtab_cmd.symoff = @as(u32, @intCast(offset));
    self.symtab_cmd.nsyms = nsyms;

    return SymtabCtx{
        .nlocalsym = nlocals,
        .nextdefsym = nexports,
        .nundefsym = nimports,
        .imports_table = imports_table,
    };
}

fn writeStrtab(self: *MachO) !void {
    const seg = self.getLinkeditSegmentPtr();
    const offset = seg.fileoff + seg.filesize;
    assert(mem.isAlignedGeneric(u64, offset, @alignOf(u64)));
    const needed_size = self.strtab.buffer.items.len;
    const needed_size_aligned = mem.alignForward(u64, needed_size, @alignOf(u64));
    seg.filesize = offset + needed_size_aligned - seg.fileoff;

    log.debug("writing string table from 0x{x} to 0x{x}", .{ offset, offset + needed_size_aligned });

    const buffer = try self.base.allocator.alloc(u8, needed_size_aligned);
    defer self.base.allocator.free(buffer);
    @memset(buffer, 0);
    @memcpy(buffer[0..self.strtab.buffer.items.len], self.strtab.buffer.items);

    try self.base.file.pwriteAll(buffer, offset);

    self.symtab_cmd.stroff = @as(u32, @intCast(offset));
    self.symtab_cmd.strsize = @as(u32, @intCast(needed_size_aligned));
}

const SymtabCtx = struct {
    nlocalsym: u32,
    nextdefsym: u32,
    nundefsym: u32,
    imports_table: std.AutoHashMap(SymbolWithLoc, u32),
};

fn writeDysymtab(self: *MachO, ctx: SymtabCtx) !void {
    const gpa = self.base.allocator;
    const nstubs = @as(u32, @intCast(self.stubs.items.len));
    const ngot_entries = @as(u32, @intCast(self.got_entries.items.len));
    const nindirectsyms = nstubs * 2 + ngot_entries;
    const iextdefsym = ctx.nlocalsym;
    const iundefsym = iextdefsym + ctx.nextdefsym;

    const seg = self.getLinkeditSegmentPtr();
    const offset = seg.fileoff + seg.filesize;
    assert(mem.isAlignedGeneric(u64, offset, @alignOf(u64)));
    const needed_size = nindirectsyms * @sizeOf(u32);
    const needed_size_aligned = mem.alignForward(u64, needed_size, @alignOf(u64));
    seg.filesize = offset + needed_size_aligned - seg.fileoff;

    log.debug("writing indirect symbol table from 0x{x} to 0x{x}", .{ offset, offset + needed_size_aligned });

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();
    try buf.ensureTotalCapacity(needed_size_aligned);
    const writer = buf.writer();

    if (self.getSectionByName("__TEXT", "__stubs")) |sect_id| {
        const stubs = &self.sections.items(.header)[sect_id];
        stubs.reserved1 = 0;
        for (self.stubs.items) |entry| {
            const target_sym = entry.getTargetSymbol(self);
            assert(target_sym.undf());
            try writer.writeIntLittle(u32, iundefsym + ctx.imports_table.get(entry.target).?);
        }
    }

    if (self.getSectionByName("__DATA_CONST", "__got")) |sect_id| {
        const got = &self.sections.items(.header)[sect_id];
        got.reserved1 = nstubs;
        for (self.got_entries.items) |entry| {
            const target_sym = entry.getTargetSymbol(self);
            if (target_sym.undf()) {
                try writer.writeIntLittle(u32, iundefsym + ctx.imports_table.get(entry.target).?);
            } else {
                try writer.writeIntLittle(u32, macho.INDIRECT_SYMBOL_LOCAL);
            }
        }
    }

    if (self.getSectionByName("__DATA", "__la_symbol_ptr")) |sect_id| {
        const la_symbol_ptr = &self.sections.items(.header)[sect_id];
        la_symbol_ptr.reserved1 = nstubs + ngot_entries;
        for (self.stubs.items) |entry| {
            const target_sym = entry.getTargetSymbol(self);
            assert(target_sym.undf());
            try writer.writeIntLittle(u32, iundefsym + ctx.imports_table.get(entry.target).?);
        }
    }

    const padding = needed_size_aligned - needed_size;
    if (padding > 0) {
        buf.appendNTimesAssumeCapacity(0, padding);
    }

    assert(buf.items.len == needed_size_aligned);

    try self.base.file.pwriteAll(buf.items, offset);

    self.dysymtab_cmd.nlocalsym = ctx.nlocalsym;
    self.dysymtab_cmd.iextdefsym = iextdefsym;
    self.dysymtab_cmd.nextdefsym = ctx.nextdefsym;
    self.dysymtab_cmd.iundefsym = iundefsym;
    self.dysymtab_cmd.nundefsym = ctx.nundefsym;
    self.dysymtab_cmd.indirectsymoff = @as(u32, @intCast(offset));
    self.dysymtab_cmd.nindirectsyms = nindirectsyms;
}

fn writeUuid(self: *MachO, uuid_cmd_offset: u32, has_codesig: bool) !void {
    const file_size = if (!has_codesig) blk: {
        const seg = self.getLinkeditSegmentPtr();
        break :blk seg.fileoff + seg.filesize;
    } else self.codesig_cmd.dataoff;
    try calcUuid(self.base.allocator, self.base.thread_pool, self.base.file, file_size, &self.uuid_cmd.uuid);
    const offset = uuid_cmd_offset + @sizeOf(macho.load_command);
    try self.base.file.pwriteAll(&self.uuid_cmd.uuid, offset);
}

fn writeCodeSignaturePadding(self: *MachO, code_sig: *CodeSignature) !void {
    const seg = self.getLinkeditSegmentPtr();
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

fn writeCodeSignature(self: *MachO, code_sig: *CodeSignature) !void {
    const seg_id = self.getSegmentByName("__TEXT").?;
    const seg = self.segments.items[seg_id];

    var buffer = std.ArrayList(u8).init(self.base.allocator);
    defer buffer.deinit();
    try buffer.ensureTotalCapacityPrecise(code_sig.size());
    try code_sig.writeAdhocSignature(self, .{
        .file = self.base.file,
        .exec_seg_base = seg.fileoff,
        .exec_seg_limit = seg.filesize,
        .file_size = self.codesig_cmd.dataoff,
        .output_mode = self.options.output_mode,
    }, buffer.writer());
    assert(buffer.items.len == code_sig.size());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{
        self.codesig_cmd.dataoff,
        self.codesig_cmd.dataoff + buffer.items.len,
    });

    try self.base.file.pwriteAll(buffer.items, self.codesig_cmd.dataoff);
}

/// Writes Mach-O file header.
fn writeHeader(self: *MachO, ncmds: u32, sizeofcmds: u32) !void {
    var header: macho.mach_header_64 = .{};
    header.flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK | macho.MH_PIE | macho.MH_TWOLEVEL;

    switch (self.options.cpu_arch.?) {
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

pub fn makeStaticString(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    assert(bytes.len <= buf.len);
    mem.copy(u8, &buf, bytes);
    return buf;
}

pub fn getAtomPtr(self: *MachO, atom_index: AtomIndex) *Atom {
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

pub fn getAtom(self: MachO, atom_index: AtomIndex) Atom {
    assert(atom_index < self.atoms.items.len);
    return self.atoms.items[atom_index];
}

fn getSegmentByName(self: MachO, segname: []const u8) ?u8 {
    for (self.segments.items, 0..) |seg, i| {
        if (mem.eql(u8, segname, seg.segName())) return @as(u8, @intCast(i));
    } else return null;
}

pub fn getSegment(self: MachO, sect_id: u8) macho.segment_command_64 {
    const index = self.sections.items(.segment_index)[sect_id];
    return self.segments.items[index];
}

pub fn getSegmentPtr(self: *MachO, sect_id: u8) *macho.segment_command_64 {
    const index = self.sections.items(.segment_index)[sect_id];
    return &self.segments.items[index];
}

pub fn getLinkeditSegmentPtr(self: *MachO) *macho.segment_command_64 {
    assert(self.segments.items.len > 0);
    const seg = &self.segments.items[self.segments.items.len - 1];
    assert(mem.eql(u8, seg.segName(), "__LINKEDIT"));
    return seg;
}

pub fn getSectionByName(self: MachO, segname: []const u8, sectname: []const u8) ?u8 {
    // TODO investigate caching with a hashmap
    for (self.sections.items(.header), 0..) |header, i| {
        if (mem.eql(u8, header.segName(), segname) and mem.eql(u8, header.sectName(), sectname))
            return @as(u8, @intCast(i));
    } else return null;
}

pub fn getSectionIndexes(self: MachO, segment_index: u8) struct { start: u8, end: u8 } {
    var start: u8 = 0;
    const nsects = for (self.segments.items, 0..) |seg, i| {
        if (i == segment_index) break @as(u8, @intCast(seg.nsects));
        start += @as(u8, @intCast(seg.nsects));
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
    if (sym_with_loc.getFile()) |file| {
        const object = &self.objects.items[file];
        return &object.symtab[sym_with_loc.sym_index];
    } else {
        return &self.locals.items[sym_with_loc.sym_index];
    }
}

/// Returns symbol described by `sym_with_loc` descriptor.
pub fn getSymbol(self: *const MachO, sym_with_loc: SymbolWithLoc) macho.nlist_64 {
    if (sym_with_loc.getFile()) |file| {
        const object = &self.objects.items[file];
        return object.symtab[sym_with_loc.sym_index];
    } else {
        return self.locals.items[sym_with_loc.sym_index];
    }
}

/// Returns name of the symbol described by `sym_with_loc` descriptor.
pub fn getSymbolName(self: *const MachO, sym_with_loc: SymbolWithLoc) []const u8 {
    if (sym_with_loc.getFile()) |file| {
        const object = self.objects.items[file];
        return object.getSymbolName(sym_with_loc.sym_index);
    } else {
        const sym = self.locals.items[sym_with_loc.sym_index];
        return self.strtab.get(sym.n_strx).?;
    }
}

/// Returns GOT atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getGotAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    const index = self.got_table.get(sym_with_loc) orelse return null;
    const entry = self.got_entries.items[index];
    return entry.atom_index;
}

/// Returns stubs atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getStubsAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    const index = self.stubs_table.get(sym_with_loc) orelse return null;
    const entry = self.stubs.items[index];
    return entry.atom_index;
}

/// Returns TLV pointer atom that references `sym_with_loc` if one exists.
/// Returns null otherwise.
pub fn getTlvPtrAtomIndexForSymbol(self: *MachO, sym_with_loc: SymbolWithLoc) ?AtomIndex {
    const index = self.tlv_ptr_table.get(sym_with_loc) orelse return null;
    const entry = self.tlv_ptr_entries.items[index];
    return entry.atom_index;
}

/// Returns symbol location corresponding to the set entrypoint.
/// Asserts output mode is executable.
pub fn getEntryPoint(self: MachO) SymbolWithLoc {
    assert(self.options.output_mode == .exe);
    const global_index = self.entry_index.?;
    return self.globals.items[global_index];
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
    if (self.options.cpu_arch.? == .aarch64) switch (self.options.platform.?.platform) {
        .MACOS, .IOSSIMULATOR, .WATCHOSSIMULATOR, .TVOSSIMULATOR => return true,
        else => {},
    };
    return false;
}

inline fn requiresThunks(self: MachO) bool {
    return self.options.cpu_arch.? == .aarch64;
}

pub fn generateSymbolStabs(self: *MachO, object: Object, locals: *std.ArrayList(macho.nlist_64)) !void {
    assert(!self.options.strip);

    log.debug("generating stabs for '{s}'", .{object.name});

    const gpa = self.base.allocator;
    var debug_info = object.parseDwarfInfo();

    var lookup = DwarfInfo.AbbrevLookupTable.init(gpa);
    defer lookup.deinit();
    try lookup.ensureUnusedCapacity(std.math.maxInt(u8));

    // We assume there is only one CU.
    var cu_it = debug_info.getCompileUnitIterator();
    const compile_unit = while (try cu_it.next()) |cu| {
        try debug_info.genAbbrevLookupByKind(cu.cuh.debug_abbrev_offset, &lookup);
        break cu;
    } else {
        log.debug("no compile unit found in debug info in {s}; skipping", .{object.name});
        return;
    };

    var abbrev_it = compile_unit.getAbbrevEntryIterator(debug_info);
    const cu_entry: DwarfInfo.AbbrevEntry = while (try abbrev_it.next(lookup, self)) |entry| switch (entry.tag) {
        dwarf.TAG.compile_unit => break entry,
        else => continue,
    } else {
        log.debug("missing DWARF_TAG_compile_unit tag in {s}; skipping", .{object.name});
        return;
    };

    var maybe_tu_name: ?[]const u8 = null;
    var maybe_tu_comp_dir: ?[]const u8 = null;
    var attr_it = cu_entry.getAttributeIterator(debug_info, compile_unit.cuh);

    while (try attr_it.next(self)) |attr| switch (attr.name) {
        dwarf.AT.comp_dir => maybe_tu_comp_dir = attr.getString(debug_info, compile_unit.cuh) orelse continue,
        dwarf.AT.name => maybe_tu_name = attr.getString(debug_info, compile_unit.cuh) orelse continue,
        else => continue,
    };

    if (maybe_tu_name == null or maybe_tu_comp_dir == null) {
        log.debug("missing DWARF_AT_comp_dir and DWARF_AT_name attributes {s}; skipping", .{object.name});
        return;
    }

    const tu_name = maybe_tu_name.?;
    const tu_comp_dir = maybe_tu_comp_dir.?;

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

    var name_lookup: ?DwarfInfo.SubprogramLookupByName = if (object.header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS == 0) blk: {
        var name_lookup = DwarfInfo.SubprogramLookupByName.init(gpa);
        errdefer name_lookup.deinit();
        try name_lookup.ensureUnusedCapacity(@as(u32, @intCast(object.atoms.items.len)));
        try debug_info.genSubprogramLookupByName(compile_unit, lookup, &name_lookup, self);
        break :blk name_lookup;
    } else null;
    defer if (name_lookup) |*nl| nl.deinit();

    for (object.atoms.items) |atom_index| {
        const atom = self.getAtom(atom_index);
        const stabs = try self.generateSymbolStabsForSymbol(
            atom_index,
            atom.getSymbolWithLoc(),
            name_lookup,
            &stabs_buf,
        );
        try locals.appendSlice(stabs);

        var it = Atom.getInnerSymbolsIterator(self, atom_index);
        while (it.next()) |sym_loc| {
            const contained_stabs = try self.generateSymbolStabsForSymbol(
                atom_index,
                sym_loc,
                name_lookup,
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
    atom_index: AtomIndex,
    sym_loc: SymbolWithLoc,
    lookup: ?DwarfInfo.SubprogramLookupByName,
    buf: *[4]macho.nlist_64,
) ![]const macho.nlist_64 {
    const gpa = self.base.allocator;
    const object = self.objects.items[sym_loc.getFile().?];
    const sym = self.getSymbol(sym_loc);
    const sym_name = self.getSymbolName(sym_loc);
    const header = self.sections.items(.header)[sym.n_sect - 1];

    if (sym.n_strx == 0) return buf[0..0];
    if (self.symbolIsTemp(sym_loc)) return buf[0..0];

    if (!header.isCode()) {
        // Since we are not dealing with machine code, it's either a global or a static depending
        // on the linkage scope.
        if (sym.sect() and sym.ext()) {
            // Global gets an N_GSYM stab type.
            buf[0] = .{
                .n_strx = try self.strtab.insert(gpa, sym_name),
                .n_type = macho.N_GSYM,
                .n_sect = sym.n_sect,
                .n_desc = 0,
                .n_value = 0,
            };
        } else {
            // Local static gets an N_STSYM stab type.
            buf[0] = .{
                .n_strx = try self.strtab.insert(gpa, sym_name),
                .n_type = macho.N_STSYM,
                .n_sect = sym.n_sect,
                .n_desc = 0,
                .n_value = sym.n_value,
            };
        }
        return buf[0..1];
    }

    const size: u64 = size: {
        if (object.header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0) {
            break :size self.getAtom(atom_index).size;
        }

        // Since we don't have subsections to work with, we need to infer the size of each function
        // the slow way by scanning the debug info for matching symbol names and extracting
        // the symbol's DWARF_AT_low_pc and DWARF_AT_high_pc values.
        const source_sym = object.getSourceSymbol(sym_loc.sym_index) orelse return buf[0..0];
        const subprogram = lookup.?.get(sym_name[1..]) orelse return buf[0..0];

        if (subprogram.addr <= source_sym.n_value and source_sym.n_value < subprogram.addr + subprogram.size) {
            break :size subprogram.size;
        } else {
            log.debug("no stab found for {s}", .{sym_name});
            return buf[0..0];
        }
    };

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
        .n_value = size,
    };
    buf[3] = .{
        .n_strx = 0,
        .n_type = macho.N_ENSYM,
        .n_sect = sym.n_sect,
        .n_desc = 0,
        .n_value = size,
    };

    return buf;
}

fn logSegments(self: *MachO) void {
    log.debug("segments:", .{});
    for (self.segments.items, 0..) |segment, i| {
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
    for (self.sections.items(.header), 0..) |header, i| {
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

fn logSymAttributes(sym: macho.nlist_64, buf: []u8) []const u8 {
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
    return buf[0..];
}

fn logSymtab(self: *MachO) void {
    var buf: [4]u8 = undefined;

    const scoped_log = std.log.scoped(.symtab);

    scoped_log.debug("locals:", .{});
    for (self.objects.items, 0..) |object, id| {
        scoped_log.debug("  object({d}): {s}", .{ id, object.name });
        if (object.in_symtab == null) continue;
        for (object.symtab, 0..) |sym, sym_id| {
            @memset(&buf, '_');
            scoped_log.debug("    %{d}: {s} @{x} in sect({d}), {s}", .{
                sym_id,
                object.getSymbolName(@as(u32, @intCast(sym_id))),
                sym.n_value,
                sym.n_sect,
                logSymAttributes(sym, &buf),
            });
        }
    }

    scoped_log.debug("  object(-1)", .{});
    for (self.locals.items, 0..) |sym, sym_id| {
        if (sym.undf()) continue;
        scoped_log.debug("    %{d}: {s} @{x} in sect({d}), {s}", .{
            sym_id,
            self.strtab.get(sym.n_strx).?,
            sym.n_value,
            sym.n_sect,
            logSymAttributes(sym, &buf),
        });
    }

    scoped_log.debug("exports:", .{});
    for (self.globals.items, 0..) |global, i| {
        const sym = self.getSymbol(global);
        if (sym.undf()) continue;
        if (sym.n_desc == N_DEAD) continue;
        scoped_log.debug("    %{d}: {s} @{x} in sect({d}), {s} (def in object({?}))", .{
            i,
            self.getSymbolName(global),
            sym.n_value,
            sym.n_sect,
            logSymAttributes(sym, &buf),
            global.getFile(),
        });
    }

    scoped_log.debug("imports:", .{});
    for (self.globals.items, 0..) |global, i| {
        const sym = self.getSymbol(global);
        if (!sym.undf()) continue;
        if (sym.n_desc == N_DEAD) continue;
        const ord = @divTrunc(sym.n_desc, macho.N_SYMBOL_RESOLVER);
        scoped_log.debug("    %{d}: {s} @{x} in ord({d}), {s}", .{
            i,
            self.getSymbolName(global),
            sym.n_value,
            ord,
            logSymAttributes(sym, &buf),
        });
    }

    scoped_log.debug("GOT entries:", .{});
    for (self.got_entries.items, 0..) |entry, i| {
        const atom_sym = entry.getAtomSymbol(self);
        const target_sym = entry.getTargetSymbol(self);
        const target_sym_name = entry.getTargetSymbolName(self);
        if (target_sym.undf()) {
            scoped_log.debug("  {d}@{x} => import('{s}')", .{
                i,
                atom_sym.n_value,
                target_sym_name,
            });
        } else {
            scoped_log.debug("  {d}@{x} => local(%{d}) in object({?}) {s}", .{
                i,
                atom_sym.n_value,
                entry.target.sym_index,
                entry.target.getFile(),
                logSymAttributes(target_sym, buf[0..4]),
            });
        }
    }

    scoped_log.debug("__thread_ptrs entries:", .{});
    for (self.tlv_ptr_entries.items, 0..) |entry, i| {
        const atom_sym = entry.getAtomSymbol(self);
        const target_sym = entry.getTargetSymbol(self);
        const target_sym_name = entry.getTargetSymbolName(self);
        assert(target_sym.undf());
        scoped_log.debug("  {d}@{x} => import('{s}')", .{
            i,
            atom_sym.n_value,
            target_sym_name,
        });
    }

    scoped_log.debug("stubs entries:", .{});
    for (self.stubs.items, 0..) |entry, i| {
        const atom_sym = entry.getAtomSymbol(self);
        const target_sym = entry.getTargetSymbol(self);
        const target_sym_name = entry.getTargetSymbolName(self);
        assert(target_sym.undf());
        scoped_log.debug("  {d}@{x} => import('{s}')", .{
            i,
            atom_sym.n_value,
            target_sym_name,
        });
    }

    scoped_log.debug("thunks:", .{});
    for (self.thunks.items, 0..) |thunk, i| {
        scoped_log.debug("  thunk({d})", .{i});
        for (thunk.lookup.keys(), 0..) |target, j| {
            const target_sym = self.getSymbol(target);
            const atom = self.getAtom(thunk.lookup.get(target).?);
            const atom_sym = self.getSymbol(atom.getSymbolWithLoc());
            scoped_log.debug("    {d}@{x} => thunk('{s}'@{x})", .{
                j,
                atom_sym.n_value,
                self.getSymbolName(target),
                target_sym.n_value,
            });
        }
    }
}

fn logAtoms(self: *MachO) void {
    log.debug("atoms:", .{});
    const slice = self.sections.slice();
    for (slice.items(.first_atom_index), 0..) |first_atom_index, sect_id| {
        var atom_index = first_atom_index;
        if (atom_index == 0) continue;

        const header = slice.items(.header)[sect_id];

        log.debug("{s},{s}", .{ header.segName(), header.sectName() });

        while (true) {
            const atom = self.getAtom(atom_index);
            self.logAtom(atom_index, log);

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }
}

pub fn logAtom(self: *MachO, atom_index: AtomIndex, logger: anytype) void {
    if (!build_options.enable_logging) return;

    const atom = self.getAtom(atom_index);
    const sym = self.getSymbol(atom.getSymbolWithLoc());
    const sym_name = self.getSymbolName(atom.getSymbolWithLoc());
    logger.debug("  ATOM(%{d}, '{s}') @ {x} (sizeof({x}), alignof({x})) in object({?}) in sect({d})", .{
        atom.sym_index,
        sym_name,
        sym.n_value,
        atom.size,
        atom.alignment,
        atom.getFile(),
        sym.n_sect,
    });

    if (atom.getFile() != null) {
        var it = Atom.getInnerSymbolsIterator(self, atom_index);
        while (it.next()) |sym_loc| {
            const inner = self.getSymbol(sym_loc);
            const inner_name = self.getSymbolName(sym_loc);
            const offset = Atom.calcInnerSymbolOffset(self, atom_index, sym_loc.sym_index);

            logger.debug("    (%{d}, '{s}') @ {x} ({x})", .{
                sym_loc.sym_index,
                inner_name,
                inner.n_value,
                offset,
            });
        }

        if (Atom.getSectionAlias(self, atom_index)) |sym_loc| {
            const alias = self.getSymbol(sym_loc);
            const alias_name = self.getSymbolName(sym_loc);

            logger.debug("    (%{d}, '{s}') @ {x} ({x})", .{
                sym_loc.sym_index,
                alias_name,
                alias.n_value,
                0,
            });
        }
    }
}
