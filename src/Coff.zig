base: Zld,
options: Options,

objects: std.ArrayListUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},

sections: std.MultiArrayList(Section) = .{},

string_intern: StringTable = .{},

atoms: std.ArrayListUnmanaged(Atom) = .{},

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
        .object => data.object.deinit(gpa),
    };
    self.files.deinit(gpa);
    self.objects.deinit(gpa);

    for (self.sections.items(.atoms)) |*list| {
        list.deinit(gpa);
    }
    self.sections.deinit(gpa);
    self.atoms.deinit(gpa);
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

    for (lib_dirs) |dir| {
        try buffer.writer().print("{s}" ++ std.fs.path.sep_str ++ "{s}", .{ dir, obj.name });
        if (visited.get(buffer.items)) |_| return error.AlreadyVisited;
        if (try accessPath(buffer.items)) {
            const path = try arena.dupe(u8, buffer.items);
            try visited.putNoClobber(path, {});
            return .{ .name = obj.name, .path = path, .tag = obj.tag };
        }
        buffer.clearRetainingCapacity();
    }
    self.base.fatal("file not found '{s}'", .{obj.name});
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
} || std.os.AccessError || std.fs.File.OpenError || std.os.PReadError;

fn parsePositional(
    self: *Coff,
    arena: Allocator,
    obj: LinkObject,
    lib_paths: []const []const u8,
    queue: anytype,
    visited: anytype,
) ParseError!void {
    log.debug("parsing positional {}", .{obj});

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
    if (!Object.isValidHeader(&header_buffer)) return false;
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
    try self.parseDirectives(object, queue);

    return true;
}

fn parseDirectives(self: *Coff, object: *const Object, queue: anytype) ParseError!void {
    var has_parse_error = false;
    var it = mem.splitScalar(u8, object.directives.items, ' ');
    var p = Options.ArgsParser(@TypeOf(it)){ .it = &it };
    while (p.hasMore()) {
        if (p.arg("defaultlib")) |name| {
            const dir_obj = LinkObject{ .name = name, .tag = .default_lib };
            log.debug("{}: adding implicit include {}", .{ object.fmtPath(), dir_obj });
            try queue.writeItem(dir_obj);
        } else {
            self.base.fatal("{}: unhandled directive: {s}", .{
                object.fmtPath(),
                p.next_arg,
            });
            has_parse_error = true;
        }
    }
    if (has_parse_error) return error.ParseFailed;
}

fn parseArchive(self: *Coff, obj: LinkObject, queue: anytype) ParseError!bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    var magic: [Archive.magic.len]u8 = undefined;
    const amt = file.preadAll(&magic, 0) catch return false;
    if (amt != Archive.magic.len) return false;
    if (!Archive.isValidMagic(&magic)) return false;

    var archive = Archive{};
    defer archive.deinit(gpa);
    try archive.parse(obj.path, fh, self);

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
        self.parseDirectives(object, queue) catch |err| switch (err) {
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

pub fn getFile(self: *Coff, index: File.Index) ?File {
    const tag = self.files.items(.tags)[index];
    return switch (tag) {
        .null => null,
        .object => .{ .object = &self.files.items(.data)[index].object },
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
        try writer.print("{}\n", .{
            object.fmtAtoms(self),
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
const trace = @import("tracy.zig").trace;

const Allocator = mem.Allocator;
const Archive = @import("Coff/Archive.zig");
const Atom = @import("Coff/Atom.zig");
const Coff = @This();
const File = @import("Coff/file.zig").File;
const Object = @import("Coff/Object.zig");
pub const Options = @import("Coff/Options.zig");
const StringTable = @import("StringTable.zig");
const ThreadPool = std.Thread.Pool;
const Zld = @import("Zld.zig");
