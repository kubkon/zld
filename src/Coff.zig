base: Zld,
options: Options,

objects: std.ArrayListUnmanaged(File.Index) = .{},
files: std.MultiArrayList(File.Entry) = .{},
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},

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
}

pub fn flush(self: *Coff) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;

    // Append null file.
    try self.files.append(gpa, .null);

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // Resolve search dirs
    const search_dirs = std.ArrayList([]const u8).init(arena);
    _ = search_dirs;

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
                .lib => return error.Todo,
            }
        };
        resolved_objects.appendAssumeCapacity(.{
            .path = full_path,
            .tag = obj.tag,
        });
    }

    // TODO infer CPU arch and perhaps subsystem and whatnot?

    var has_parse_error = false;
    for (resolved_objects.items) |obj| {
        self.parsePositional(obj) catch |err| {
            has_parse_error = true;
            switch (err) {
                // error.ParseFailed => {}, // already reported
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

    return error.Todo;
}

fn parsePositional(self: *Coff, obj: LinkObject) !void {
    log.debug("parsing positional {}", .{obj});

    if (try self.parseObject(obj)) return;

    self.base.fatal("unknown filetype for positional argument: '{s}'", .{obj.path});
}

fn parseObject(self: *Coff, obj: LinkObject) !bool {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.allocator;
    const file = try std.fs.cwd().openFile(obj.path, .{});
    const fh = try self.addFileHandle(file);

    const header = file.reader().readStruct(coff.CoffHeader) catch return false;
    try file.seekTo(0);

    if (header.size_of_optional_header != 0) return false;

    const index = @as(File.Index, @intCast(try self.files.addOne(gpa)));
    self.files.set(index, .{ .object = .{
        .path = try gpa.dupe(u8, obj.path),
        .file_handle = fh,
        .index = index,
    } });
    const object = &self.files.items(.data)[index].object;
    try object.parse(self);
    try self.objects.append(gpa, index);
    // TODO validate CPU arch

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

pub const LinkObject = struct {
    path: []const u8,
    tag: enum { obj, lib },

    pub fn format(
        self: LinkObject,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        switch (self.tag) {
            .lib => try writer.writeAll("-l"),
            .obj => {},
        }
        try writer.writeAll(self.path);
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
const std = @import("std");
const trace = @import("tracy.zig").trace;

const Allocator = mem.Allocator;
const Coff = @This();
const File = @import("Coff/file.zig").File;
const Object = @import("Coff/Object.zig");
pub const Options = @import("Coff/Options.zig");
const ThreadPool = std.Thread.Pool;
const Zld = @import("Zld.zig");
