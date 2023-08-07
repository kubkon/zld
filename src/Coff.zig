const Coff = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const coff = std.coff;
const fs = std.fs;
const log = std.log.scoped(.coff);
const mem = std.mem;

const Allocator = mem.Allocator;
const Object = @import("Coff/Object.zig");
pub const Options = @import("Coff/Options.zig");
const ThreadPool = std.Thread.Pool;
const Zld = @import("Zld.zig");

pub const base_tag = Zld.Tag.coff;

base: Zld,
options: Options,

objects: std.ArrayListUnmanaged(Object) = .{},

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
    for (self.objects.items) |*object| {
        object.deinit(self.base.allocator);
    }

    self.objects.deinit(self.base.allocator);
}

pub fn flush(self: *Coff) !void {
    const gpa = self.base.allocator;

    var positionals = std.ArrayList([]const u8).init(gpa);
    defer positionals.deinit();
    try positionals.ensureTotalCapacity(self.options.positionals.len);

    for (self.options.positionals) |obj| {
        positionals.appendAssumeCapacity(obj.path);
    }

    try self.parsePositionals(positionals.items);
    log.debug("{}", .{self.dumpState()});
}

fn parsePositionals(self: *Coff, files: []const []const u8) !void {
    for (files) |file_name| {
        const full_path = full_path: {
            var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
            const path = try std.fs.realpath(file_name, &buffer);
            break :full_path try self.base.allocator.dupe(u8, path);
        };
        defer self.base.allocator.free(full_path);
        log.debug("parsing input file path '{s}'", .{full_path});

        if (try self.parseObject(full_path)) continue;

        log.warn("unknown filetype for positional input file: '{s}'", .{file_name});
    }
}

fn parseObject(self: *Coff, path: []const u8) !bool {
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

    object.parse(self.base.allocator, self.options.target.cpu_arch.?, self) catch |err| switch (err) {
        error.EndOfStream => {
            object.deinit(self.base.allocator);
            return false;
        },
        else => |e| return e,
    };

    try self.objects.append(self.base.allocator, object);

    return true;
}

fn dumpState(self: *Coff) std.fmt.Formatter(fmtDumpState) {
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
    for (self.objects.items) |*obj| {
        try writer.print("Object name: '{s}'", .{obj.name});
        try writer.print("Symbols: {}", .{obj.symtab.len()});
        var it = obj.symtab.slice(0, null);
        while (it.next()) |sym| {
            const name = sym.getName() orelse obj.getString(sym.getNameOffset().?);
            try writer.print("    Name: `{s}`\n", .{name});
            try writer.print("        Type:    {} {}\n", .{ sym.type.base_type, sym.type.complex_type });
            try writer.print("        Storage: {}\n", .{sym.storage_class});
        }
        try writer.print("SectionHeaders: {}\n", .{obj.shdrtab.items.len});
        for (obj.shdrtab.items) |sh| {
            const name = sh.getName() orelse obj.getString(sh.getNameOffset().?);
            try writer.print("    Name: `{s}`\n", .{name});
            try writer.print("    Flags: {x}\n", .{@as(u32, @bitCast(sh.flags))});
        }
    }
}
