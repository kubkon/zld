tag: Tag,
allocator: Allocator,
file: fs.File,
thread_pool: *ThreadPool,
warnings: std.ArrayListUnmanaged([]const u8) = .{},
errors: std.ArrayListUnmanaged([]const u8) = .{},

pub const Tag = enum {
    coff,
    elf,
    macho,
    wasm,
};

pub const Emit = struct {
    directory: fs.Dir,
    sub_path: []const u8,
};

pub const OutputMode = enum {
    exe,
    lib,
};

pub const SystemLib = struct {
    needed: bool = true,
    weak: bool = false,
    static: bool = false,
};

pub const LinkObject = struct {
    path: []const u8,
    must_link: bool = false,
};

pub const Options = union {
    elf: Elf.Options,
    macho: MachO.Options,
    coff: Coff.Options,
    wasm: Wasm.Options,

    pub const ArgsIterator = struct {
        args: []const []const u8,
        i: usize = 0,

        pub fn next(it: *@This()) ?[]const u8 {
            if (it.i >= it.args.len) return null;
            defer it.i += 1;
            return it.args[it.i];
        }

        pub fn nextOrFatal(it: *@This(), ctx: anytype) []const u8 {
            const arg = it.next() orelse
                ctx.fatal("Expected parameter after '{s}'", .{it.args[it.i - 1]});
            return arg;
        }
    };

    pub fn parse(arena: Allocator, tag: Tag, args: []const []const u8, ctx: anytype) !Options {
        return switch (tag) {
            .elf => .{ .elf = try Elf.Options.parse(arena, args, ctx) },
            .macho => .{ .macho = try MachO.Options.parse(arena, args, ctx) },
            .coff => .{ .coff = try Coff.Options.parse(arena, args, ctx) },
            .wasm => .{ .wasm = try Wasm.Options.parse(arena, args, ctx) },
        };
    }
};

pub fn openPath(allocator: Allocator, tag: Tag, options: Options, thread_pool: *ThreadPool) !*Zld {
    return switch (tag) {
        .macho => &(try MachO.openPath(allocator, options.macho, thread_pool)).base,
        .elf => &(try Elf.openPath(allocator, options.elf, thread_pool)).base,
        .coff => &(try Coff.openPath(allocator, options.coff, thread_pool)).base,
        .wasm => &(try Wasm.openPath(allocator, options.wasm, thread_pool)).base,
    };
}

pub fn deinit(base: *Zld) void {
    base.file.close();
    for (base.warnings.items) |msg| {
        base.allocator.free(msg);
    }
    base.warnings.deinit(base.allocator);
    for (base.errors.items) |msg| {
        base.allocator.free(msg);
    }
    base.errors.deinit(base.allocator);
    switch (base.tag) {
        .elf => {
            const parent = @fieldParentPtr(Elf, "base", base);
            parent.deinit();
            base.allocator.destroy(parent);
        },
        .macho => {
            const parent = @fieldParentPtr(MachO, "base", base);
            parent.deinit();
            base.allocator.destroy(parent);
        },
        .coff => {
            const parent = @fieldParentPtr(Coff, "base", base);
            parent.deinit();
            base.allocator.destroy(parent);
        },
        .wasm => {
            const parent = @fieldParentPtr(Wasm, "base", base);
            parent.deinit();
            base.allocator.destroy(parent);
        },
    }
}

pub fn flush(base: *Zld) !void {
    switch (base.tag) {
        .elf => try @fieldParentPtr(Elf, "base", base).flush(),
        .macho => try @fieldParentPtr(MachO, "base", base).flush(),
        .coff => try @fieldParentPtr(Coff, "base", base).flush(),
        .wasm => try @fieldParentPtr(Wasm, "base", base).flush(),
    }
}

pub fn warn(base: *Zld, comptime format: []const u8, args: anytype) void {
    base.warnings.ensureUnusedCapacity(base.allocator, 1) catch return;
    const msg = std.fmt.allocPrint(base.allocator, format, args) catch return;
    base.warnings.appendAssumeCapacity(msg);
}

pub fn fatal(base: *Zld, comptime format: []const u8, args: anytype) void {
    base.errors.ensureUnusedCapacity(base.allocator, 1) catch return;
    const msg = std.fmt.allocPrint(base.allocator, format, args) catch return;
    base.errors.appendAssumeCapacity(msg);
}

pub fn getAllWarningsAlloc(base: *Zld) !ErrorBundle {
    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(base.allocator);
    defer bundle.deinit();

    for (base.warnings.items) |msg| {
        try bundle.addRootErrorMessage(.{ .msg = try bundle.addString(msg) });
    }

    return bundle.toOwnedBundle("");
}

pub fn getAllErrorsAlloc(base: *Zld) !ErrorBundle {
    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(base.allocator);
    defer bundle.deinit();

    for (base.errors.items) |msg| {
        try bundle.addRootErrorMessage(.{ .msg = try bundle.addString(msg) });
    }

    return bundle.toOwnedBundle("");
}

fn renderWarningToStdErr(eb: ErrorBundle) void {
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
    const stderr = std.io.getStdErr();
    return renderWarningToWriter(eb, stderr.writer()) catch return;
}

fn renderWarningToWriter(eb: ErrorBundle, writer: anytype) !void {
    for (eb.getMessages()) |msg| {
        try renderWarningMessageToWriter(eb, msg, writer, "warning", .Cyan, 0);
    }
}

fn renderWarningMessageToWriter(
    eb: ErrorBundle,
    err_msg_index: ErrorBundle.MessageIndex,
    stderr: anytype,
    kind: []const u8,
    color: std.debug.TTY.Color,
    indent: usize,
) anyerror!void {
    const ttyconf = std.debug.detectTTYConfig(std.io.getStdErr());
    const err_msg = eb.getErrorMessage(err_msg_index);
    try ttyconf.setColor(stderr, color);
    try stderr.writeByteNTimes(' ', indent);
    try stderr.writeAll(kind);
    try stderr.writeAll(": ");
    try ttyconf.setColor(stderr, .Reset);
    const msg = eb.nullTerminatedString(err_msg.msg);
    if (err_msg.count == 1) {
        try stderr.print("{s}\n", .{msg});
    } else {
        try stderr.print("{s}", .{msg});
        try ttyconf.setColor(stderr, .Dim);
        try stderr.print(" ({d} times)\n", .{err_msg.count});
    }
    try ttyconf.setColor(stderr, .Reset);
    for (eb.getNotes(err_msg_index)) |note| {
        try renderWarningMessageToWriter(eb, note, stderr, "note", .White, indent + 4);
    }
}

pub fn reportWarningsAndErrors(base: *Zld) !void {
    var warnings = try base.getAllWarningsAlloc();
    defer warnings.deinit(base.allocator);
    if (warnings.errorMessageCount() > 0) {
        renderWarningToStdErr(warnings);
    }

    var errors = try base.getAllErrorsAlloc();
    defer errors.deinit(base.allocator);
    if (errors.errorMessageCount() > 0) {
        errors.renderToStdErr(.{ .ttyconf = std.debug.detectTTYConfig(std.io.getStdErr()) });
        return error.LinkFail;
    }
}

pub fn reportWarningsAndErrorsAndExit(base: *Zld) void {
    base.reportWarningsAndErrors() catch {
        base.deinit();
        process.exit(1);
    };
}

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;
const trace = @import("tracy.zig").trace;

pub const Elf = @import("Elf.zig");
pub const MachO = @import("MachO.zig");
pub const Coff = @import("Coff.zig");
pub const Wasm = @import("Wasm.zig");

const Allocator = mem.Allocator;
const CrossTarget = std.zig.CrossTarget;
const ErrorBundle = std.zig.ErrorBundle;
const ThreadPool = @import("ThreadPool.zig");
const Zld = @This();
