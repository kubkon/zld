tag: Tag,
allocator: Allocator,
file: fs.File,
thread_pool: *ThreadPool,
warnings: std.ArrayListUnmanaged(ErrorMsg) = .{},
errors: std.ArrayListUnmanaged(ErrorMsg) = .{},

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

        pub fn peek(it: *@This()) ?[]const u8 {
            const arg = it.next();
            defer if (it.i > 0) {
                it.i -= 1;
            };
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

pub fn ArgParser(comptime Ctx: type) type {
    return struct {
        arg: []const u8 = undefined,
        it: *Options.ArgsIterator,
        ctx: Ctx,

        pub fn hasMore(p: *Self) bool {
            p.arg = p.it.next() orelse return false;
            return true;
        }

        pub fn flagAny(p: *Self, comptime pat: []const u8) bool {
            return p.flag2(pat) or p.flag1(pat);
        }

        pub fn flag2(p: *Self, comptime pat: []const u8) bool {
            return p.flagPrefix(pat, "--");
        }

        pub fn flag1(p: *Self, comptime pat: []const u8) bool {
            return p.flagPrefix(pat, "-");
        }

        pub fn flagZ(p: *Self, comptime pat: []const u8) bool {
            const prefix = "-z";
            const i = p.it.i;
            const actual_flag = blk: {
                if (mem.eql(u8, p.arg, prefix)) {
                    break :blk p.it.nextOrFatal(p.ctx);
                }
                if (mem.startsWith(u8, p.arg, prefix)) {
                    break :blk p.arg[prefix.len..];
                }
                return false;
            };
            if (mem.eql(u8, actual_flag, pat)) return true;
            p.it.i = i;
            return false;
        }

        fn flagPrefix(p: *Self, comptime pat: []const u8, comptime prefix: []const u8) bool {
            if (mem.startsWith(u8, p.arg, prefix)) {
                const actual_arg = p.arg[prefix.len..];
                if (mem.eql(u8, actual_arg, pat)) {
                    return true;
                }
            }
            return false;
        }

        pub fn argAny(p: *Self, comptime pat: []const u8) ?[]const u8 {
            if (p.arg2(pat)) |value| return value;
            return p.arg1(pat);
        }

        pub fn arg2(p: *Self, comptime pat: []const u8) ?[]const u8 {
            return p.argPrefix(pat, "--");
        }

        pub fn arg1(p: *Self, comptime pat: []const u8) ?[]const u8 {
            return p.argPrefix(pat, "-");
        }

        pub fn argZ(p: *Self, comptime pat: []const u8) ?[]const u8 {
            const prefix = "-z";
            const i = p.it.i;
            const actual_arg = blk: {
                if (mem.eql(u8, p.arg, prefix)) {
                    if (p.it.peek()) |next| {
                        if (mem.startsWith(u8, next, "-")) return null;
                    }
                    break :blk p.it.nextOrFatal(p.ctx);
                }
                if (mem.startsWith(u8, p.arg, prefix)) {
                    break :blk p.arg[prefix.len..];
                }
                return null;
            };
            if (mem.startsWith(u8, actual_arg, pat)) {
                if (mem.indexOf(u8, actual_arg, "=")) |index| {
                    if (index == pat.len) {
                        const value = actual_arg[index + 1 ..];
                        return value;
                    }
                }
            }
            p.it.i = i;
            return null;
        }

        fn argPrefix(p: *Self, comptime pat: []const u8, comptime prefix: []const u8) ?[]const u8 {
            if (mem.startsWith(u8, p.arg, prefix)) {
                const actual_arg = p.arg[prefix.len..];
                if (mem.eql(u8, actual_arg, pat)) {
                    if (p.it.peek()) |next| {
                        if (mem.startsWith(u8, next, "-")) return null;
                    }
                    return p.it.nextOrFatal(p.ctx);
                }
                if (pat.len == 1 and mem.eql(u8, actual_arg[0..pat.len], pat)) {
                    return actual_arg[pat.len..];
                }
                // MachO specific
                if (mem.eql(u8, pat, "needed-l") or mem.eql(u8, pat, "weak-l") or
                    mem.eql(u8, pat, "hidden-l") or mem.eql(u8, pat, "reexport-l"))
                {
                    if (mem.startsWith(u8, actual_arg, pat)) {
                        return actual_arg[pat.len..];
                    }
                }
                if (mem.startsWith(u8, actual_arg, pat)) {
                    if (mem.indexOf(u8, actual_arg, "=")) |index| {
                        if (index == pat.len) {
                            const value = actual_arg[index + 1 ..];
                            return value;
                        }
                    }
                }
            }
            return null;
        }

        const Self = @This();
    };
}

pub const ErrorMsg = struct {
    msg: []const u8,
    notes: std.ArrayListUnmanaged(ErrorMsg) = .{},

    fn deinit(err: *ErrorMsg, allocator: Allocator) void {
        allocator.free(err.msg);
        for (err.notes.items) |*note| note.deinit(allocator);
        err.notes.deinit(allocator);
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
    base.warnings.deinit(base.allocator);
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
    base.warnings.appendAssumeCapacity(.{ .msg = msg });
}

pub fn fatal(base: *Zld, comptime format: []const u8, args: anytype) void {
    base.errors.ensureUnusedCapacity(base.allocator, 1) catch return;
    const msg = std.fmt.allocPrint(base.allocator, format, args) catch return;
    base.errors.appendAssumeCapacity(.{ .msg = msg });
}

pub const ErrorWithNotes = struct {
    err_index: usize,
    allocator: Allocator,
    errors: []ErrorMsg,

    pub fn addMsg(err: ErrorWithNotes, comptime format: []const u8, args: anytype) !void {
        const err_msg = err.getErrorMsg();
        err_msg.msg = try std.fmt.allocPrint(err.allocator, format, args);
    }

    pub fn addNote(err: ErrorWithNotes, comptime format: []const u8, args: anytype) !void {
        const err_msg = err.getErrorMsg();
        err_msg.notes.appendAssumeCapacity(.{
            .msg = try std.fmt.allocPrint(err.allocator, format, args),
        });
    }

    fn getErrorMsg(err: ErrorWithNotes) *ErrorMsg {
        assert(err.err_index < err.errors.len);
        return &err.errors[err.err_index];
    }
};

pub fn addErrorWithNotes(base: *Zld, note_count: usize) !ErrorWithNotes {
    const err_index = base.errors.items.len;
    const err_msg = try base.errors.addOne(base.allocator);
    err_msg.* = .{ .msg = undefined };
    try err_msg.notes.ensureTotalCapacityPrecise(base.allocator, note_count);
    return .{ .err_index = err_index, .allocator = base.allocator, .errors = base.errors.items };
}

pub fn addWarningWithNotes(base: *Zld, note_count: usize) !ErrorWithNotes {
    const err_index = base.warnings.items.len;
    const err_msg = try base.warnings.addOne(base.allocator);
    err_msg.* = .{ .msg = undefined };
    try err_msg.notes.ensureTotalCapacityPrecise(base.allocator, note_count);
    return .{ .err_index = err_index, .allocator = base.allocator, .errors = base.warnings.items };
}

pub fn getAllWarningsAlloc(base: *Zld) !ErrorBundle {
    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(base.allocator);
    defer bundle.deinit();
    defer {
        while (base.warnings.popOrNull()) |msg| {
            var mut_msg = msg;
            mut_msg.deinit(base.allocator);
        }
    }

    for (base.warnings.items) |msg| {
        const notes = msg.notes.items;
        try bundle.addRootErrorMessage(.{
            .msg = try bundle.addString(msg.msg),
            .notes_len = @as(u32, @intCast(notes.len)),
        });
        const notes_start = try bundle.reserveNotes(@as(u32, @intCast(notes.len)));
        for (notes_start.., notes) |index, note| {
            bundle.extra.items[index] = @intFromEnum(bundle.addErrorMessageAssumeCapacity(.{
                .msg = try bundle.addString(note.msg),
            }));
        }
    }

    return bundle.toOwnedBundle("");
}

pub fn getAllErrorsAlloc(base: *Zld) !ErrorBundle {
    var bundle: ErrorBundle.Wip = undefined;
    try bundle.init(base.allocator);
    defer bundle.deinit();
    defer {
        while (base.errors.popOrNull()) |msg| {
            var mut_msg = msg;
            mut_msg.deinit(base.allocator);
        }
    }

    for (base.errors.items) |msg| {
        const notes = msg.notes.items;
        try bundle.addRootErrorMessage(.{
            .msg = try bundle.addString(msg.msg),
            .notes_len = @as(u32, @intCast(notes.len)),
        });
        const notes_start = try bundle.reserveNotes(@as(u32, @intCast(notes.len)));
        for (notes_start.., notes) |index, note| {
            bundle.extra.items[index] = @intFromEnum(bundle.addErrorMessageAssumeCapacity(.{
                .msg = try bundle.addString(note.msg),
            }));
        }
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
        try renderWarningMessageToWriter(eb, msg, writer, "warning", .cyan, 0);
    }
}

fn renderWarningMessageToWriter(
    eb: ErrorBundle,
    err_msg_index: ErrorBundle.MessageIndex,
    stderr: anytype,
    kind: []const u8,
    color: std.io.tty.Color,
    indent: usize,
) anyerror!void {
    const ttyconf = std.io.tty.detectConfig(std.io.getStdErr());
    const err_msg = eb.getErrorMessage(err_msg_index);
    try ttyconf.setColor(stderr, color);
    try stderr.writeByteNTimes(' ', indent);
    try stderr.writeAll(kind);
    try stderr.writeAll(": ");
    try ttyconf.setColor(stderr, .reset);
    const msg = eb.nullTerminatedString(err_msg.msg);
    if (err_msg.count == 1) {
        try stderr.print("{s}\n", .{msg});
    } else {
        try stderr.print("{s}", .{msg});
        try ttyconf.setColor(stderr, .dim);
        try stderr.print(" ({d} times)\n", .{err_msg.count});
    }
    try ttyconf.setColor(stderr, .reset);
    for (eb.getNotes(err_msg_index)) |note| {
        try renderWarningMessageToWriter(eb, note, stderr, "note", .white, indent + 4);
    }
}

pub fn reportErrors(base: *Zld) void {
    var errors = base.getAllErrorsAlloc() catch @panic("OOM");
    defer errors.deinit(base.allocator);
    if (errors.errorMessageCount() > 0) {
        errors.renderToStdErr(.{ .ttyconf = std.io.tty.detectConfig(std.io.getStdErr()) });
    }
}

pub fn reportWarnings(base: *Zld) void {
    var warnings = base.getAllWarningsAlloc() catch @panic("OOM");
    defer warnings.deinit(base.allocator);
    if (warnings.errorMessageCount() > 0) {
        renderWarningToStdErr(warnings);
    }
}

/// Binary search
pub fn binarySearch(comptime T: type, haystack: []align(1) const T, predicate: anytype) usize {
    if (!@hasDecl(@TypeOf(predicate), "predicate"))
        @compileError("Predicate is required to define fn predicate(@This(), T) bool");

    var min: usize = 0;
    var max: usize = haystack.len;
    while (min < max) {
        const index = (min + max) / 2;
        const curr = haystack[index];
        if (predicate.predicate(curr)) {
            min = index + 1;
        } else {
            max = index;
        }
    }
    return min;
}

/// Linear search
pub fn linearSearch(comptime T: type, haystack: []align(1) const T, predicate: anytype) usize {
    if (!@hasDecl(@TypeOf(predicate), "predicate"))
        @compileError("Predicate is required to define fn predicate(@This(), T) bool");

    var i: usize = 0;
    while (i < haystack.len) : (i += 1) {
        if (predicate.predicate(haystack[i])) break;
    }
    return i;
}

test {
    std.testing.refAllDeclsRecursive(Zld);
}

const std = @import("std");
const assert = std.debug.assert;
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
const ThreadPool = std.Thread.Pool;
const Zld = @This();
