index: File.Index,

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    self.symbols.deinit(allocator);
    self.strtab.deinit(allocator);
}

pub fn addSymbol(self: *InternalObject, name: [:0]const u8, coff_file: *Coff) !Symbol.Index {
    const gpa = coff_file.base.allocator;
    try self.symbols.ensureUnusedCapacity(gpa, 1);
    const off = try coff_file.string_intern.insert(gpa, name);
    const gop = try coff_file.getOrCreateGlobal(off);
    self.symbols.addOneAssumeCapacity().* = gop.index;
    const sym = coff_file.getSymbol(gop.index);
    sym.file = self.index;
    sym.value = 0;
    sym.atom = 0;
    sym.coff_sym_idx = 0;
    sym.flags = .{ .global = true };
    return gop.index;
}

fn insertString(self: *InternalObject, allocator: Allocator, name: [:0]const u8) error{OutOfMemory}!u32 {
    const off: u32 = @intCast(self.strtab.items.len);
    try self.strtab.ensureUnusedCapacity(allocator, name.len + 1);
    self.strtab.appendSliceAssumeCapacity(name);
    self.strtab.appendAssumeCapacity(0);
    return off;
}

pub fn getString(self: InternalObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

const FormatContext = struct {
    self: *InternalObject,
    coff_file: *Coff,
};

pub fn fmtSymbols(self: *InternalObject, coff_file: *Coff) std.fmt.Formatter(formatSymbols) {
    return .{ .data = .{
        .self = self,
        .coff_file = coff_file,
    } };
}

fn formatSymbols(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll("  symbols\n");
    for (ctx.self.symbols.items) |index| {
        const sym = ctx.coff_file.getSymbol(index);
        try writer.print("    {}\n", .{sym.fmt(ctx.coff_file)});
    }
}

const assert = std.debug.assert;
const mem = std.mem;
const std = @import("std");

const Allocator = mem.Allocator;
const Coff = @import("../Coff.zig");
const File = @import("file.zig").File;
const InternalObject = @import("InternalObject.zig");
const Symbol = @import("Symbol.zig");
