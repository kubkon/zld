const StringTable = @This();

const std = @import("std");
const log = std.log.scoped(.string_table);
const mem = std.mem;

const Allocator = mem.Allocator;
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;

buffer: std.ArrayListUnmanaged(u8) = .{},
table: std.HashMapUnmanaged(u32, bool, StringIndexContext, std.hash_map.default_max_load_percentage) = .{},

pub fn deinit(self: *StringTable, gpa: Allocator) void {
    self.buffer.deinit(gpa);
    self.table.deinit(gpa);
}

pub fn toOwnedSlice(self: *StringTable, gpa: Allocator) []const u8 {
    const result = self.buffer.toOwnedSlice(gpa);
    self.table.clearRetainingCapacity();
    return result;
}

pub const PrunedResult = struct {
    buffer: []const u8,
    idx_map: std.AutoHashMap(u32, u32),
};

pub fn toPrunedResult(self: *StringTable, gpa: Allocator) !PrunedResult {
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensureTotalCapacity(self.buffer.items.len);
    buffer.appendAssumeCapacity(0);

    var idx_map = std.AutoHashMap(u32, u32).init(gpa);
    errdefer idx_map.deinit();
    try idx_map.ensureTotalCapacity(self.table.count());

    var it = self.table.iterator();
    while (it.next()) |entry| {
        const off = entry.key_ptr.*;
        const save = entry.value_ptr.*;
        if (!save) continue;
        const new_off = @intCast(u32, buffer.items.len);
        buffer.appendSliceAssumeCapacity(self.getAssumeExists(off));
        idx_map.putAssumeCapacityNoClobber(off, new_off);
    }

    self.buffer.clearRetainingCapacity();
    self.table.clearRetainingCapacity();

    return PrunedResult{
        .buffer = buffer.toOwnedSlice(),
        .idx_map = idx_map,
    };
}

pub fn insert(self: *StringTable, gpa: Allocator, string: []const u8) !u32 {
    const gop = try self.table.getOrPutContextAdapted(gpa, @as([]const u8, string), StringIndexAdapter{
        .bytes = &self.buffer,
    }, StringIndexContext{
        .bytes = &self.buffer,
    });
    if (gop.found_existing) {
        const off = gop.key_ptr.*;
        gop.value_ptr.* = true;
        log.debug("reusing string '{s}' at offset 0x{x}", .{ string, off });
        return off;
    }

    try self.buffer.ensureUnusedCapacity(gpa, string.len + 1);
    const new_off = @intCast(u32, self.buffer.items.len);

    log.debug("writing new string '{s}' at offset 0x{x}", .{ string, new_off });

    self.buffer.appendSliceAssumeCapacity(string);
    self.buffer.appendAssumeCapacity(0);

    gop.key_ptr.* = new_off;
    gop.value_ptr.* = true;

    return new_off;
}

pub fn delete(self: *StringTable, string: []const u8) void {
    const value_ptr = self.table.getPtrAdapted(@as([]const u8, string), StringIndexAdapter{
        .bytes = &self.buffer,
    }) orelse return;
    value_ptr.* = false;

    log.debug("marked '{s}' for deletion", .{string});
}

pub fn get(self: StringTable, off: u32) ?[]const u8 {
    if (off >= self.buffer.items.len) return null;
    return mem.sliceTo(@ptrCast([*:0]const u8, self.buffer.items.ptr + off), 0);
}

pub fn getAssumeExists(self: StringTable, off: u32) []const u8 {
    return self.get(off) orelse unreachable;
}
