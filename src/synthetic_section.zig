pub fn SyntheticSection(comptime Entry: type, comptime Ctx: anytype, comptime opts: struct {
    entry_size: comptime_int,
    log_scope: @Type(.EnumLiteral) = .synthetic_section,
    baseAddrFn: fn (ctx: Ctx) u64,
    writeFn: fn (ctx: Ctx, entry: Entry, writer: anytype) anyerror!void,
}) type {
    const log = std.log.scoped(opts.log_scope);
    return struct {
        entries: std.ArrayListUnmanaged(Entry) = .{},
        lookup: std.AutoHashMapUnmanaged(Entry, Index) = .{},

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.entries.deinit(allocator);
            self.lookup.deinit(allocator);
        }

        fn addOne(self: *Self, allocator: Allocator) Allocator.Error!Index {
            try self.entries.ensureUnusedCapacity(allocator, 1);
            log.debug("allocating entry at index {d}", .{self.entries.items.len});
            const index = @intCast(u32, self.entries.items.len);
            _ = self.entries.addOneAssumeCapacity();
            return index;
        }

        const GetOrCreateResult = struct {
            found_existing: bool,
            value: Index,
        };

        pub fn getOrCreate(self: *Self, allocator: Allocator, entry: Entry) Allocator.Error!GetOrCreateResult {
            const gop = try self.lookup.getOrPut(allocator, entry);
            if (!gop.found_existing) {
                const index = try self.addOne(allocator);
                self.entries.items[index] = entry;
                gop.value_ptr.* = index;
            }
            return .{
                .found_existing = gop.found_existing,
                .value = gop.value_ptr.*,
            };
        }

        pub fn count(self: Self) usize {
            return self.entries.items.len;
        }

        pub fn size(self: Self) usize {
            return self.count() * opts.entry_size;
        }

        pub fn getAddress(self: Self, entry: Entry, ctx: Ctx) ?u64 {
            const base_addr = opts.baseAddrFn(ctx);
            const index = self.lookup.get(entry) orelse return null;
            return base_addr + index * opts.entry_size;
        }

        pub fn write(self: Self, ctx: Ctx, writer: anytype) !void {
            for (self.entries.items) |entry| {
                try opts.writeFn(ctx, entry, writer);
            }
        }

        pub fn format(
            self: Self,
            comptime unused_format_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            comptime assert(unused_format_string.len == 0);
            try writer.print("{s}:\n", .{@tagName(opts.log_scope)});
            for (self.entries.items, 0..) |entry, i| {
                try writer.print("  {d} => {}\n", .{ i, entry });
            }
        }

        const Self = @This();
        pub const Index = u32;
    };
}

const std = @import("std");
const assert = std.debug.assert;

const Allocator = std.mem.Allocator;
