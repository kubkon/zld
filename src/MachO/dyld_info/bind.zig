const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log.scoped(.dyld_info);
const macho = std.macho;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub fn Bind(comptime Ctx: type, comptime Target: type) type {
    return struct {
        entries: std.ArrayListUnmanaged(Entry) = .{},
        buffer: std.ArrayListUnmanaged(u8) = .{},

        const Self = @This();

        const Entry = struct {
            target: Target,
            offset: u64,
            segment_id: u8,
            addend: i64,

            pub fn lessThan(ctx: Ctx, entry: Entry, other: Entry) bool {
                if (entry.segment_id == other.segment_id) {
                    if (entry.target.eql(other.target)) {
                        return entry.offset < other.offset;
                    }
                    const entry_name = ctx.getSymbolName(entry.target);
                    const other_name = ctx.getSymbolName(other.target);
                    return std.mem.lessThan(u8, entry_name, other_name);
                }
                return entry.segment_id < other.segment_id;
            }
        };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
            self.buffer.deinit(gpa);
        }

        pub fn size(self: Self) u64 {
            return @intCast(u64, self.buffer.items.len);
        }

        pub fn finalize(self: *Self, gpa: Allocator, ctx: Ctx) !void {
            if (self.entries.items.len == 0) return;

            const writer = self.buffer.writer(gpa);

            std.sort.sort(Entry, self.entries.items, ctx, Entry.lessThan);

            var start: usize = 0;
            var seg_id: ?u8 = null;
            for (self.entries.items) |entry, i| {
                if (seg_id != null and seg_id.? == entry.segment_id) continue;
                try finalizeSegment(self.entries.items[start..i], ctx, writer);
                seg_id = entry.segment_id;
                start = i;
            }

            try finalizeSegment(self.entries.items[start..], ctx, writer);
            try done(writer);
        }

        fn finalizeSegment(entries: []const Entry, ctx: Ctx, writer: anytype) !void {
            if (entries.len == 0) return;

            const seg_id = entries[0].segment_id;
            try setSegmentOffset(seg_id, entries[0].offset, writer);

            var start: usize = 0;
            var offset = @intCast(i64, entries[0].offset);
            var target: ?Target = null;
            for (entries) |entry, i| {
                if (target != null and target.?.eql(entry.target)) continue;
                offset = try finalizeTarget(entries[start..i], offset, ctx, writer);
                target = entry.target;
                start = i;
            }

            _ = try finalizeTarget(entries[start..], offset, ctx, writer);
        }

        fn finalizeTarget(entries: []const Entry, base_offset: i64, ctx: Ctx, writer: anytype) !i64 {
            if (entries.len == 0) return base_offset;

            const first = entries[0];
            const sym = ctx.getSymbol(first.target);
            const name = ctx.getSymbolName(first.target);
            const flags: u8 = if (sym.weakRef())
                macho.BIND_SYMBOL_FLAGS_WEAK_IMPORT
            else
                0;
            const ordinal = @divTrunc(@bitCast(i16, sym.n_desc), macho.N_SYMBOL_RESOLVER);

            try setSymbol(name, flags, writer);
            try setTypePointer(writer);
            try setDylibOrdinal(ordinal, writer);

            var addend = first.addend;
            try setAddend(addend, writer);

            var offset: i64 = base_offset;
            var count: usize = 0;
            var skip: i64 = 0;
            var state: enum {
                start,
                single,
                times_skip,
            } = .start;

            var i: usize = 0;
            while (i < entries.len) : (i += 1) {
                log.warn("{x}, {d}, {x}, {?x}, {s}", .{ offset, count, skip, addend, @tagName(state) });
                const current = entries[i];
                log.warn("  => {x}", .{current.offset});
                switch (state) {
                    .start => {
                        if (current.addend != addend) {
                            addend = current.addend;
                            try setAddend(addend, writer);
                        }
                        const delta = @intCast(i64, current.offset) - offset;
                        if (delta != 0) {
                            try addAddr(delta, writer);
                            offset += delta;
                        }
                        state = .single;
                        offset += @sizeOf(u64);
                        count = 1;
                    },
                    .single => {
                        const delta = @intCast(i64, current.offset) - offset;
                        if (delta == 0) {
                            try bind(writer);
                            state = .start;
                        } else {
                            state = .times_skip;
                            skip = delta;
                            offset += skip;
                        }
                        i -= 1;
                    },
                    .times_skip => {
                        const delta = @intCast(i64, current.offset) - offset;
                        if (delta == 0) {
                            count += 1;
                            offset += @sizeOf(u64) + skip;
                        } else {
                            try bindTimesSkip(count, skip, writer);
                            state = .start;
                            i -= 1;
                        }
                    },
                }
            }

            switch (state) {
                .start => unreachable,
                .single => {
                    try bind(writer);
                },
                .times_skip => {
                    try bindTimesSkip(count, skip, writer);
                },
            }

            return offset;
        }

        fn setSegmentOffset(segment_id: u8, offset: u64, writer: anytype) !void {
            log.warn(">>> set segment: {d} and offset: {x}", .{ segment_id, offset });
            try writer.writeByte(macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, segment_id));
            try std.leb.writeULEB128(writer, offset);
        }

        fn setSymbol(name: []const u8, flags: u8, writer: anytype) !void {
            log.warn(">>> set symbol: {s} with flags: {x}", .{ name, flags });
            try writer.writeByte(macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | @truncate(u4, flags));
            try writer.writeAll(name);
            try writer.writeByte(0);
        }

        fn setTypePointer(writer: anytype) !void {
            log.warn(">>> set type: {d}", .{macho.BIND_TYPE_POINTER});
            try writer.writeByte(macho.BIND_OPCODE_SET_TYPE_IMM | @truncate(u4, macho.BIND_TYPE_POINTER));
        }

        fn setDylibOrdinal(ordinal: i16, writer: anytype) !void {
            if (ordinal <= 0) {
                switch (ordinal) {
                    macho.BIND_SPECIAL_DYLIB_SELF,
                    macho.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE,
                    macho.BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
                    => {},
                    else => unreachable, // Invalid dylib special binding
                }
                log.warn(">>> set dylib special: {d}", .{ordinal});
                const cast = @bitCast(u16, ordinal);
                try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | @truncate(u4, cast));
            } else {
                const cast = @bitCast(u16, ordinal);
                log.warn(">>> set dylib ordinal: {d}", .{ordinal});
                if (cast <= 0xf) {
                    try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | @truncate(u4, cast));
                } else {
                    try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
                    try std.leb.writeULEB128(writer, cast);
                }
            }
        }

        fn setAddend(addend: i64, writer: anytype) !void {
            log.warn(">>> set addend: {x}", .{addend});
            try writer.writeByte(macho.BIND_OPCODE_SET_ADDEND_SLEB);
            try std.leb.writeILEB128(writer, addend);
        }

        fn bind(writer: anytype) !void {
            log.warn(">>> bind", .{});
            try writer.writeByte(macho.BIND_OPCODE_DO_BIND);
        }

        fn bindAddAddr(addr: u64, writer: anytype) !void {
            log.warn(">>> bind with add: {x}", .{addr});
            if (std.mem.isAligned(addr, @sizeOf(u64))) {
                const imm = @divExact(addr, @sizeOf(u64));
                if (imm <= 0xf) {
                    try writer.writeByte(
                        macho.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED | @truncate(u4, imm),
                    );
                    return;
                }
            }
            try writer.writeByte(macho.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB);
            try std.leb.writeULEB128(writer, addr);
        }

        fn bindTimesSkip(count: usize, skip: i64, writer: anytype) !void {
            log.warn(">>> bind with count: {d} and skip: {x}", .{ count, skip });
            try writer.writeByte(macho.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
            try std.leb.writeULEB128(writer, count);
            try std.leb.writeULEB128(writer, @intCast(u64, skip));
        }

        fn addAddr(addr: i64, writer: anytype) !void {
            log.warn(">>> add: {x}", .{addr});
            try writer.writeByte(macho.BIND_OPCODE_ADD_ADDR_ULEB);
            try std.leb.writeULEB128(writer, @bitCast(u64, addr));
        }

        fn done(writer: anytype) !void {
            log.warn(">>> done", .{});
            try writer.writeByte(macho.BIND_OPCODE_DONE);
        }

        pub fn write(self: Self, writer: anytype) !void {
            if (self.size() == 0) return;
            try writer.writeAll(self.buffer.items);
        }
    };
}

const TestContext = struct {
    symbols: std.ArrayListUnmanaged(macho.nlist_64) = .{},
    strtab: std.ArrayListUnmanaged(u8) = .{},

    const Target = struct {
        index: u32,

        fn eql(this: Target, other: Target) bool {
            return this.index == other.index;
        }
    };

    fn deinit(ctx: *TestContext, gpa: Allocator) void {
        ctx.symbols.deinit(gpa);
        ctx.strtab.deinit(gpa);
    }

    fn addSymbol(ctx: *TestContext, gpa: Allocator, name: []const u8, ordinal: i16, flags: u16) !void {
        const n_strx = try ctx.addString(gpa, name);
        var n_desc = @bitCast(u16, ordinal * macho.N_SYMBOL_RESOLVER);
        n_desc |= flags;
        try ctx.symbols.append(gpa, .{
            .n_value = 0,
            .n_strx = n_strx,
            .n_desc = n_desc,
            .n_type = macho.N_EXT,
            .n_sect = 0,
        });
    }

    fn addString(ctx: *TestContext, gpa: Allocator, name: []const u8) !u32 {
        const n_strx = @intCast(u32, ctx.strtab.items.len);
        try ctx.strtab.appendSlice(gpa, name);
        try ctx.strtab.append(gpa, 0);
        return n_strx;
    }

    fn getSymbol(ctx: TestContext, target: Target) macho.nlist_64 {
        return ctx.symbols.items[target.index];
    }

    fn getSymbolName(ctx: TestContext, target: Target) []const u8 {
        const sym = ctx.getSymbol(target);
        assert(sym.n_strx < ctx.strtab.items.len);
        return std.mem.sliceTo(@ptrCast([*:0]const u8, ctx.strtab.items.ptr + sym.n_strx), 0);
    }
};

fn generateTestContext() !TestContext {
    const gpa = testing.allocator;
    var ctx = TestContext{};
    try ctx.addSymbol(gpa, "_import_1", 1, 0);
    try ctx.addSymbol(gpa, "_import_2", 1, 0);
    try ctx.addSymbol(gpa, "_import_3", 1, 0);
    try ctx.addSymbol(gpa, "_import_4", 2, 0);
    try ctx.addSymbol(gpa, "_import_5_weak", 2, macho.N_WEAK_REF);
    try ctx.addSymbol(gpa, "_import_6", 2, 0);
    return ctx;
}

test "bind - no entries" {
    const gpa = testing.allocator;

    var test_context = try generateTestContext();
    defer test_context.deinit(gpa);

    var bind = Bind(TestContext, TestContext.Target){};
    defer bind.deinit(gpa);

    try bind.finalize(gpa, test_context);
    try testing.expectEqual(@as(u64, 0), bind.size());
}

test "bind - single entry" {
    const gpa = testing.allocator;

    var test_context = try generateTestContext();
    defer test_context.deinit(gpa);

    var bind = Bind(TestContext, TestContext.Target){};
    defer bind.deinit(gpa);

    try bind.entries.append(gpa, .{
        .offset = 0x10,
        .segment_id = 1,
        .target = TestContext.Target{ .index = 0 },
        .addend = 0,
    });
    try bind.finalize(gpa, test_context);
    try testing.expectEqualSlices(u8, &[_]u8{
        macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x10,
        macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
        0x5f,
        0x69,
        0x6d,
        0x70,
        0x6f,
        0x72,
        0x74,
        0x5f,
        0x31,
        0x0,
        macho.BIND_OPCODE_SET_TYPE_IMM | 1,
        macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        macho.BIND_OPCODE_DO_BIND,
        macho.BIND_OPCODE_DONE,
    }, bind.buffer.items);
}

test "bind - multiple occurrences within the same segment" {
    const gpa = testing.allocator;

    var test_context = try generateTestContext();
    defer test_context.deinit(gpa);

    var bind = Bind(TestContext, TestContext.Target){};
    defer bind.deinit(gpa);

    try bind.entries.append(gpa, .{
        .offset = 0x10,
        .segment_id = 1,
        .target = TestContext.Target{ .index = 0 },
        .addend = 0,
    });
    try bind.entries.append(gpa, .{
        .offset = 0x18,
        .segment_id = 1,
        .target = TestContext.Target{ .index = 0 },
        .addend = 0,
    });
    try bind.entries.append(gpa, .{
        .offset = 0x20,
        .segment_id = 1,
        .target = TestContext.Target{ .index = 0 },
        .addend = 0,
    });
    try bind.entries.append(gpa, .{
        .offset = 0x28,
        .segment_id = 1,
        .target = TestContext.Target{ .index = 0 },
        .addend = 0,
    });

    try bind.finalize(gpa, test_context);
    try testing.expectEqualSlices(u8, &[_]u8{
        macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 1,
        0x10,
        macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
        0x5f,
        0x69,
        0x6d,
        0x70,
        0x6f,
        0x72,
        0x74,
        0x5f,
        0x31,
        0x0,
        macho.BIND_OPCODE_SET_TYPE_IMM | 1,
        macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        macho.BIND_OPCODE_DO_BIND,
        macho.BIND_OPCODE_DO_BIND,
        macho.BIND_OPCODE_DO_BIND,
        macho.BIND_OPCODE_DO_BIND,
        macho.BIND_OPCODE_DONE,
    }, bind.buffer.items);
}
