const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log.scoped(.dyld_info);
const macho = std.macho;
const testing = std.testing;

const Allocator = std.mem.Allocator;
const MachO = @import("../../MachO.zig");

pub fn Bind(comptime Ctx: type) type {
    return struct {
        entries: std.ArrayListUnmanaged(Entry) = .{},
        buffer: std.ArrayListUnmanaged(u8) = .{},

        const Self = @This();

        const Entry = struct {
            target: MachO.SymbolWithLoc,
            offset: u64,
            segment_id: u8,
            addend: i64,

            pub fn lessThan(ctx: *const Ctx, entry: Entry, other: Entry) bool {
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

        pub fn finalize(self: *Self, gpa: Allocator, ctx: *const Ctx) !void {
            if (self.entries.items.len == 0) return;

            const writer = self.buffer.writer(gpa);

            std.sort.sort(Entry, self.entries.items, ctx, Entry.lessThan);

            var start: usize = 0;
            const first = self.entries.items[start];
            var seg_id = first.segment_id;
            var target = first.target;

            try setSegmentOffset(seg_id, first.offset, writer);

            for (self.entries.items) |entry, i| {
                if (seg_id != seg_id) {
                    try setSegmentOffset(seg_id, entry.offset, writer);
                }
                if (!target.eql(entry.target)) {
                    try finalizeTarget(self.entries.items[start..i], ctx, writer);
                    start = i;
                }
            }

            try finalizeTarget(self.entries.items[start..], ctx, writer);
            try done(writer);
        }

        fn finalizeTarget(entries: []const Entry, ctx: *const Ctx, writer: anytype) !void {
            if (entries.len == 0) return;

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
            if (addend > 0) {
                try setAddend(addend, writer);
            }

            var offset: i64 = @intCast(i64, first.offset);
            var count: usize = 0;
            var skip: i64 = 0;
            var state: enum {
                start,
                single,
                times_skip,
            } = .start;

            var i: usize = 0;
            while (i < entries.len) : (i += 1) {
                log.debug("{x}, {d}, {x}, {?x}, {s}", .{ offset, count, skip, addend, @tagName(state) });
                const current = entries[i];
                log.debug("  => {x}", .{current.offset});
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
        }

        fn setSegmentOffset(segment_id: u8, offset: u64, writer: anytype) !void {
            log.debug(">>> set segment: {d} and offset: {x}", .{ segment_id, offset });
            try writer.writeByte(macho.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | @truncate(u4, segment_id));
            try std.leb.writeULEB128(writer, offset);
        }

        fn setSymbol(name: []const u8, flags: u8, writer: anytype) !void {
            log.debug(">>> set symbol: {s} with flags: {x}", .{ name, flags });
            try writer.writeByte(macho.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | @truncate(u4, flags));
            try writer.writeAll(name);
            try writer.writeByte(0);
        }

        fn setTypePointer(writer: anytype) !void {
            log.debug(">>> set type: {d}", .{macho.BIND_TYPE_POINTER});
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
                log.debug(">>> set dylib special: {d}", .{ordinal});
                const cast = @bitCast(u16, ordinal);
                try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | @truncate(u4, cast));
            } else {
                const cast = @bitCast(u16, ordinal);
                log.debug(">>> set dylib ordinal: {d}", .{ordinal});
                if (cast <= 0xf) {
                    try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | @truncate(u4, cast));
                } else {
                    try writer.writeByte(macho.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
                    try std.leb.writeULEB128(writer, cast);
                }
            }
        }

        fn setAddend(addend: i64, writer: anytype) !void {
            log.debug(">>> set addend: {x}", .{addend});
            try writer.writeByte(macho.BIND_OPCODE_SET_ADDEND_SLEB);
            try std.leb.writeILEB128(writer, addend);
        }

        fn bind(writer: anytype) !void {
            log.debug(">>> bind", .{});
            try writer.writeByte(macho.BIND_OPCODE_DO_BIND);
        }

        fn bindAddAddr(addr: u64, writer: anytype) !void {
            log.debug(">>> bind with add: {x}", .{addr});
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
            log.debug(">>> bind with count: {d} and skip: {x}", .{ count, skip });
            try writer.writeByte(macho.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
            try std.leb.writeULEB128(writer, count);
            try std.leb.writeULEB128(writer, @intCast(u64, skip));
        }

        fn addAddr(addr: i64, writer: anytype) !void {
            log.debug(">>> add: {x}", .{addr});
            try writer.writeByte(macho.BIND_OPCODE_ADD_ADDR_ULEB);
            try std.leb.writeULEB128(writer, @bitCast(u64, addr));
        }

        fn done(writer: anytype) !void {
            log.debug(">>> done", .{});
            try writer.writeByte(macho.BIND_OPCODE_DONE);
        }

        pub fn write(self: Self, writer: anytype) !void {
            if (self.size() == 0) return;
            try writer.writeAll(self.buffer.items);
        }
    };
}
