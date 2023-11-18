pub const GotSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
    needs_rela: bool = false,

    pub const Index = u32;

    pub fn deinit(got: *GotSection, allocator: Allocator) void {
        got.symbols.deinit(allocator);
    }

    pub fn addSymbol(got: *GotSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.allocator;
        const index = @as(Index, @intCast(got.symbols.items.len));
        const entry = try got.symbols.addOne(gpa);
        entry.* = sym_index;
        const symbol = macho_file.getSymbol(sym_index);
        if (symbol.flags.import)
            got.needs_rela = true;
        if (symbol.getExtra(macho_file)) |extra| {
            var new_extra = extra;
            new_extra.got = index;
            symbol.setExtra(new_extra, macho_file);
        } else try symbol.addExtra(.{ .got = index }, macho_file);
    }

    pub fn getAddress(got: GotSection, index: Index, macho_file: *MachO) u64 {
        assert(index < got.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.got_sect_index.?];
        return header.addr + index * @sizeOf(u64);
    }

    const FormatCtx = struct {
        got: GotSection,
        macho_file: *MachO,
    };

    pub fn fmt(got: GotSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .got = got, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.got.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.getSymbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.getGotAddress(ctx.macho_file),
                entry,
                symbol.getAddress(ctx.macho_file),
                symbol.getName(ctx.macho_file),
            });
        }
    }
};

const assert = std.debug.assert;
const std = @import("std");

const Allocator = std.mem.Allocator;
const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
