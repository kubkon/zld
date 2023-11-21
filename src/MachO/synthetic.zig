pub const GotSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
    needs_rebase: bool = false,
    needs_bind: bool = false,

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
        if (symbol.flags.import) {
            got.needs_bind = true;
        } else {
            got.needs_rebase = true;
        }
        try symbol.addExtra(.{ .got = index }, macho_file);
    }

    pub fn getAddress(got: GotSection, index: Index, macho_file: *MachO) u64 {
        assert(index < got.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.got_sect_index.?];
        return header.addr + index * @sizeOf(u64);
    }

    pub fn size(got: GotSection) usize {
        return got.symbols.items.len * @sizeOf(u64);
    }

    pub fn addRebase(got: GotSection, macho_file: *MachO) !void {
        const gpa = macho_file.base.allocator;
        try macho_file.rebase.entries.ensureUnusedCapacity(gpa, got.symbols.items.len);

        const seg_id = macho_file.sections.items(.segment_id)[macho_file.got_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (got.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.getSymbol(sym_index);
            if (sym.flags.import) continue;
            const addr = got.getAddress(@intCast(idx), macho_file);
            macho_file.rebase.entries.appendAssumeCapacity(.{
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
            });
        }
    }

    pub fn addBind(got: GotSection, macho_file: *MachO) !void {
        const gpa = macho_file.base.allocator;
        try macho_file.bind.entries.ensureUnusedCapacity(gpa, got.symbols.items.len);

        const seg_id = macho_file.sections.items(.segment_id)[macho_file.got_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (got.symbols.items, 0..) |sym_index, idx| {
            const sym = macho_file.getSymbol(sym_index);
            if (!sym.flags.import) continue;
            const addr = got.getAddress(@intCast(idx), macho_file);
            macho_file.bind.entries.appendAssumeCapacity(.{
                .target = sym_index,
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
                .addend = 0,
            });
        }
    }

    pub fn write(got: GotSection, macho_file: *MachO, writer: anytype) !void {
        for (got.symbols.items) |sym_index| {
            const sym = macho_file.getSymbol(sym_index);
            const value = if (sym.flags.import) @as(u64, 0) else sym.getAddress(.{}, macho_file);
            try writer.writeInt(u64, value, .little);
        }
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
                symbol.getAddress(.{}, ctx.macho_file),
                symbol.getName(ctx.macho_file),
            });
        }
    }
};

pub const StubsSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub const Index = u32;

    pub fn deinit(stubs: *StubsSection, allocator: Allocator) void {
        stubs.symbols.deinit(allocator);
    }

    pub fn addSymbol(stubs: *StubsSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.allocator;
        const index = @as(Index, @intCast(stubs.symbols.items.len));
        const entry = try stubs.symbols.addOne(gpa);
        entry.* = sym_index;
        const symbol = macho_file.getSymbol(sym_index);
        try symbol.addExtra(.{ .stubs = index }, macho_file);
    }

    pub fn getAddress(stubs: StubsSection, index: Index, macho_file: *MachO) u64 {
        assert(index < stubs.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.stubs_sect_index.?];
        return header.addr + index * header.reserved2;
    }

    pub fn size(stubs: StubsSection, macho_file: *MachO) usize {
        const header = macho_file.sections.items(.header)[macho_file.stubs_sect_index.?];
        return stubs.symbols.items.len * header.reserved2;
    }

    const FormatCtx = struct {
        stubs: StubsSection,
        macho_file: *MachO,
    };

    pub fn fmt(stubs: StubsSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .stubs = stubs, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.stubs.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.getSymbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.getStubsAddress(ctx.macho_file),
                entry,
                symbol.getAddress(.{}, ctx.macho_file),
                symbol.getName(ctx.macho_file),
            });
        }
    }
};

pub const StubsHelperSection = struct {
    inline fn preambleSize(cpu_arch: std.Target.Cpu.Arch) usize {
        return switch (cpu_arch) {
            .x86_64 => 15,
            .aarch64 => 6 * @sizeOf(u32),
            else => 0,
        };
    }

    inline fn entrySize(cpu_arch: std.Target.Cpu.Arch) usize {
        return switch (cpu_arch) {
            .x86_64 => 10,
            .aarch64 => 3 * @sizeOf(u32),
            else => 0,
        };
    }

    pub fn size(stubs_helper: StubsHelperSection, macho_file: *MachO) usize {
        _ = stubs_helper;
        const cpu_arch = macho_file.options.cpu_arch.?;
        var s: usize = preambleSize(cpu_arch);
        for (macho_file.stubs.symbols.items) |_| {
            s += entrySize(cpu_arch);
        }
        return s;
    }
};

pub const LaSymbolPtrSection = struct {
    pub fn size(laptr: LaSymbolPtrSection, macho_file: *MachO) usize {
        _ = laptr;
        return macho_file.stubs.symbols.items.len * @sizeOf(u64);
    }

    pub fn addLazyBind(laptr: LaSymbolPtrSection, macho_file: *MachO) !void {
        _ = laptr;
        const gpa = macho_file.base.allocator;
        try macho_file.lazy_bind.entries.ensureUnusedCapacity(gpa, macho_file.stubs.symbols.items.len);

        const sect = macho_file.sections.items(.header)[macho_file.la_symbol_ptr_sect_index.?];
        const seg_id = macho_file.sections.items(.segment_id)[macho_file.la_symbol_ptr_sect_index.?];
        const seg = macho_file.segments.items[seg_id];

        for (macho_file.stubs.symbols.items, 0..) |sym_index, idx| {
            const addr = sect.addr + idx * @sizeOf(u64);
            macho_file.lazy_bind.entries.appendAssumeCapacity(.{
                .target = sym_index,
                .offset = addr - seg.vmaddr,
                .segment_id = seg_id,
                .addend = 0,
            });
        }
    }
};

pub const TlvPtrSection = struct {
    symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

    pub const Index = u32;

    pub fn deinit(tlv: *TlvPtrSection, allocator: Allocator) void {
        tlv.symbols.deinit(allocator);
    }

    pub fn addSymbol(tlv: *TlvPtrSection, sym_index: Symbol.Index, macho_file: *MachO) !void {
        const gpa = macho_file.base.allocator;
        const index = @as(Index, @intCast(tlv.symbols.items.len));
        const entry = try tlv.symbols.addOne(gpa);
        entry.* = sym_index;
        const symbol = macho_file.getSymbol(sym_index);
        try symbol.addExtra(.{ .tlv_ptr = index }, macho_file);
    }

    pub fn getAddress(tlv: TlvPtrSection, index: Index, macho_file: *MachO) u64 {
        assert(index < tlv.symbols.items.len);
        const header = macho_file.sections.items(.header)[macho_file.tlv_ptr_sect_index.?];
        return header.addr + index * @sizeOf(u64) * 3;
    }

    pub fn size(tlv: TlvPtrSection) usize {
        return tlv.symbols.items.len * @sizeOf(u64) * 3;
    }

    const FormatCtx = struct {
        tlv: TlvPtrSection,
        macho_file: *MachO,
    };

    pub fn fmt(tlv: TlvPtrSection, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{ .tlv = tlv, .macho_file = macho_file } };
    }

    pub fn format2(
        ctx: FormatCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        for (ctx.tlv.symbols.items, 0..) |entry, i| {
            const symbol = ctx.macho_file.getSymbol(entry);
            try writer.print("  {d}@0x{x} => {d}@0x{x} ({s})\n", .{
                i,
                symbol.getTlvPtrAddress(ctx.macho_file),
                entry,
                symbol.getAddress(.{}, ctx.macho_file),
                symbol.getName(ctx.macho_file),
            });
        }
    }
};

pub const RebaseSection = Rebase;
pub const BindSection = bind.Bind;
pub const LazyBindSection = bind.LazyBind;
pub const ExportTrieSection = Trie;

const assert = std.debug.assert;
const bind = @import("dyld_info/bind.zig");
const std = @import("std");

const Allocator = std.mem.Allocator;
const MachO = @import("../MachO.zig");
const Rebase = @import("dyld_info/Rebase.zig");
const Symbol = @import("Symbol.zig");
const Trie = @import("dyld_info/Trie.zig");
