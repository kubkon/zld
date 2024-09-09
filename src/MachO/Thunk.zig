value: u64 = 0,
out_n_sect: u8 = 0,
symbols: std.AutoArrayHashMapUnmanaged(MachO.Ref, void) = .{},

pub fn deinit(thunk: *Thunk, allocator: Allocator) void {
    thunk.symbols.deinit(allocator);
}

pub fn size(thunk: Thunk) usize {
    return thunk.symbols.keys().len * trampoline_size;
}

pub fn getAddress(thunk: Thunk, macho_file: *MachO) u64 {
    const header = macho_file.sections.items(.header)[thunk.out_n_sect];
    return header.addr + thunk.value;
}

pub fn getTargetAddress(thunk: Thunk, ref: MachO.Ref, macho_file: *MachO) u64 {
    return thunk.getAddress(macho_file) + thunk.symbols.getIndex(ref).? * trampoline_size;
}

pub fn write(thunk: Thunk, macho_file: *MachO, writer: anytype) !void {
    for (thunk.symbols.keys(), 0..) |ref, i| {
        const sym = ref.getSymbol(macho_file).?;
        const saddr = thunk.getAddress(macho_file) + i * trampoline_size;
        const taddr = sym.getAddress(.{}, macho_file);
        const pages = try aarch64.calcNumberOfPages(@intCast(saddr), @intCast(taddr));
        try writer.writeInt(u32, aarch64.Instruction.adrp(.x16, pages).toU32(), .little);
        const off: u12 = @truncate(taddr);
        try writer.writeInt(u32, aarch64.Instruction.add(.x16, .x16, off, false).toU32(), .little);
        try writer.writeInt(u32, aarch64.Instruction.br(.x16).toU32(), .little);
    }
}

pub fn isReachable(atom: *const Atom, rel: Relocation, macho_file: *MachO) bool {
    const target = rel.getTargetSymbol(atom.*, macho_file);
    if (target.getSectionFlags().stubs or target.getSectionFlags().objc_stubs) return false;
    if (atom.out_n_sect != target.getOutputSectionIndex(macho_file)) return false;
    const target_atom = target.getAtom(macho_file).?;
    if (target_atom.value == @as(u64, @bitCast(@as(i64, -1)))) return false;
    const saddr = @as(i64, @intCast(atom.getAddress(macho_file))) + @as(i64, @intCast(rel.offset - atom.off));
    const taddr: i64 = @intCast(rel.getTargetAddress(atom.*, macho_file));
    _ = math.cast(i28, taddr + rel.addend - saddr) orelse return false;
    return true;
}

pub fn format(
    thunk: Thunk,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = thunk;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format Thunk directly");
}

pub fn fmt(thunk: Thunk, macho_file: *MachO) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .thunk = thunk,
        .macho_file = macho_file,
    } };
}

const FormatContext = struct {
    thunk: Thunk,
    macho_file: *MachO,
};

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const thunk = ctx.thunk;
    const macho_file = ctx.macho_file;
    try writer.print("@{x} : size({x})\n", .{ thunk.value, thunk.size() });
    for (thunk.symbols.keys()) |ref| {
        const sym = ref.getSymbol(macho_file).?;
        try writer.print("  {} : {s} : @{x}\n", .{ ref, sym.getName(macho_file), sym.value });
    }
}

const trampoline_size = 3 * @sizeOf(u32);

pub const Index = u32;

const aarch64 = @import("../aarch64.zig");
const assert = std.debug.assert;
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
const Thunk = @This();
