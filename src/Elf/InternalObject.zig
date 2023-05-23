index: File.Index,
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
symbols: std.ArrayListUnmanaged(u32) = .{},
alive: bool = true,

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    self.symtab.deinit(allocator);
    self.symbols.deinit(allocator);
}

pub fn addSyntheticGlobal(self: *InternalObject, name: [:0]const u8, elf_file: *Elf) !u32 {
    const gpa = elf_file.base.allocator;
    try self.symtab.ensureUnusedCapacity(gpa, 1);
    try self.symbols.ensureUnusedCapacity(gpa, 1);
    self.symtab.appendAssumeCapacity(.{
        .st_name = try elf_file.string_intern.insert(gpa, name),
        .st_info = elf.STB_GLOBAL << 4,
        .st_other = @enumToInt(elf.STV.HIDDEN),
        .st_shndx = elf.SHN_ABS,
        .st_value = 0,
        .st_size = 0,
    });
    const gop = try elf_file.getOrCreateGlobal(name);
    self.symbols.addOneAssumeCapacity().* = gop.index;
    return gop.index;
}

pub fn resolveSymbols(self: *InternalObject, elf_file: *Elf) void {
    for (self.symbols.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, i);
        const this_sym = self.symtab.items[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getSymbol(index);
        if (self.asFile().getSymbolRank(this_sym, false) < global.getSymbolRank(elf_file)) {
            global.* = .{
                .value = 0,
                .name = global.name,
                .atom = 0,
                .file = self.index,
                .sym_idx = sym_idx,
            };
        }
    }
}

pub fn resetGlobals(self: *InternalObject, elf_file: *Elf) void {
    for (self.symbols.items) |index| {
        const global = elf_file.getSymbol(index);
        const name = global.name;
        global.* = .{};
        global.name = name;
    }
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

pub inline fn getGlobals(self: *InternalObject) []const u32 {
    return self.symbols.items;
}

pub fn fmtSymtab(self: *InternalObject, elf_file: *Elf) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .self = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    self: *InternalObject,
    elf_file: *Elf,
};

fn formatSymtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll("  globals\n");
    for (ctx.self.getGlobals()) |index| {
        const global = ctx.elf_file.getSymbol(index);
        try writer.print("    {}\n", .{global.fmt(ctx.elf_file)});
    }
}

const std = @import("std");
const elf = std.elf;

const Allocator = std.mem.Allocator;
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const InternalObject = @This();
const Object = @import("Object.zig");
