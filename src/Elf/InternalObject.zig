symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
globals: std.ArrayListUnmanaged(u32) = .{},

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    self.symtab.deinit(allocator);
    self.globals.deinit(allocator);
}

pub fn addSyntheticGlobal(self: *InternalObject, name: [:0]const u8, elf_file: *Elf) !u32 {
    const gpa = elf_file.base.allocator;
    const sym_idx = @intCast(u32, self.symtab.items.len);
    try self.symtab.ensureUnusedCapacity(gpa, 1);
    try self.globals.ensureUnusedCapacity(gpa, 1);
    self.symtab.appendAssumeCapacity(.{
        .st_name = try elf_file.string_intern.insert(gpa, name),
        .st_info = elf.STB_GLOBAL << 4,
        .st_other = @enumToInt(elf.STV.HIDDEN),
        .st_shndx = elf.SHN_ABS,
        .st_value = 0,
        .st_size = 0,
    });
    const gop = try elf_file.getOrCreateGlobal(name);
    if (!gop.found_existing) {
        const global = elf_file.getGlobal(gop.index);
        global.* = .{
            .value = 0,
            .name = global.name,
            .atom = 0,
            .file = null,
            .sym_idx = sym_idx,
        };
    }
    self.globals.addOneAssumeCapacity().* = gop.index;
    return gop.index;
}

pub fn resolveSymbols(self: *InternalObject, elf_file: *Elf) !void {
    for (self.globals.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, i);
        const this_sym = self.symtab.items[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getGlobal(index);
        if (Object.getSymbolRank(this_sym) < global.getSymbolRank(elf_file)) {
            global.* = .{
                .value = 0,
                .name = global.name,
                .atom = 0,
                .file = null,
                .sym_idx = sym_idx,
            };
        }
    }
}

pub fn fmtSymtab(self: InternalObject, elf_file: *Elf) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .self = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    self: InternalObject,
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
    for (ctx.self.globals.items) |index| {
        const global = ctx.elf_file.getGlobal(index);
        try writer.print("    {}\n", .{global.fmt(ctx.elf_file)});
    }
}

const std = @import("std");
const elf = std.elf;

const Allocator = std.mem.Allocator;
const Elf = @import("../Elf.zig");
const InternalObject = @This();
const Object = @import("Object.zig");
