index: File.Index,
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
symbols: std.ArrayListUnmanaged(u32) = .{},
alive: bool = true,

output_symtab_size: Elf.SymtabSize = .{},

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
    const off = try elf_file.internString("{s}", .{name});
    const gop = try elf_file.getOrCreateGlobal(off);
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

pub fn calcSymtabSize(self: *InternalObject, elf_file: *Elf) !void {
    if (elf_file.options.strip_all) return;

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        if (global.getFile(elf_file)) |file| if (file.getIndex() != self.index) continue;
        global.output_symtab = true;
        self.output_symtab_size.nlocals += 1;
        self.output_symtab_size.strsize += @intCast(u32, global.getName(elf_file).len + 1);
    }
}

pub fn writeSymtab(self: *InternalObject, elf_file: *Elf, ctx: Elf.WriteSymtabCtx) !void {
    if (elf_file.options.strip_all) return;

    const gpa = elf_file.base.allocator;

    var ilocal = ctx.ilocal;
    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        if (global.getFile(elf_file)) |file| if (file.getIndex() != self.index) continue;
        if (!global.output_symtab) continue;
        const st_name = try ctx.strtab.insert(gpa, global.getName(elf_file));
        ctx.symtab[ilocal] = global.asElfSym(st_name, elf_file);
        ilocal += 1;
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
