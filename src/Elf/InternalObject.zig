index: File.Index,
symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},
symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
alive: bool = true,

output_symtab_ctx: Elf.SymtabCtx = .{},

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
        .st_other = @intFromEnum(elf.STV.HIDDEN),
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
    for (self.getGlobals(), 0..) |index, i| {
        const sym_idx = @as(Symbol.Index, @intCast(i));
        const this_sym = self.symtab.items[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getSymbol(index);
        if (self.asFile().getSymbolRank(this_sym, false) < global.getSymbolRank(elf_file)) {
            global.value = 0;
            global.atom = 0;
            global.file = self.index;
            global.sym_idx = sym_idx;
            global.ver_idx = elf_file.default_sym_version;
        }
    }
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

pub fn calcSymtabSize(self: *InternalObject, elf_file: *Elf) !void {
    if (elf_file.options.strip_all) return;

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        const file_ptr = global.getFile(elf_file) orelse continue;
        if (file_ptr.getIndex() != self.index) continue;
        global.flags.output_symtab = true;
        if (global.isLocal(elf_file)) {
            try global.setOutputSymtabIndex(self.output_symtab_ctx.nlocals, elf_file);
            self.output_symtab_ctx.nlocals += 1;
        } else {
            try global.setOutputSymtabIndex(self.output_symtab_ctx.nglobals, elf_file);
            self.output_symtab_ctx.nglobals += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(global.getName(elf_file).len + 1));
    }
}

pub fn writeSymtab(self: InternalObject, elf_file: *Elf) void {
    if (elf_file.options.strip_all) return;

    for (self.getGlobals()) |global_index| {
        const global = elf_file.getSymbol(global_index);
        const file_ptr = global.getFile(elf_file) orelse continue;
        if (file_ptr.getIndex() != self.index) continue;
        const idx = global.getOutputSymtabIndex(elf_file) orelse continue;
        const st_name = @as(u32, @intCast(elf_file.strtab.items.len));
        elf_file.strtab.appendSliceAssumeCapacity(global.getName(elf_file));
        elf_file.strtab.appendAssumeCapacity(0);
        const out_sym = &elf_file.symtab.items[idx];
        out_sym.st_name = st_name;
        global.setOutputSym(elf_file, out_sym);
    }
}

pub inline fn getGlobals(self: InternalObject) []const Symbol.Index {
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

const assert = std.debug.assert;
const elf = std.elf;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Elf = @import("../Elf.zig");
const File = @import("file.zig").File;
const InternalObject = @This();
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
