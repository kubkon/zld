index: File.Index,

symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

alive: bool = true,

output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
}

pub fn addSymbol(self: *InternalObject, name: [:0]const u8, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.allocator;
    const nlist_idx = try self.addNlist(gpa);
    const nlist = &self.symtab.items[nlist_idx];
    nlist.n_strx = try self.insertString(gpa, name);

    try self.symbols.ensureUnusedCapacity(gpa, 1);
    const off = try macho_file.string_intern.insert(gpa, name);
    const gop = try macho_file.getOrCreateGlobal(off);
    self.symbols.addOneAssumeCapacity().* = gop.index;
    const sym = macho_file.getSymbol(gop.index);
    sym.file = self.index;
    sym.nlist_idx = nlist_idx;

    return gop.index;
}

fn addNlist(self: *InternalObject, allocator: Allocator) !Symbol.Index {
    const index = @as(Symbol.Index, @intCast(self.symtab.items.len));
    try self.symtab.append(allocator, MachO.null_sym);
    return index;
}

pub fn calcSymtabSize(self: *InternalObject, macho_file: *MachO) !void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        if (sym.getFile(macho_file)) |file| if (file.getIndex() != self.index) continue;
        sym.flags.output_symtab = true;
        if (sym.isLocal()) {
            try sym.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, macho_file);
            self.output_symtab_ctx.nlocals += 1;
        } else if (sym.flags.@"export") {
            try sym.addExtra(.{ .symtab = self.output_symtab_ctx.nexports }, macho_file);
            self.output_symtab_ctx.nexports += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(sym.getName(macho_file).len + 1));
    }
}

pub fn writeSymtab(self: InternalObject, macho_file: *MachO) void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.getSymbol(sym_index);
        if (sym.getFile(macho_file)) |file| if (file.getIndex() != self.index) continue;
        const idx = sym.getOutputSymtabIndex(macho_file) orelse continue;
        const n_strx = @as(u32, @intCast(macho_file.strtab.items.len));
        macho_file.strtab.appendSliceAssumeCapacity(sym.getName(macho_file));
        macho_file.strtab.appendAssumeCapacity(0);
        const out_sym = &macho_file.symtab.items[idx];
        out_sym.n_strx = n_strx;
        sym.setOutputSym(macho_file, out_sym);
    }
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

fn insertString(self: *InternalObject, allocator: Allocator, name: []const u8) !u32 {
    const off = @as(u32, @intCast(self.strtab.items.len));
    try self.strtab.writer(allocator).print("{s}\x00", .{name});
    return off;
}

inline fn getString(self: InternalObject, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(self.strtab.items.ptr + off)), 0);
}

const FormatContext = struct {
    self: *InternalObject,
    macho_file: *MachO,
};

pub fn fmtSymtab(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .self = self,
        .macho_file = macho_file,
    } };
}

fn formatSymtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll("  symbols\n");
    for (ctx.self.symbols.items) |index| {
        const global = ctx.macho_file.getSymbol(index);
        try writer.print("    {}\n", .{global.fmt(ctx.macho_file)});
    }
}

const assert = std.debug.assert;
const macho = std.macho;
const mem = std.mem;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const InternalObject = @This();
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
