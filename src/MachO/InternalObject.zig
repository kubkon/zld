index: File.Index,

sections: std.ArrayListUnmanaged(macho.section_64) = .{},
symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
first_global: Symbol.Index = 0,

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

relocations: std.ArrayListUnmanaged(macho.relocation_info) = .{},

alive: bool = true,

pub fn init(self: *InternalObject, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    {
        const n_sect = self.getSectionByName("__DATA", "__data") orelse
            try self.addSection(gpa, "__DATA", "__data");
        const sect = &self.sections.items[n_sect];
        const sym_index = try self.addAtom(macho_file);
        const sym = macho_file.getSymbol(sym_index);
        const nlist = &self.symtab.items[sym.nlist_idx];
        const atom = sym.getAtom(macho_file).?;
        nlist.n_strx = try self.insertString(gpa, "dyld_private");
        const off = try macho_file.string_intern.insert(gpa, self.getString(nlist.n_strx));
        sym.name = off;
        atom.name = off;
        atom.size = @sizeOf(u64);
        atom.alignment = 3;
        atom.n_sect = n_sect;
        sect.size += atom.size;

        const target_idx = try self.addUndefined("dyld_stub_binder", macho_file);
        macho_file.dyld_stub_binder_index = self.symbols.items[target_idx];
        atom.relocs = try self.addRelocations(gpa, &[_]macho.relocation_info{.{
            .r_address = 0,
            .r_symbolnum = @intCast(target_idx),
            .r_pcrel = 0,
            .r_length = 3,
            .r_extern = 1,
            .r_type = @intFromEnum(macho.reloc_type_x86_64.X86_64_RELOC_GOT),
        }});
    }

    {
        const target_idx = try self.addDefined("__mh_execute_header", macho_file);
        macho_file.mh_execute_header_index = self.symbols.items[target_idx];
    }

    if (macho_file.getGlobalByName("__dso_handle")) |index| {
        if (macho_file.getSymbol(index).getFile(macho_file) == null) {
            const target_idx = try self.addDefined("__dso_handle", macho_file);
            macho_file.dso_handle_index = self.symbols.items[target_idx];
        }
    }
}

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    self.sections.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.relocations.deinit(allocator);
}

fn addSection(self: *InternalObject, allocator: Allocator, segname: []const u8, sectname: []const u8) !u8 {
    const index = @as(u8, @intCast(self.sections.items.len));
    try self.sections.append(allocator, .{
        .segname = MachO.makeStaticString(segname),
        .sectname = MachO.makeStaticString(sectname),
    });
    return index;
}

fn addRelocations(
    self: *InternalObject,
    allocator: Allocator,
    relocs: []const macho.relocation_info,
) !Atom.Loc {
    const pos: u32 = @intCast(self.relocations.items.len);
    try self.relocations.ensureUnusedCapacity(allocator, relocs.len);
    self.relocations.appendSliceAssumeCapacity(relocs);
    return .{ .pos = pos, .len = relocs.len };
}

fn addNlist(self: *InternalObject, allocator: Allocator) !Symbol.Index {
    const index = @as(Symbol.Index, @intCast(self.symtab.items.len));
    try self.symtab.append(allocator, MachO.null_sym);
    return index;
}

fn addAtom(self: *InternalObject, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.allocator;
    const atom_index = try macho_file.addAtom();
    const symbol_index = try macho_file.addSymbol();
    const nlist_idx = try self.addNlist(gpa);

    try self.atoms.append(gpa, atom_index);
    try self.symbols.append(gpa, symbol_index);

    const atom = macho_file.getAtom(atom_index).?;
    atom.file = self.index;
    atom.atom_index = atom_index;

    const symbol = macho_file.getSymbol(symbol_index);
    symbol.file = self.index;
    symbol.atom = atom_index;
    symbol.nlist_idx = nlist_idx;

    self.first_global += 1;

    return symbol_index;
}

fn addDefined(self: *InternalObject, name: [:0]const u8, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.allocator;
    const nlist_idx = try self.addNlist(gpa);
    const nlist = &self.symtab.items[nlist_idx];
    nlist.n_strx = try self.insertString(gpa, name);
    nlist.n_type |= macho.N_SECT;
    const index = @as(Symbol.Index, @intCast(self.symbols.items.len));
    try self.symbols.ensureUnusedCapacity(gpa, 1);
    const off = try macho_file.string_intern.insert(gpa, name);
    const gop = try macho_file.getOrCreateGlobal(off);
    self.symbols.addOneAssumeCapacity().* = gop.index;
    return index;
}

fn addUndefined(self: *InternalObject, name: [:0]const u8, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.allocator;
    const nlist_idx = try self.addNlist(gpa);
    const nlist = &self.symtab.items[nlist_idx];
    nlist.n_strx = try self.insertString(gpa, name);
    const index = @as(Symbol.Index, @intCast(self.symbols.items.len));
    try self.symbols.ensureUnusedCapacity(gpa, 1);
    const off = try macho_file.string_intern.insert(gpa, name);
    const gop = try macho_file.getOrCreateGlobal(off);
    self.symbols.addOneAssumeCapacity().* = gop.index;
    return index;
}

pub fn resolveSymbols(self: *InternalObject, macho_file: *MachO) void {
    for (self.getGlobals(), 0..) |index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
        const nlist = self.symtab.items[nlist_idx];

        if (nlist.undf()) continue;

        const global = macho_file.getSymbol(index);
        if (self.asFile().getSymbolRank(nlist, false) < global.getSymbolRank(macho_file)) {
            global.value = 0;
            global.atom = 0;
            global.file = self.index;
            global.nlist_idx = nlist_idx;
            global.flags.weak = nlist.weakDef() or nlist.pext();
        }
    }
}

pub fn scanRelocs(self: InternalObject, macho_file: *MachO) !void {
    for (self.atoms.items) |atom_index| {
        const atom = macho_file.getAtom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        try atom.scanRelocs(macho_file);
    }
}

pub fn claimUnresolved(self: InternalObject, macho_file: *MachO) void {
    for (self.getGlobals(), 0..) |global_index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(self.first_global + i));
        const nlist = self.symtab.items[nlist_idx];
        if (!nlist.undf()) continue;

        const global = macho_file.getSymbol(global_index);
        if (global.getFile(macho_file)) |_| {
            if (!global.getNlist(macho_file).undf()) continue;
        }

        const is_import = switch (macho_file.options.undefined_treatment) {
            .@"error", .warn, .suppress => false,
            .dynamic_lookup => true,
        };

        global.value = 0;
        global.atom = 0;
        global.nlist_idx = nlist_idx;
        global.file = self.index;
        global.flags.import = is_import;
    }
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

pub inline fn getLocals(self: InternalObject) []const Symbol.Index {
    return self.symbols.items[0..self.first_global];
}

pub inline fn getGlobals(self: InternalObject) []const Symbol.Index {
    return self.symbols.items[self.first_global..];
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

fn getSectionByName(self: InternalObject, segname: []const u8, sectname: []const u8) ?u8 {
    for (self.sections.items, 0..) |header, i| {
        if (mem.eql(u8, header.segName(), segname) and mem.eql(u8, header.sectName(), sectname))
            return @as(u8, @intCast(i));
    } else return null;
}

pub fn fmtSymtab(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .self = self,
        .macho_file = macho_file,
    } };
}

const FormatContext = struct {
    self: *InternalObject,
    macho_file: *MachO,
};

fn formatSymtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll("  locals\n");
    for (ctx.self.getLocals()) |index| {
        const local = ctx.macho_file.getSymbol(index);
        try writer.print("    {}\n", .{local.fmt(ctx.macho_file)});
    }
    try writer.writeAll("  globals\n");
    for (ctx.self.getGlobals()) |index| {
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
