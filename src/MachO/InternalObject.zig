index: File.Index,

sections: std.ArrayListUnmanaged(macho.section_64) = .{},
symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

code: std.ArrayListUnmanaged(u8) = .{},

alive: bool = true,

output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn init(self: *InternalObject, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;
    {
        const n_sect = self.getSectionByName("__TEXT", "__text") orelse
            try self.addSection(gpa, "__TEXT", "__text");
        const target_idx = try self.addGlobal("__mh_execute_header", macho_file);
        const nlist = &self.symtab.items[target_idx];
        nlist.n_type = macho.N_EXT | macho.N_SECT;
        nlist.n_desc = macho.REFERENCED_DYNAMICALLY;
        nlist.n_sect = n_sect + 1;
        const atom_index = try self.addAtom(macho_file);
        const atom = macho_file.getAtom(atom_index).?;
        atom.name = try macho_file.string_intern.insert(gpa, self.getString(nlist.n_strx));
        atom.n_sect = n_sect;
        macho_file.mh_execute_header_index = self.symbols.items[target_idx];
    }

    if (macho_file.getGlobalByName("__dso_handle")) |index| {
        if (macho_file.getSymbol(index).getFile(macho_file) == null) {
            const target_idx = try self.addGlobal("__dso_handle", macho_file);
            const nlist = &self.symtab.items[target_idx];
            nlist.n_type = macho.N_EXT | macho.N_ABS;
            macho_file.dso_handle_index = self.symbols.items[target_idx];
        }
    }

    {
        const target_idx = try self.addGlobal("dyld_private", macho_file);
        macho_file.dyld_private_index = self.symbols.items[target_idx];

        const n_sect = self.getSectionByName("__DATA", "__data") orelse
            try self.addSection(gpa, "__DATA", "__data");

        const nlist = &self.symtab.items[target_idx];
        nlist.n_sect = n_sect + 1;
        nlist.n_type = macho.N_PEXT | macho.N_EXT | macho.N_SECT;

        const sect = &self.sections.items[n_sect];
        const atom_index = try self.addAtom(macho_file);
        const atom = macho_file.getAtom(atom_index).?;
        atom.name = try macho_file.string_intern.insert(gpa, self.getString(nlist.n_strx));
        atom.size = @sizeOf(u64);
        atom.alignment = 3;
        atom.n_sect = n_sect;
        sect.size += atom.size;

        try self.code.ensureUnusedCapacity(gpa, atom.size);
        atom.off = self.code.items.len;
        self.code.appendNTimesAssumeCapacity(0, atom.size);
    }

    {
        const target_idx = try self.addGlobal("dyld_stub_binder", macho_file);
        const target = macho_file.getSymbol(self.symbols.items[target_idx]);
        target.flags.got = true;
        macho_file.dyld_stub_binder_index = self.symbols.items[target_idx];
    }
}

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    self.sections.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.code.deinit(allocator);
}

fn addSection(self: *InternalObject, allocator: Allocator, segname: []const u8, sectname: []const u8) !u8 {
    const index = @as(u8, @intCast(self.sections.items.len));
    try self.sections.append(allocator, .{
        .segname = MachO.makeStaticString(segname),
        .sectname = MachO.makeStaticString(sectname),
    });
    return index;
}

fn addNlist(self: *InternalObject, allocator: Allocator) !Symbol.Index {
    const index = @as(Symbol.Index, @intCast(self.symtab.items.len));
    try self.symtab.append(allocator, MachO.null_sym);
    return index;
}

fn addAtom(self: *InternalObject, macho_file: *MachO) !Atom.Index {
    const gpa = macho_file.base.allocator;
    const atom_index = try macho_file.addAtom();
    try self.atoms.append(gpa, atom_index);
    const atom = macho_file.getAtom(atom_index).?;
    atom.file = self.index;
    atom.atom_index = atom_index;
    return atom_index;
}

fn addGlobal(self: *InternalObject, name: [:0]const u8, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.allocator;
    const nlist_idx = try self.addNlist(gpa);
    const nlist = &self.symtab.items[nlist_idx];
    nlist.n_strx = try self.insertString(gpa, name);
    nlist.n_type = macho.N_EXT;
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
            const atom = if (nlist.abs()) 0 else self.atoms.items[nlist.n_sect - 1];
            global.value = nlist.n_value;
            global.atom = atom;
            global.file = self.index;
            global.nlist_idx = nlist_idx;
            global.flags.weak = nlist.weakDef() or nlist.pext();
        }
    }
}

pub fn claimUnresolved(self: InternalObject, macho_file: *MachO) void {
    for (self.getGlobals(), 0..) |global_index, i| {
        const nlist_idx = @as(Symbol.Index, @intCast(i));
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

pub fn calcSymtabSize(self: *InternalObject, macho_file: *MachO) !void {
    for (self.getGlobals()) |global_index| {
        const global = macho_file.getSymbol(global_index);
        const file = global.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        global.flags.output_symtab = true;
        if (global.isLocal()) {
            try global.addExtra(.{ .symtab = self.output_symtab_ctx.nlocals }, macho_file);
            self.output_symtab_ctx.nlocals += 1;
        } else if (global.flags.@"export") {
            try global.addExtra(.{ .symtab = self.output_symtab_ctx.nexports }, macho_file);
            self.output_symtab_ctx.nexports += 1;
        } else {
            try global.addExtra(.{ .symtab = self.output_symtab_ctx.nimports }, macho_file);
            self.output_symtab_ctx.nimports += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @intCast(global.getName(macho_file).len + 1));
    }
}

pub fn writeSymtab(self: InternalObject, macho_file: *MachO) void {
    for (self.getGlobals()) |global_index| {
        const global = macho_file.getSymbol(global_index);
        const file = global.getFile(macho_file) orelse continue;
        if (file.getIndex() != self.index) continue;
        const idx = global.getOutputSymtabIndex(macho_file) orelse continue;
        const n_strx = @as(u32, @intCast(macho_file.strtab.items.len));
        macho_file.strtab.appendSliceAssumeCapacity(global.getName(macho_file));
        macho_file.strtab.appendAssumeCapacity(0);
        const out_sym = &macho_file.symtab.items[idx];
        out_sym.n_strx = n_strx;
        global.setOutputSym(macho_file, out_sym);
    }
}

pub fn asFile(self: *InternalObject) File {
    return .{ .internal = self };
}

pub inline fn getGlobals(self: InternalObject) []const Symbol.Index {
    return self.symbols.items;
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

const FormatContext = struct {
    self: *InternalObject,
    macho_file: *MachO,
};

pub fn fmtAtoms(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(formatAtoms) {
    return .{ .data = .{
        .self = self,
        .macho_file = macho_file,
    } };
}

fn formatAtoms(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.writeAll("  atoms\n");
    for (ctx.self.atoms.items) |atom_index| {
        const atom = ctx.macho_file.getAtom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(ctx.macho_file)});
    }
}

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
