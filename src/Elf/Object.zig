name: []const u8,
data: []const u8,
object_id: u32,

header: ?elf.Elf64_Ehdr = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},
shstrtab: []const u8 = &[0]u8{},
first_global: ?u32 = null,

locals: std.ArrayListUnmanaged(Symbol) = .{},
globals: std.ArrayListUnmanaged(u32) = .{},

atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

pub fn isValid(self: Object) bool {
    var stream = std.io.fixedBufferStream(self.data);
    const header = stream.reader().readStruct(elf.Elf64_Ehdr) catch return false;

    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) {
        log.debug("Invalid ELF magic {s}, expected \x7fELF", .{header.e_ident[0..4]});
        return false;
    }
    if (header.e_ident[elf.EI_VERSION] != 1) {
        log.debug("Unknown ELF version {d}, expected 1", .{header.e_ident[elf.EI_VERSION]});
        return false;
    }
    if (header.e_type != elf.ET.REL) {
        log.err("Invalid file type {any}, expected ET.REL", .{header.e_type});
        return false;
    }
    if (header.e_version != 1) {
        log.err("Invalid ELF version {d}, expected 1", .{header.e_version});
        return false;
    }

    return true;
}

pub fn deinit(self: *Object, allocator: Allocator) void {
    self.locals.deinit(allocator);
    self.globals.deinit(allocator);
    self.atoms.deinit(allocator);
    allocator.free(self.name);
    allocator.free(self.data);
}

pub fn parse(self: *Object, elf_file: *Elf) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);

    if (self.header.?.e_shnum == 0) return;

    const shdrs = self.getShdrs();
    self.shstrtab = self.getShdrContents(self.header.?.e_shstrndx);

    const symtab_index = for (self.getShdrs(), 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_SYMTAB => break @intCast(u16, i),
        else => {},
    } else null;

    if (symtab_index) |index| {
        const shdr = shdrs[index];
        self.first_global = shdr.sh_info;

        const symtab = self.getShdrContents(index);
        const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
        self.symtab = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
        self.strtab = self.getShdrContents(@intCast(u16, shdr.sh_link));
    }

    try self.initAtoms(elf_file);
    try self.initSymtab(elf_file);
}

fn initAtoms(self: *Object, elf_file: *Elf) !void {
    const shdrs = self.getShdrs();
    try self.atoms.resize(elf_file.base.allocator, shdrs.len);
    mem.set(Atom.Index, self.atoms.items, 0);

    for (shdrs, 0..) |shdr, i| {
        if (shdr.sh_flags & elf.SHF_EXCLUDE != 0 and
            shdr.sh_flags & elf.SHF_ALLOC == 0 and
            // shdr.sh_type != elf.SHT_LLVM_ADDRSIG) continue;
            shdr.sh_type != elf.SHT_LOOS + 0xfff4c03) continue;

        switch (shdr.sh_type) {
            elf.SHT_GROUP => @panic("TODO"),
            elf.SHT_SYMTAB_SHNDX => @panic("TODO"),
            elf.SHT_NULL,
            elf.SHT_REL,
            elf.SHT_RELA,
            elf.SHT_SYMTAB,
            elf.SHT_STRTAB,
            => {},
            else => {
                const atom_index = try elf_file.addAtom();
                const atom = elf_file.getAtom(atom_index).?;
                const name = self.getShString(shdr.sh_name);
                atom.atom_index = atom_index;
                atom.name = try elf_file.string_intern.insert(elf_file.base.allocator, name);
                atom.file = self.object_id;
                atom.size = @intCast(u32, shdr.sh_size);
                atom.alignment = math.log2_int(u64, shdr.sh_addralign);
                atom.shndx = @intCast(u16, i);
                self.atoms.items[i] = atom_index;
            },
        }
    }

    // Parse relocs sections if any.
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_REL, elf.SHT_RELA => {
            const atom_index = self.atoms.items[shdr.sh_info];
            elf_file.getAtom(atom_index).?.relocs_shndx = @intCast(u16, i);
        },
        else => {},
    };
}

fn initSymtab(self: *Object, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;
    const first_global = self.first_global orelse self.symtab.len;
    const shdrs = self.getShdrs();

    try self.locals.ensureTotalCapacityPrecise(gpa, first_global);
    try self.globals.ensureTotalCapacityPrecise(gpa, self.symtab.len - first_global);

    for (self.symtab[0..first_global], 0..) |sym, i| {
        const symbol = self.locals.addOneAssumeCapacity();
        const name = blk: {
            if (sym.st_name == 0 and sym.st_type() == elf.STT_SECTION) {
                const shdr = shdrs[sym.st_shndx];
                break :blk self.getShString(shdr.sh_name);
            }
            break :blk self.getString(sym.st_name);
        };
        symbol.* = .{
            .value = sym.st_value,
            .name = try elf_file.string_intern.insert(gpa, name),
            .sym_idx = @intCast(u32, i),
            .atom = if (sym.st_shndx == elf.SHN_ABS) 0 else self.atoms.items[sym.st_shndx],
            .file = self.object_id,
        };
    }

    for (self.symtab[first_global..], 0..) |sym, i| {
        const sym_idx = @intCast(u32, first_global + i);
        const name = self.getString(sym.st_name);
        const gop = try elf_file.getOrCreateGlobal(name);
        if (!gop.found_existing) {
            const global = elf_file.getGlobal(gop.index);
            self.setGlobal(sym_idx, global);
        }
        self.globals.addOneAssumeCapacity().* = gop.index;
    }
}

pub fn resolveSymbols(self: Object, elf_file: *Elf) !void {
    const first_global = self.first_global orelse return;
    for (self.globals.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, first_global + i);
        const this_sym = self.symtab[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getGlobal(index);
        if (getSymbolPrecedence(this_sym) < global.getSymbolPrecedence(elf_file)) {
            self.setGlobal(sym_idx, global);
        }
    }
}

fn setGlobal(self: Object, sym_idx: u32, global: *Symbol) void {
    const sym = self.symtab[sym_idx];
    const name = global.name;
    const atom = if (sym.st_shndx == elf.SHN_UNDEF or sym.st_shndx == elf.SHN_ABS)
        0
    else
        self.atoms.items[sym.st_shndx];
    global.* = .{
        .value = sym.st_value,
        .name = name,
        .atom = atom,
        .sym_idx = sym_idx,
        .file = self.object_id,
    };
}

pub fn checkDuplicates(self: Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (self.globals.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, first_global + i);
        const this_sym = self.symtab[sym_idx];
        const global = elf_file.getGlobal(index);
        const global_file = global.getObject(elf_file) orelse continue;

        if (self.object_id == global_file.object_id or
            this_sym.st_shndx == elf.SHN_UNDEF or
            this_sym.st_bind() == elf.STB_WEAK) continue;
        log.err("multiple definition: {s}: {s}: {s}", .{ self.name, global_file.name, global.getName(elf_file) });
    }
}

pub fn checkUndefined(self: Object, elf_file: *Elf) void {
    for (self.globals.items) |index| {
        const global = elf_file.getGlobal(index);
        if (global.isUndef(elf_file)) {
            log.err("undefined reference: {s}: {s}", .{ self.name, global.getName(elf_file) });
        }
    }
}

/// Encodes symbol precedence so that the following ordering applies:
/// * strong defined
/// * weak defined
/// * undefined
pub inline fn getSymbolPrecedence(sym: elf.Elf64_Sym) u4 {
    if (sym.st_shndx == elf.SHN_UNDEF) return 0xf;
    return switch (sym.st_bind()) {
        elf.STB_GLOBAL => 0,
        elf.STB_WEAK => 1,
        else => 0xf,
    };
}

pub inline fn getSourceSymbol(self: Object, index: u32) elf.Elf64_Sym {
    assert(index < self.symtab.len);
    return self.symtab[index];
}

pub fn getGlobalIndex(self: Object, index: u32) ?u32 {
    assert(index < self.symtab.len);
    const nlocals = self.first_global orelse self.locals.items.len;
    if (index < nlocals) return null;
    return self.globals.items[index - nlocals];
}

pub fn getSymbol(self: *Object, index: u32, elf_file: *Elf) *Symbol {
    if (self.getGlobalIndex(index)) |global_index| {
        return elf_file.getGlobal(global_index);
    } else {
        return &self.locals.items[index];
    }
}

pub inline fn getShdrs(self: Object) []align(1) const elf.Elf64_Shdr {
    const header = self.header orelse return &[0]elf.Elf64_Shdr{};
    return @ptrCast([*]align(1) const elf.Elf64_Shdr, self.data.ptr + header.e_shoff)[0..header.e_shnum];
}

pub inline fn getShdrContents(self: Object, index: u16) []const u8 {
    const shdr = self.getShdrs()[index];
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

inline fn getString(self: Object, off: u32) [:0]const u8 {
    assert(off < self.strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.strtab.ptr + off), 0);
}

inline fn getShString(self: Object, off: u32) [:0]const u8 {
    assert(off < self.shstrtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.shstrtab.ptr + off), 0);
}

pub fn format(
    self: Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format objects directly");
}

pub fn fmtSymtab(self: *const Object, elf_file: *Elf) std.fmt.Formatter(formatSymtab) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    object: *const Object,
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
    const object = ctx.object;
    try writer.writeAll("  locals\n");
    for (object.locals.items) |sym| {
        try writer.print("    {}\n", .{sym.fmt(ctx.elf_file)});
    }
    try writer.writeAll("  globals\n");
    for (object.globals.items) |index| {
        const global = ctx.elf_file.getGlobal(index);
        try writer.print("    {}\n", .{global.fmt(ctx.elf_file)});
    }
}

pub fn fmtAtoms(self: *const Object, elf_file: *Elf) std.fmt.Formatter(formatAtoms) {
    return .{ .data = .{
        .object = self,
        .elf_file = elf_file,
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
    const object = ctx.object;
    try writer.writeAll("  atoms\n");
    for (object.atoms.items) |atom_index| {
        const atom = ctx.elf_file.getAtom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(ctx.elf_file)});
    }
}

const Object = @This();

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const fs = std.fs;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Symbol = @import("Symbol.zig");
