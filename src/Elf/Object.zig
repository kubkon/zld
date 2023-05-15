archive: ?[]const u8 = null,
name: []const u8,
data: []const u8,
index: Elf.File.Index,

header: ?elf.Elf64_Ehdr = null,
symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
strtab: []const u8 = &[0]u8{},
shstrtab: []const u8 = &[0]u8{},
first_global: ?u32 = null,

locals: std.ArrayListUnmanaged(Symbol) = .{},
globals: std.ArrayListUnmanaged(u32) = .{},

atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

needs_exec_stack: bool = false,
alive: bool = true,

pub fn isValidHeader(header: *const elf.Elf64_Ehdr) bool {
    if (!mem.eql(u8, header.e_ident[0..4], "\x7fELF")) {
        log.debug("invalid ELF magic '{s}', expected \x7fELF", .{header.e_ident[0..4]});
        return false;
    }
    if (header.e_ident[elf.EI_VERSION] != 1) {
        log.debug("unknown ELF version '{d}', expected 1", .{header.e_ident[elf.EI_VERSION]});
        return false;
    }
    if (header.e_type != elf.ET.REL) {
        log.debug("invalid file type '{s}', expected ET.REL", .{@tagName(header.e_type)});
        return false;
    }
    if (header.e_version != 1) {
        log.debug("invalid ELF version '{d}', expected 1", .{header.e_version});
        return false;
    }
    return true;
}

pub fn deinit(self: *Object, allocator: Allocator) void {
    self.locals.deinit(allocator);
    self.globals.deinit(allocator);
    self.atoms.deinit(allocator);
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
    @memset(self.atoms.items, 0);

    for (shdrs, 0..) |shdr, i| {
        if (shdr.sh_flags & elf.SHF_EXCLUDE != 0 and
            shdr.sh_flags & elf.SHF_ALLOC == 0 and
            shdr.sh_type != elf.SHT_LLVM_ADDRSIG) continue;

        switch (shdr.sh_type) {
            elf.SHT_NULL,
            elf.SHT_REL,
            elf.SHT_RELA,
            elf.SHT_SYMTAB,
            elf.SHT_STRTAB,
            => {},
            else => {
                const name = self.getShString(shdr.sh_name);
                const shndx = @intCast(u16, i);

                if (mem.eql(u8, ".note.GNU-stack", name)) {
                    if (shdr.sh_flags & elf.SHF_EXECINSTR != 0) {
                        if (!elf_file.options.execstack or !elf_file.options.execstack_if_needed) {
                            elf_file.base.warn(
                                "{s}: may cause segmentation fault as this file requested executable stack",
                                .{self.name},
                            );
                        }
                        self.needs_exec_stack = true;
                    }
                    continue;
                }
                if (self.skipShdr(shndx, elf_file)) continue;
                try self.addAtom(shdr, shndx, name, elf_file);
            },
        }
    }

    // Parse relocs sections if any.
    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_REL, elf.SHT_RELA => {
            const atom_index = self.atoms.items[shdr.sh_info];
            if (elf_file.getAtom(atom_index)) |atom| {
                atom.relocs_shndx = @intCast(u16, i);
            }
        },
        else => {},
    };
}

fn addAtom(self: *Object, shdr: elf.Elf64_Shdr, shndx: u16, name: [:0]const u8, elf_file: *Elf) !void {
    const atom_index = try elf_file.addAtom();
    const atom = elf_file.getAtom(atom_index).?;
    atom.atom_index = atom_index;
    atom.name = try elf_file.string_intern.insert(elf_file.base.allocator, name);
    atom.file = self.index;
    atom.shndx = shndx;
    self.atoms.items[shndx] = atom_index;

    if (shdr.sh_flags & elf.SHF_COMPRESSED != 0) {
        const data = self.getShdrContents(shndx);
        const chdr = @ptrCast(*align(1) const elf.Elf64_Chdr, data.ptr).*;
        atom.size = @intCast(u32, chdr.ch_size);
        atom.alignment = math.log2_int(u64, chdr.ch_addralign);
    } else {
        atom.size = @intCast(u32, shdr.sh_size);
        atom.alignment = math.log2_int(u64, shdr.sh_addralign);
    }
}

fn skipShdr(self: Object, index: u32, elf_file: *Elf) bool {
    const shdr = self.getShdrs()[index];
    const name = self.getShString(shdr.sh_name);
    const ignore = blk: {
        switch (shdr.sh_type) {
            elf.SHT_X86_64_UNWIND,
            elf.SHT_GROUP,
            elf.SHT_SYMTAB_SHNDX,
            => break :blk true,

            else => {},
        }
        if (mem.startsWith(u8, name, ".note")) break :blk true;
        if (mem.startsWith(u8, name, ".comment")) break :blk true;
        if (mem.startsWith(u8, name, ".llvm_addrsig")) break :blk true;
        if ((elf_file.options.strip_debug or elf_file.options.strip_all) and
            shdr.sh_flags & elf.SHF_ALLOC == 0 and
            mem.startsWith(u8, name, ".debug")) break :blk true;
        break :blk false;
    };
    return ignore;
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
            .file = self.index,
        };
    }

    for (self.symtab[first_global..]) |sym| {
        const name = self.getString(sym.st_name);
        const gop = try elf_file.getOrCreateGlobal(name);
        self.globals.addOneAssumeCapacity().* = gop.index;
    }
}

pub fn resolveSymbols(self: Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (self.globals.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, first_global + i);
        const this_sym = self.symtab[sym_idx];

        if (this_sym.st_shndx == elf.SHN_UNDEF) continue;

        const global = elf_file.getGlobal(index);
        if (self.asFile().getSymbolRank(this_sym, !self.alive) < global.getSymbolRank(elf_file)) {
            const atom = switch (this_sym.st_shndx) {
                elf.SHN_ABS, elf.SHN_COMMON => 0,
                else => self.atoms.items[this_sym.st_shndx],
            };
            global.* = .{
                .value = this_sym.st_value,
                .name = global.name,
                .atom = atom,
                .sym_idx = sym_idx,
                .file = self.index,
            };
        }
    }
}

pub fn resetGlobals(self: Object, elf_file: *Elf) void {
    for (self.globals.items) |index| {
        const global = elf_file.getGlobal(index);
        const name = global.name;
        global.* = .{};
        global.name = name;
    }
}

pub fn markLive(self: *Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (self.globals.items, 0..) |index, i| {
        const sym_idx = first_global + i;
        const sym = self.symtab[sym_idx];
        if (sym.st_bind() == elf.STB_WEAK) continue;

        const global = elf_file.getGlobal(index);
        const file = global.getFile(elf_file) orelse continue;
        if (sym.st_shndx == elf.SHN_UNDEF and !file.deref().isAlive()) {
            file.setAlive();
            file.markLive(elf_file);
        }
    }
}

pub fn checkDuplicates(self: Object, elf_file: *Elf) void {
    const first_global = self.first_global orelse return;
    for (self.globals.items, 0..) |index, i| {
        const sym_idx = @intCast(u32, first_global + i);
        const this_sym = self.symtab[sym_idx];
        const global = elf_file.getGlobal(index);
        const global_file = global.getFile(elf_file) orelse continue;

        if (self.index == global_file.deref().getIndex() or
            this_sym.st_shndx == elf.SHN_UNDEF or
            this_sym.st_bind() == elf.STB_WEAK) continue;
        elf_file.base.fatal("multiple definition: {s}: {s}: {s}", .{
            self.name,
            global_file.deref().getPath(),
            global.getName(elf_file),
        });
    }
}

pub fn checkUndefined(self: Object, elf_file: *Elf) void {
    for (self.globals.items) |index| {
        const global = elf_file.getGlobal(index);
        if (global.getFile(elf_file) == null) {
            elf_file.base.fatal("undefined reference: {s}: {s}", .{ self.name, global.getName(elf_file) });
        }
    }
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

pub fn asFile(self: Object) Elf.File {
    return .{ .object = self };
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
