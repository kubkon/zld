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

name: []const u8,
data: []const u8,

header: elf.Elf64_Ehdr = undefined,
s_symtab: []align(1) const elf.Elf64_Sym = &[0]elf.Elf64_Sym{},
s_strtab: []const u8 = &[0]u8{},
s_shstrtab: []const u8 = &[0]u8{},
first_global: ?u32 = null,

symtab: std.ArrayListUnmanaged(elf.Elf64_Sym) = .{},

atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
atom_table: std.AutoHashMapUnmanaged(u32, Atom.Index) = .{},

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
    self.symtab.deinit(allocator);
    self.atoms.deinit(allocator);
    self.atom_table.deinit(allocator);
    allocator.free(self.name);
    allocator.free(self.data);
}

pub fn parse(self: *Object, allocator: Allocator) !void {
    var stream = std.io.fixedBufferStream(self.data);
    const reader = stream.reader();

    self.header = try reader.readStruct(elf.Elf64_Ehdr);

    if (self.header.e_shnum == 0) return;

    const shdrs = self.getShdrs();
    self.s_shstrtab = self.getShdrContents(self.header.e_shstrndx);

    const symtab_index = for (self.getShdrs(), 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_SYMTAB => break @intCast(u16, i),
        else => {},
    } else null;

    if (symtab_index) |index| {
        const shdr = shdrs[index];
        self.first_global = shdr.sh_info;

        const symtab = self.getShdrContents(index);
        const nsyms = @divExact(symtab.len, @sizeOf(elf.Elf64_Sym));
        self.s_symtab = @ptrCast([*]align(1) const elf.Elf64_Sym, symtab.ptr)[0..nsyms];
        self.s_strtab = self.getShdrContents(@intCast(u16, shdr.sh_link));

        try self.symtab.appendUnalignedSlice(allocator, self.s_symtab);
    }
}

pub fn scanInputSections(self: *Object, elf_file: *Elf) !void {
    for (self.getShdrs()) |shdr| switch (shdr.sh_type) {
        elf.SHT_PROGBITS, elf.SHT_NOBITS => {
            const shdr_name = self.getShString(shdr.sh_name);
            if (shdr.sh_flags & elf.SHF_GROUP != 0) {
                log.err("section '{s}' is part of a section group", .{shdr_name});
                return error.HandleSectionGroups;
            }

            const tshdr_ndx = (try elf_file.getOutputSection(shdr, shdr_name)) orelse {
                log.debug("unhandled section", .{});
                continue;
            };
            const out_shdr = elf_file.sections.items(.shdr)[tshdr_ndx];
            log.debug("mapping '{s}' into output sect({d}, '{s}')", .{
                shdr_name,
                tshdr_ndx,
                elf_file.shstrtab.getAssumeExists(out_shdr.sh_name),
            });
        },
        else => {},
    };
}

pub fn splitIntoAtoms(self: *Object, allocator: Allocator, object_id: u16, elf_file: *Elf) !void {
    log.debug("parsing '{s}' into atoms", .{self.name});

    var symbols_by_shndx = std.AutoHashMap(u16, std.ArrayList(u32)).init(allocator);
    defer {
        var it = symbols_by_shndx.valueIterator();
        while (it.next()) |value| {
            value.deinit();
        }
        symbols_by_shndx.deinit();
    }

    const shdrs = self.getShdrs();

    var rel_shdrs = std.AutoHashMap(u16, u16).init(allocator);
    defer rel_shdrs.deinit();

    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_REL, elf.SHT_RELA => {
            try rel_shdrs.putNoClobber(@intCast(u16, shdr.sh_info), @intCast(u16, i));
        },
        else => {},
    };

    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_PROGBITS, elf.SHT_NOBITS => {
            try symbols_by_shndx.putNoClobber(@intCast(u16, i), std.ArrayList(u32).init(allocator));
        },
        else => {},
    };

    for (self.s_symtab, 0..) |sym, sym_id| {
        if (sym.st_shndx == elf.SHN_UNDEF) continue;
        if (elf.SHN_LORESERVE <= sym.st_shndx and sym.st_shndx < elf.SHN_HIRESERVE) continue;
        const map = symbols_by_shndx.getPtr(sym.st_shndx) orelse continue;
        try map.append(@intCast(u32, sym_id));
    }

    for (shdrs, 0..) |shdr, i| switch (shdr.sh_type) {
        elf.SHT_PROGBITS, elf.SHT_NOBITS => {
            const ndx = @intCast(u16, i);
            const shdr_name = self.getShString(shdr.sh_name);

            log.debug("parsing section '{s}'", .{shdr_name});

            const tshdr_ndx = (try elf_file.getOutputSection(shdr, shdr_name)) orelse {
                log.debug("unhandled section", .{});
                continue;
            };

            const syms = symbols_by_shndx.get(ndx).?;

            const atom_index = try elf_file.addAtom();
            try self.atoms.append(allocator, atom_index);
            const atom = elf_file.getAtomPtr(atom_index);
            atom.file = object_id;
            atom.name = shdr.sh_name;
            atom.size = @intCast(u32, shdr.sh_size);
            atom.alignment = @intCast(u32, shdr.sh_addralign);
            atom.shndx = ndx;

            if (rel_shdrs.get(ndx)) |rel_ndx| {
                atom.relocs_shndx = rel_ndx;
            }

            for (syms.items) |sym_id| {
                try self.atom_table.putNoClobber(allocator, sym_id, atom_index);
            }

            try elf_file.addAtomToSection(atom_index, tshdr_ndx);
        },
        else => {},
    };
}

pub inline fn getShdrs(self: Object) []const elf.Elf64_Shdr {
    return @ptrCast(
        [*]const elf.Elf64_Shdr,
        @alignCast(@alignOf(elf.Elf64_Shdr), &self.data[self.header.e_shoff]),
    )[0..self.header.e_shnum];
}

pub inline fn getShdrContents(self: Object, index: u16) []const u8 {
    const shdr = self.getShdrs()[index];
    return self.data[shdr.sh_offset..][0..shdr.sh_size];
}

pub fn getSourceSymbol(self: Object, index: u32) ?elf.Elf64_Sym {
    if (index >= self.s_symtab.len) return null;
    return self.s_symtab[index];
}

pub fn getSourceSymbolName(self: Object, index: u32) []const u8 {
    const sym = self.getSourceSymbol(index) orelse return "";
    if (sym.st_type() == elf.STT_SECTION) {
        const shdr = self.getShdrs()[sym.st_shndx];
        return self.getShString(shdr.sh_name);
    } else {
        return self.getString(sym.st_name);
    }
}

pub fn getSymbolPtr(self: *Object, index: u32) *elf.Elf64_Sym {
    return &self.symtab.items[index];
}

pub fn getSymbol(self: Object, index: u32) elf.Elf64_Sym {
    return self.symtab.items[index];
}

pub fn getSymbolName(self: Object, index: u32) []const u8 {
    const sym = self.getSymbol(index);
    return self.getString(sym.st_name);
}

pub fn getAtomIndexForSymbol(self: Object, sym_index: u32) ?Atom.Index {
    return self.atom_table.get(sym_index);
}

pub fn getString(self: Object, off: u32) []const u8 {
    assert(off < self.s_strtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.s_strtab.ptr + off), 0);
}

pub fn getShString(self: Object, off: u32) []const u8 {
    assert(off < self.s_shstrtab.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, self.s_shstrtab.ptr + off), 0);
}
