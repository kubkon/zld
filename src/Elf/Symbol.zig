//! Represents a defined symbol.

value: u64 = 0,

name: u32 = 0,

atom: Atom.Index = 0,

sym_idx: u32 = 0,

pub inline fn getName(symbol: Symbol, elf_file: *Elf) [:0]const u8 {
    return elf_file.getString(symbol.name);
}

pub inline fn getAtom(symbol: Symbol, elf_file: *Elf) ?*Atom {
    return elf_file.getAtom(symbol.atom);
}

pub fn getSourceSymbol(symbol: Symbol, elf_file: *Elf) ?elf.Elf64_Sym {
    const atom = symbol.getAtom(elf_file) orelse return null;
    const object = atom.getFile(elf_file);
    return object.s_symtab[symbol.sym_idx];
}

pub fn getSymbolPrecedence(symbol: Symbol, elf_file: *Elf) u4 {
    const sym = symbol.getSourceSymbol(elf_file) orelse return 0xf;
    return Object.getSymbolPrecedence(sym);
}

const std = @import("std");
const elf = std.elf;

const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");
const Symbol = @This();
