/// Address allocated for this Atom.
value: u64,

/// Name of this Atom.
name: u32,

file: u32,

/// Size of this atom
size: u32,

/// Alignment of this atom as a power of two.
alignment: u8,

/// Index of the input section.
shndx: u16,

/// Index of the output section.
out_shndx: u16,

/// Index of the input section containing this atom's relocs.
relocs_shndx: u16,

atom_index: Index,

is_alive: bool,

/// Points to the previous and next neighbours
next: ?Index,
prev: ?Index,

pub const Index = u32;

pub const empty = Atom{
    .value = 0,
    .name = 0,
    .file = 0,
    .size = 0,
    .alignment = 0,
    .shndx = 0,
    .out_shndx = 0,
    .relocs_shndx = @bitCast(u16, @as(i16, -1)),
    .atom_index = 0,
    .is_alive = false,
    .prev = null,
    .next = null,
};

pub fn getName(self: Atom, elf_file: *Elf) [:0]const u8 {
    return elf_file.string_intern.getAssumeExists(self.name);
}

pub fn getCode(self: Atom, elf_file: *Elf) []const u8 {
    const object = self.getFile(elf_file);
    return object.getShdrContents(self.shndx);
}

pub inline fn getFile(self: Atom, elf_file: *Elf) *Object {
    return &elf_file.objects.items[self.file];
}

pub fn getInputShdr(self: Atom, elf_file: *Elf) elf.Elf64_Shdr {
    const object = self.getFile(elf_file);
    return object.getShdrs()[self.shndx];
}

pub fn getRelocs(self: Atom, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
    if (self.relocs_shndx == @bitCast(u16, @as(i16, -1))) return &[0]elf.Elf64_Rela{};
    const object = self.getFile(elf_file);
    const bytes = object.getShdrContents(self.relocs_shndx);
    const nrelocs = @divExact(bytes.len, @sizeOf(elf.Elf64_Rela));
    return @ptrCast([*]align(1) const elf.Elf64_Rela, bytes)[0..nrelocs];
}

pub fn initOutputSection(self: *Atom, elf_file: *Elf) !void {
    const shdr = self.getInputShdr(elf_file);
    const flags = shdr.sh_flags;
    const name = self.getName(elf_file);
    const out_name = switch (shdr.sh_type) {
        elf.SHT_NULL => unreachable,
        elf.SHT_PROGBITS => name: {
            if (flags & elf.SHF_ALLOC == 0) break :name name;
            if (flags & elf.SHF_EXECINSTR != 0) {
                if (mem.startsWith(u8, name, ".init")) {
                    break :name ".init";
                } else if (mem.startsWith(u8, name, ".fini")) {
                    break :name ".fini";
                } else if (mem.startsWith(u8, name, ".init_array")) {
                    break :name ".init_array";
                } else if (mem.startsWith(u8, name, ".fini_array")) {
                    break :name ".fini_array";
                } else {
                    break :name ".text";
                }
            }
            if (flags & elf.SHF_WRITE != 0) {
                if (flags & elf.SHF_TLS != 0) {
                    break :name ".tdata";
                } else if (mem.startsWith(u8, name, ".data.rel.ro")) {
                    break :name ".data.rel.ro";
                } else {
                    break :name ".data";
                }
            }
            break :name ".rodata";
        },
        elf.SHT_NOBITS => name: {
            if (flags & elf.SHF_TLS != 0) {
                break :name ".tbss";
            } else {
                break :name ".bss";
            }
        },
        else => name,
    };
    const out_shndx = elf_file.getSectionByName(out_name) orelse try elf_file.addSection(.{
        .name = out_name,
        .type = shdr.sh_type,
        .flags = shdr.sh_flags,
        .info = shdr.sh_info,
        .entsize = shdr.sh_entsize,
    });
    if (mem.eql(u8, ".text", out_name)) {
        elf_file.text_sect_index = out_shndx;
    }
    self.out_shndx = out_shndx;
}

pub fn scanRelocs(self: Atom, elf_file: *Elf) !void {
    const gpa = elf_file.base.allocator;
    const object = self.getFile(elf_file);
    for (self.getRelocs(elf_file)) |rel| {
        // While traversing relocations, synthesize any missing atom.
        // TODO synthesize PLT atoms, GOT atoms, etc.
        const tsym = object.getSymbol(rel.r_sym(), elf_file);
        const tsym_name = tsym.getName(elf_file);
        switch (rel.r_type()) {
            elf.R_X86_64_REX_GOTPCRELX, elf.R_X86_64_GOTPCREL => {
                const global = elf_file.globals_table.get(tsym_name).?;
                const gop = try elf_file.got_section.getOrCreate(gpa, global);
                if (!gop.found_existing) {
                    log.debug("{s}: creating GOT entry: [() -> {s}]", .{
                        switch (rel.r_type()) {
                            elf.R_X86_64_REX_GOTPCRELX => "REX_GOTPCRELX",
                            elf.R_X86_64_GOTPCREL => "GOTPCREL",
                            else => unreachable,
                        },
                        tsym_name,
                    });
                }
            },
            else => {},
        }
    }
}

pub fn resolveRelocs(self: Atom, elf_file: *Elf, writer: anytype) !void {
    const gpa = elf_file.base.allocator;
    const code = try gpa.dupe(u8, self.getCode(elf_file));
    defer gpa.free(code);
    const relocs = self.getRelocs(elf_file);
    const object = self.getFile(elf_file);

    for (relocs) |rel| {
        const target = object.getSymbol(rel.r_sym(), elf_file);
        const target_name = target.getName(elf_file);
        const source_addr = @intCast(i64, self.value + rel.r_offset);

        const r_type = rel.r_type();
        switch (r_type) {
            elf.R_X86_64_NONE => {},
            elf.R_X86_64_64 => {
                const target_addr = @intCast(i64, target.value) + rel.r_addend;
                log.debug("64: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, target_addr, target_name });
                mem.writeIntLittle(i64, code[rel.r_offset..][0..8], target_addr);
            },
            elf.R_X86_64_PC32,
            elf.R_X86_64_PLT32,
            => {
                const displacement = @intCast(i32, @intCast(i64, target.value) - source_addr + rel.r_addend);
                log.debug("{s}: {x}: [0x{x} => 0x{x}] ({s})", .{
                    switch (r_type) {
                        elf.R_X86_64_PC32 => "PC32",
                        elf.R_X86_64_PLT32 => "PLT32",
                        else => unreachable,
                    },
                    rel.r_offset,
                    source_addr,
                    target.value,
                    target_name,
                });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], displacement);
            },
            elf.R_X86_64_GOTPCREL,
            elf.R_X86_64_REX_GOTPCRELX,
            => {
                const global = elf_file.globals_table.get(target_name).?;
                const target_addr = @intCast(i64, elf_file.got_section.getAddress(global, elf_file).?);
                const displacement = @intCast(i32, target_addr - source_addr + rel.r_addend);
                log.debug("{s}: {x}: [0x{x} => 0x{x}] ({s})", .{
                    switch (r_type) {
                        elf.R_X86_64_GOTPCREL => "GOTPCREL",
                        elf.R_X86_64_REX_GOTPCRELX => "REX_GOTPCRELX",
                        else => unreachable,
                    },
                    rel.r_offset,
                    source_addr,
                    target_addr,
                    target_name,
                });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], displacement);
            },
            elf.R_X86_64_32 => {
                const target_addr = @intCast(i64, target.value) + rel.r_addend;
                const scaled = math.cast(u32, target_addr) orelse {
                    log.err("32: target value overflows 32bits", .{});
                    log.err("  target value 0x{x}", .{target_addr});
                    log.err("  target symbol {s}", .{target_name});
                    return error.RelocationOverflow;
                };
                log.debug("32: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, target_name });
                mem.writeIntLittle(u32, code[rel.r_offset..][0..4], scaled);
            },
            elf.R_X86_64_32S => {
                const target_addr = @intCast(i64, target.value) + rel.r_addend;
                const scaled = math.cast(i32, target_addr) orelse {
                    log.err("32S: target value overflows 32bits", .{});
                    log.err("  target value 0x{x}", .{target_addr});
                    log.err("  target symbol {s}", .{target_name});
                    return error.RelocationOverflow;
                };
                log.debug("32S: {x}: [() => 0x{x}] ({s})", .{ rel.r_offset, scaled, target_name });
                mem.writeIntLittle(i32, code[rel.r_offset..][0..4], scaled);
            },
            else => {
                log.debug("TODO {d}: {x}: [0x{x} => 0x{x}] ({s})", .{
                    r_type,
                    rel.r_offset,
                    source_addr,
                    target.value,
                    target_name,
                });
            },
        }
    }

    try writer.writeAll(code);
}

pub fn format(
    atom: Atom,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = atom;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format symbols directly");
}

pub fn fmt(atom: Atom, elf_file: *Elf) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .elf_file = elf_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
    elf_file: *Elf,
};

fn format2(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const atom = ctx.atom;
    try writer.print("atom({d}) : {s} : @{x} : sect({d}) : align({x}) : size({x})", .{
        atom.atom_index, atom.getName(ctx.elf_file), atom.value,
        atom.out_shndx,  atom.alignment,             atom.size,
    });
    if (ctx.elf_file.options.gc_sections and !atom.is_alive) {
        try writer.writeAll(" : [*]");
    }
}

const Atom = @This();

const std = @import("std");
const assert = std.debug.assert;
const dis_x86_64 = @import("dis_x86_64");
const elf = std.elf;
const log = std.log.scoped(.elf);
const math = std.math;
const mem = std.mem;

const Allocator = mem.Allocator;
const Disassembler = dis_x86_64.Disassembler;
const Elf = @import("../Elf.zig");
const Instruction = dis_x86_64.Instruction;
const Immediate = dis_x86_64.Immediate;
const Object = @import("Object.zig");
