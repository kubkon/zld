pub const Fde = struct {
    offset: u64,
    size: u64,
    data: []const u8,
    cie_index: u32,
    rel_index: u32 = 0,
    rel_num: u32 = 0,
    rel_shndx: u32 = 0,
    file: u32 = 0,
    alive: bool = true,
    out_offset: u64 = 0,

    pub fn getCiePointer(fde: Fde) u32 {
        return std.mem.readIntLittle(u32, fde.data[0..4]);
    }

    pub fn getAtom(fde: Fde, elf_file: *Elf) *Atom {
        const object = elf_file.getFile(fde.file).?.object;
        const relocs = fde.getRelocs(elf_file);
        const rel = relocs[0];
        const sym = object.symtab[rel.r_sym()];
        const atom_index = object.atoms.items[sym.st_shndx];
        return elf_file.getAtom(atom_index).?;
    }

    pub fn getRelocs(fde: Fde, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
        const object = elf_file.getFile(fde.file).?.object;
        return object.getRelocs(fde.rel_shndx)[fde.rel_index..][0..fde.rel_num];
    }

    pub fn format(
        fde: Fde,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fde;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compileError("do not format FDEs directly");
    }

    pub fn fmt(fde: Fde, elf_file: *Elf) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .fde = fde,
            .elf_file = elf_file,
        } };
    }

    const FdeFormatContext = struct {
        fde: Fde,
        elf_file: *Elf,
    };

    fn format2(
        ctx: FdeFormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const fde = ctx.fde;
        try writer.print("@{x} : size({x}) : cie({d}) : {s}", .{
            fde.offset,
            fde.size,
            fde.cie_index,
            fde.getAtom(ctx.elf_file).getName(ctx.elf_file),
        });
    }
};

pub const Cie = struct {
    offset: u64,
    size: u64,
    data: []const u8,
    rel_index: u32 = 0,
    rel_num: u32 = 0,
    rel_shndx: u32 = 0,
    file: u32 = 0,
    out_offset: u64 = 0,

    pub fn getRelocs(cie: Cie, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
        const object = elf_file.getFile(cie.file).?.object;
        return object.getRelocs(cie.rel_shndx)[cie.rel_index..][0..cie.rel_num];
    }

    pub fn format(
        cie: Cie,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = cie;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compileError("do not format CIEs directly");
    }

    pub fn fmt(cie: Cie, elf_file: *Elf) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .cie = cie,
            .elf_file = elf_file,
        } };
    }

    const CieFormatContext = struct {
        cie: Cie,
        elf_file: *Elf,
    };

    fn format2(
        ctx: CieFormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const cie = ctx.cie;
        try writer.print("@{x} : size({x})", .{
            cie.offset,
            cie.size,
        });
    }
};

pub const Iterator = struct {
    data: []const u8,
    pos: u64 = 0,

    pub const Record = struct {
        tag: enum { fde, cie },
        offset: u64,
        size: u64,
        data: []const u8,

        pub fn fde(rec: Record) Fde {
            assert(rec.tag == .fde);
            return .{
                .offset = rec.offset,
                .size = rec.size,
                .data = rec.data,
                .cie_index = undefined,
            };
        }

        pub fn cie(rec: Record) Cie {
            assert(rec.tag == .cie);
            return .{
                .offset = rec.offset,
                .size = rec.size,
                .data = rec.data,
            };
        }
    };

    pub fn next(it: *Iterator) !?Record {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        var size = try reader.readIntLittle(u32);
        it.pos += 4;
        if (size == 0xFFFFFFFF) @panic("TODO");

        const id = try reader.readIntLittle(u32);
        const record = Record{
            .tag = if (id == 0) .cie else .fde,
            .offset = it.pos,
            .size = size,
            .data = it.data[it.pos..][0..size],
        };
        it.pos += size;

        return record;
    }
};

pub fn generateEhFrame(elf_file: *Elf) !void {
    _ = elf_file;
}

pub fn calcEhFrameSize(elf_file: *Elf) usize {
    _ = elf_file;
    return 0;
}

pub fn writeEhFrame(elf_file: *Elf, writer: anytype) !void {
    _ = elf_file;
    _ = writer;
}

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
