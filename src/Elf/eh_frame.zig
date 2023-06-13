pub const Fde = struct {
    inner: eh_frame.Fde,
    rel_index: u32,
    rel_num: u32 = 0,
    rel_shndx: u32 = 0,
    file: u32 = 0,
    alive: bool = true,

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
            fde.inner.offset,
            fde.inner.size,
            fde.inner.cie_index,
            fde.getAtom(ctx.elf_file).getName(ctx.elf_file),
        });
    }
};

pub const Cie = struct {
    inner: eh_frame.Cie,
    rel_index: u32,
    rel_num: u32 = 0,
    rel_shndx: u32 = 0,
    file: u32 = 0,

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
            cie.inner.offset,
            cie.inner.size,
        });
    }
};

pub const EhFrameSection = struct {
    buffer: std.ArrayListUnmanaged(u8) = .{},

    pub fn deinit(eh: *EhFrameSection, allocator: Allocator) void {
        eh.buffer.deinit(allocator);
    }

    pub fn generate(eh: *EhFrameSection, elf_file: *Elf) !void {
        _ = eh;
        _ = elf_file;
    }

    pub fn size(eh: *EhFrameSection) usize {
        _ = eh;
        return 0;
    }

    pub fn write(eh: EhFrameSection, elf_file: *Elf, writer: anytype) !void {
        _ = elf_file;
        _ = eh;
        _ = writer;
    }
};

const std = @import("std");
const eh_frame = @import("../eh_frame.zig");
const elf = std.elf;
const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
pub const NewIterator = eh_frame.NewIterator;
