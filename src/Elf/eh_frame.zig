pub const Fde = struct {
    offset: u64,
    size: u64,
    cie_index: u32,
    rel_index: u32 = 0,
    rel_num: u32 = 0,
    rel_shndx: u32 = 0,
    shndx: u32 = 0,
    file: u32 = 0,
    alive: bool = true,
    out_offset: u64 = 0,

    pub inline fn getObject(fde: Fde, elf_file: *Elf) *Object {
        return elf_file.getFile(fde.file).?.object;
    }

    pub fn getData(fde: Fde, elf_file: *Elf) []const u8 {
        const object = fde.getObject(elf_file);
        const data = object.getShdrContents(fde.shndx);
        return data[fde.offset..][0..fde.size];
    }

    pub fn getCie(fde: Fde, elf_file: *Elf) Cie {
        const object = fde.getObject(elf_file);
        return object.cies.items[fde.cie_index];
    }

    pub fn getCiePointer(fde: Fde, elf_file: *Elf) u32 {
        const data = fde.getData(elf_file);
        return std.mem.readIntLittle(u32, data[0..4]);
    }

    pub inline fn getSize(fde: Fde) u64 {
        return fde.size + 4;
    }

    pub fn getAtom(fde: Fde, elf_file: *Elf) *Atom {
        const object = fde.getObject(elf_file);
        const relocs = fde.getRelocs(elf_file);
        const rel = relocs[0];
        const sym = object.symtab[rel.r_sym()];
        const atom_index = object.atoms.items[sym.st_shndx];
        return elf_file.getAtom(atom_index).?;
    }

    pub fn getRelocs(fde: Fde, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
        const object = fde.getObject(elf_file);
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
    rel_index: u32 = 0,
    rel_num: u32 = 0,
    rel_shndx: u32 = 0,
    shndx: u32 = 0,
    file: u32 = 0,
    out_offset: u64 = 0,

    pub inline fn getObject(cie: Cie, elf_file: *Elf) *Object {
        return elf_file.getFile(cie.file).?.object;
    }

    pub fn getData(cie: Cie, elf_file: *Elf) []const u8 {
        const object = cie.getObject(elf_file);
        const data = object.getShdrContents(cie.shndx);
        return data[cie.offset..][0..cie.size];
    }

    pub inline fn getSize(cie: Cie) u64 {
        return cie.size + 4;
    }

    pub fn getRelocs(cie: Cie, elf_file: *Elf) []align(1) const elf.Elf64_Rela {
        const object = cie.getObject(elf_file);
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
        };
        it.pos += size;

        return record;
    }
};

pub fn calcEhFrameSize(elf_file: *Elf) usize {
    var offset: u64 = 0;
    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;
        // TODO dedup CIE records among object files
        for (object.cies.items) |*cie| {
            cie.out_offset = offset;
            offset += cie.getSize();
        }
    }

    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;
        for (object.fdes.items) |*fde| {
            if (!fde.alive) continue;
            fde.out_offset = offset;
            offset += fde.getSize();
        }
    }
    return offset + 4;
}

pub fn calcEhFrameHdrSize(elf_file: *Elf) usize {
    var count: usize = 0;
    for (elf_file.objects.items) |index| {
        for (elf_file.getFile(index).?.object.fdes.items) |fde| {
            if (!fde.alive) continue;
            count += 1;
        }
    }
    return Elf.eh_frame_hdr_header_size + count * 8;
}

fn resolveReloc(
    rel: elf.Elf64_Rela,
    value: i64,
    offset: i64,
    elf_file: *Elf,
    writer: anytype,
) !void {
    const shdr_addr = @intCast(i64, elf_file.sections.items(.shdr)[elf_file.eh_frame_sect_index.?].sh_addr);
    switch (rel.r_type()) {
        elf.R_X86_64_32 => try writer.writeIntLittle(i32, @truncate(i32, value)),
        elf.R_X86_64_64 => try writer.writeIntLittle(i64, value),
        elf.R_X86_64_PC32 => try writer.writeIntLittle(i32, @intCast(i32, value - shdr_addr - offset)),
        elf.R_X86_64_PC64 => try writer.writeIntLittle(i64, value - shdr_addr - offset),
        else => unreachable,
    }
}

pub fn writeEhFrame(elf_file: *Elf, writer: anytype) !void {
    const gpa = elf_file.base.allocator;
    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;

        for (object.cies.items) |cie| {
            const data = try gpa.dupe(u8, cie.getData(elf_file));
            defer gpa.free(data);

            var stream = std.io.fixedBufferStream(data);

            for (cie.getRelocs(elf_file)) |rel| {
                const sym = object.getSymbol(rel.r_sym(), elf_file);
                const value = @intCast(i64, sym.value) + rel.r_addend;
                const offset = @intCast(i64, cie.out_offset + rel.r_offset - cie.offset);
                try stream.seekTo(rel.r_offset - cie.offset);
                try resolveReloc(rel, value, offset, elf_file, stream.writer());
            }

            try writer.writeIntLittle(u32, @intCast(u32, cie.size));
            try writer.writeAll(data);
        }
    }

    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;

        for (object.fdes.items) |fde| {
            if (!fde.alive) continue;

            const data = try gpa.dupe(u8, fde.getData(elf_file));
            defer gpa.free(data);

            var stream = std.io.fixedBufferStream(data);
            try stream.writer().writeIntLittle(
                i32,
                @truncate(i32, @intCast(i64, fde.out_offset + 4) - @intCast(i64, fde.getCie(elf_file).out_offset)),
            );

            for (fde.getRelocs(elf_file)) |rel| {
                const sym = object.getSymbol(rel.r_sym(), elf_file);
                const value = @intCast(i64, sym.getAddress(elf_file)) + rel.r_addend;
                const offset = @intCast(i64, fde.out_offset + rel.r_offset - fde.offset);
                try stream.seekTo(rel.r_offset - fde.offset);
                try resolveReloc(rel, value, offset, elf_file, stream.writer());
            }

            try writer.writeIntLittle(u32, @intCast(u32, fde.size));
            try writer.writeAll(data);
        }
    }

    try writer.writeIntLittle(u32, 0);
}

pub fn writeEhFrameHdr(elf_file: *Elf, writer: anytype) !void {
    try writer.writeByte(1); // version
    try writer.writeByte(EH_PE.pcrel | EH_PE.sdata4);
    try writer.writeByte(EH_PE.udata4);
    try writer.writeByte(EH_PE.datarel | EH_PE.sdata4);

    const eh_frame_shdr = elf_file.sections.items(.shdr)[elf_file.eh_frame_sect_index.?];
    const eh_frame_hdr_shdr = elf_file.sections.items(.shdr)[elf_file.eh_frame_hdr_sect_index.?];
    const num_fdes = @intCast(u32, @divExact(eh_frame_hdr_shdr.sh_size - Elf.eh_frame_hdr_header_size, 8));
    try writer.writeIntLittle(
        u32,
        @bitCast(u32, @truncate(
            i32,
            @intCast(i64, eh_frame_shdr.sh_addr) - @intCast(i64, eh_frame_hdr_shdr.sh_addr) + 4,
        )),
    );
    try writer.writeIntLittle(u32, num_fdes);

    const Entry = struct {
        init_addr: u32,
        fde_addr: u32,

        pub fn lessThan(ctx: void, lhs: @This(), rhs: @This()) bool {
            _ = ctx;
            return lhs.init_addr < rhs.init_addr;
        }
    };

    var entries = std.ArrayList(Entry).init(elf_file.base.allocator);
    defer entries.deinit();
    try entries.ensureTotalCapacityPrecise(num_fdes);

    for (elf_file.objects.items) |index| {
        const object = elf_file.getFile(index).?.object;
        for (object.fdes.items) |fde| {
            if (!fde.alive) continue;

            const relocs = fde.getRelocs(elf_file);
            assert(relocs.len > 0); // Should this be an error? Things are completely broken anyhow if this trips...
            const rel = relocs[0];
            const sym = object.getSymbol(rel.r_sym(), elf_file);
            const value = @intCast(i64, sym.getAddress(elf_file)) + rel.r_addend;
            entries.appendAssumeCapacity(.{
                .init_addr = @bitCast(u32, @truncate(i32, value - @intCast(i64, eh_frame_hdr_shdr.sh_addr))),
                .fde_addr = @bitCast(
                    u32,
                    @truncate(
                        i32,
                        @intCast(i64, eh_frame_shdr.sh_addr + fde.out_offset) - @intCast(i64, eh_frame_hdr_shdr.sh_addr),
                    ),
                ),
            });
        }
    }

    std.mem.sort(Entry, entries.items, {}, Entry.lessThan);
    try writer.writeAll(std.mem.sliceAsBytes(entries.items));
}

const EH_PE = struct {
    pub const absptr = 0x00;
    pub const uleb128 = 0x01;
    pub const udata2 = 0x02;
    pub const udata4 = 0x03;
    pub const udata8 = 0x04;
    pub const sleb128 = 0x09;
    pub const sdata2 = 0x0A;
    pub const sdata4 = 0x0B;
    pub const sdata8 = 0x0C;
    pub const pcrel = 0x10;
    pub const textrel = 0x20;
    pub const datarel = 0x30;
    pub const funcrel = 0x40;
    pub const aligned = 0x50;
    pub const indirect = 0x80;
    pub const omit = 0xFF;
};

const std = @import("std");
const assert = std.debug.assert;
const elf = std.elf;
const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const Elf = @import("../Elf.zig");
const Object = @import("Object.zig");
