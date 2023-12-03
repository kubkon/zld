pub const Cie = struct {
    /// Includes 4byte size cell.
    offset: u32,
    out_offset: u32 = 0,
    size: u32,
    lsda_size: ?enum { p32, p64 } = null,
    personality: ?Personality = null,
    file: File.Index = 0,
    alive: bool = false,

    pub fn parse(cie: *Cie, macho_file: *MachO) !void {
        const data = cie.getData(macho_file);
        const aug = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(data.ptr + 9)), 0);

        if (aug[0] != 'z') return; // TODO should we error out?

        var stream = std.io.fixedBufferStream(data[9 + aug.len + 1 ..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        _ = try leb.readULEB128(u64, reader); // code alignment factor
        _ = try leb.readULEB128(u64, reader); // data alignment factor
        _ = try leb.readULEB128(u64, reader); // return address register
        _ = try leb.readULEB128(u64, reader); // augmentation data length

        for (aug[1..]) |ch| switch (ch) {
            'R' => {
                const enc = try reader.readByte();
                if (enc & 0xf != EH_PE.absptr or enc & EH_PE.pcrel == 0) {
                    @panic("unexpected pointer encoding"); // TODO error
                }
            },
            'P' => {
                const enc = try reader.readByte();
                if (enc != EH_PE.pcrel | EH_PE.indirect | EH_PE.sdata4) {
                    @panic("unexpected personality pointer encoding"); // TODO error
                }
                _ = try reader.readInt(u32, .little); // personality pointer
            },
            'L' => {
                const enc = try reader.readByte();
                switch (enc & 0xf) {
                    EH_PE.sdata4 => cie.lsda_size = .p32,
                    EH_PE.absptr => cie.lsda_size = .p64,
                    else => unreachable, // TODO error
                }
            },
            else => @panic("unexpected augmentation string"), // TODO error
        };
    }

    pub inline fn getSize(cie: Cie) u32 {
        return cie.size + 4;
    }

    pub fn getObject(cie: Cie, macho_file: *MachO) *Object {
        const file = macho_file.getFile(cie.file).?;
        return file.object;
    }

    pub fn getData(cie: Cie, macho_file: *MachO) []const u8 {
        const object = cie.getObject(macho_file);
        const data = object.getSectionData(object.eh_frame_sect_index.?);
        return data[cie.offset..][0..cie.getSize()];
    }

    pub fn getPersonality(cie: Cie, macho_file: *MachO) ?*Symbol {
        const personality = cie.personality orelse return null;
        return macho_file.getSymbol(personality.index);
    }

    pub fn getPersonalityOffset(cie: Cie) ?u32 {
        const personality = cie.personality orelse return null;
        return personality.offset;
    }

    pub fn eql(cie: Cie, other: Cie, macho_file: *MachO) bool {
        if (!std.mem.eql(u8, cie.getData(macho_file), other.getData(macho_file))) return false;
        if (cie.personality != null and other.personality != null) {
            if (cie.personality.?.index != other.personality.?.index) return false;
        }
        if (cie.personality != null or other.personality != null) return false;
        return true;
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

    pub fn fmt(cie: Cie, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .cie = cie,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        cie: Cie,
        macho_file: *MachO,
    };

    fn format2(
        ctx: FormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const cie = ctx.cie;
        try writer.print("@{x} : size({x})", .{
            cie.offset,
            cie.getSize(),
        });
        if (!cie.alive) try writer.writeAll(" : [*]");
    }

    pub const Index = u32;

    pub const Personality = struct {
        index: Symbol.Index = 0,
        offset: u32 = 0,
    };
};

pub const Fde = struct {
    /// Includes 4byte size cell.
    offset: u32,
    out_offset: u32 = 0,
    size: u32,
    cie: Cie.Index,
    atom: Atom.Index = 0,
    atom_offset: u32 = 0,
    lsda: Atom.Index = 0,
    lsda_offset: u32 = 0,
    file: File.Index = 0,
    alive: bool = true,

    pub fn parse(fde: *Fde, macho_file: *MachO) !void {
        const data = fde.getData(macho_file);
        const object = fde.getObject(macho_file);
        const sect = object.sections.items(.header)[object.eh_frame_sect_index.?];

        // Parse target atom index
        const pc_begin = std.mem.readInt(i64, data[8..][0..8], .little);
        const taddr: u64 = @intCast(@as(i64, @intCast(sect.addr + fde.offset + 8)) + pc_begin);
        fde.atom = object.findAtom(taddr);
        const atom = fde.getAtom(macho_file);
        fde.atom_offset = @intCast(taddr - atom.getInputAddress(macho_file));

        // Associate with a CIE
        const cie_ptr = std.mem.readInt(u32, data[4..8], .little);
        const cie_offset = fde.offset + 4 - cie_ptr;
        const cie_index = for (object.cies.items, 0..) |cie, cie_index| {
            if (cie.offset == cie_offset) break @as(Cie.Index, @intCast(cie_index));
        } else null;
        if (cie_index) |cie| {
            fde.cie = cie;
        } else {
            macho_file.base.fatal("{}: no matching CIE found for FDE at offset {x}", .{
                object.fmtPath(),
                fde.offset,
            });
            return;
        }

        const cie = fde.getCie(macho_file);

        // Parse LSDA atom index if any
        if (cie.lsda_size) |lsda_size| {
            var stream = std.io.fixedBufferStream(data[24..]);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();
            _ = try leb.readULEB128(u64, reader); // augmentation length
            const offset = creader.bytes_read;
            const lsda_ptr = switch (lsda_size) {
                .p32 => try reader.readInt(i32, .little),
                .p64 => try reader.readInt(i64, .little),
            };
            const lsda_addr: u64 = @intCast(@as(i64, @intCast(sect.addr + 24 + offset + fde.offset)) + lsda_ptr);
            fde.lsda = object.findAtom(lsda_addr);
            const lsda_atom = fde.getLsdaAtom(macho_file).?;
            fde.lsda_offset = @intCast(lsda_addr - lsda_atom.getInputAddress(macho_file));
        }
    }

    pub inline fn getSize(fde: Fde) u32 {
        return fde.size + 4;
    }

    pub fn getObject(fde: Fde, macho_file: *MachO) *Object {
        const file = macho_file.getFile(fde.file).?;
        return file.object;
    }

    pub fn getData(fde: Fde, macho_file: *MachO) []const u8 {
        const object = fde.getObject(macho_file);
        const data = object.getSectionData(object.eh_frame_sect_index.?);
        return data[fde.offset..][0..fde.getSize()];
    }

    pub fn getCie(fde: Fde, macho_file: *MachO) *const Cie {
        const object = fde.getObject(macho_file);
        return &object.cies.items[fde.cie];
    }

    pub fn getAtom(fde: Fde, macho_file: *MachO) *Atom {
        return macho_file.getAtom(fde.atom).?;
    }

    pub fn getLsdaAtom(fde: Fde, macho_file: *MachO) ?*Atom {
        return macho_file.getAtom(fde.lsda);
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

    pub fn fmt(fde: Fde, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .fde = fde,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        fde: Fde,
        macho_file: *MachO,
    };

    fn format2(
        ctx: FormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const fde = ctx.fde;
        const macho_file = ctx.macho_file;
        try writer.print("@{x} : size({x}) : cie({d}) : {s}", .{
            fde.offset,
            fde.getSize(),
            fde.cie,
            fde.getAtom(macho_file).getName(macho_file),
        });
        if (!fde.alive) try writer.writeAll(" : [*]");
    }

    pub const Index = u32;
};

pub const Iterator = struct {
    data: []const u8,
    pos: u32 = 0,

    pub const Record = struct {
        tag: enum { fde, cie },
        offset: u32,
        size: u32,
    };

    pub fn next(it: *Iterator) !?Record {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        const size = try reader.readInt(u32, .little);
        if (size == 0xFFFFFFFF) @panic("DWARF CFI is 32bit on macOS");

        const id = try reader.readInt(u32, .little);
        const record = Record{
            .tag = if (id == 0) .cie else .fde,
            .offset = it.pos,
            .size = size,
        };
        it.pos += size + 4;

        return record;
    }
};

pub fn calcEhFrameSize(macho_file: *MachO) !u32 {
    var offset: u32 = 0;

    var cies = std.ArrayList(Cie).init(macho_file.base.allocator);
    defer cies.deinit();

    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        if (!object.has_eh_frame) continue;

        outer: for (object.cies.items) |*cie| {
            for (cies.items) |other| {
                if (other.eql(cie.*, macho_file)) {
                    // We already have a CIE record that has the exact same contents, so instead of
                    // duplicating them, we mark this one dead and set its output offset to be
                    // equal to that of the alive record. This way, we won't have to rewrite
                    // Fde.cie_index field when committing the records to file.
                    cie.out_offset = other.out_offset;
                    continue :outer;
                }
            }
            cie.alive = true;
            cie.out_offset = offset;
            offset += cie.getSize();
            try cies.append(cie.*);
        }
    }

    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        if (!object.has_eh_frame) continue;
        for (object.fdes.items) |*fde| {
            if (!fde.alive) continue;
            fde.out_offset = offset;
            offset += fde.getSize();
        }
    }

    offset += 4; // NULL terminator

    return offset;
}

pub const EH_PE = struct {
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
const leb = std.leb;
const macho = std.macho;

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
