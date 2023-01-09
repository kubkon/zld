const std = @import("std");
const assert = std.debug.assert;
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const leb = std.leb;
const log = std.log.scoped(.eh_frame);

const Allocator = mem.Allocator;
const AtomIndex = MachO.AtomIndex;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const UnwindInfo = @import("UnwindInfo.zig");

pub fn scanRelocs(macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    for (macho_file.objects.items) |*object, object_id| {
        var cies = std.AutoHashMap(u32, void).init(gpa);
        defer cies.deinit();

        var it = object.getEhFrameRecordsIterator();

        for (object.exec_atoms.items) |atom_index| {
            const fde_offset = object.eh_frame_records_lookup.get(atom_index) orelse continue;
            it.seekTo(fde_offset);
            const fde = (try it.next()).?;

            const cie_ptr = fde.getCiePointer();
            const cie_offset = fde_offset + 4 - cie_ptr;

            if (!cies.contains(cie_offset)) {
                try cies.putNoClobber(cie_offset, {});
                it.seekTo(cie_offset);
                const cie = (try it.next()).?;
                try cie.scanRelocs(macho_file, @intCast(u32, object_id), cie_offset);
            }

            try fde.scanRelocs(macho_file, @intCast(u32, object_id), fde_offset);
        }
    }
}

pub fn calcSectionSize(macho_file: *MachO) void {
    const sect_id = macho_file.getSectionByName("__TEXT", "__eh_frame") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];
    sect.size = 0;

    for (macho_file.objects.items) |object| {
        const source_sect = object.eh_frame_sect orelse continue;
        sect.size += source_sect.size;
    }
    sect.@"align" = 2;
}

pub fn write(macho_file: *MachO, unwind_info: *UnwindInfo) !void {
    const sect_id = macho_file.getSectionByName("__TEXT", "__eh_frame") orelse return;
    const sect = macho_file.sections.items(.header)[sect_id];
    const seg_id = macho_file.sections.items(.segment_index)[sect_id];
    const seg = macho_file.segments.items[seg_id];

    const gpa = macho_file.base.allocator;
    var eh_records = std.AutoArrayHashMap(u32, EhFrameRecord(true)).init(gpa);
    defer {
        for (eh_records.values()) |*rec| {
            rec.deinit(gpa);
        }
        eh_records.deinit();
    }

    var eh_frame_offset: u32 = 0;

    for (macho_file.objects.items) |*object, object_id| {
        try eh_records.ensureUnusedCapacity(2 * @intCast(u32, object.exec_atoms.items.len));

        var cies = std.AutoHashMap(u32, u32).init(gpa);
        defer cies.deinit();

        var eh_it = object.getEhFrameRecordsIterator();

        for (object.eh_frame_records_lookup.keys()) |atom_index| {
            const fde_record_offset = object.eh_frame_records_lookup.get(atom_index).?; // TODO turn into an error
            eh_it.seekTo(fde_record_offset);
            const source_fde_record = (try eh_it.next()).?;

            const cie_ptr = source_fde_record.getCiePointer();
            const cie_offset = fde_record_offset + 4 - cie_ptr;

            const gop = try cies.getOrPut(cie_offset);
            if (!gop.found_existing) {
                eh_it.seekTo(cie_offset);
                const source_cie_record = (try eh_it.next()).?;
                var cie_record = try source_cie_record.toOwned(gpa);
                try cie_record.relocate(macho_file, @intCast(u32, object_id), .{
                    .source_offset = cie_offset,
                    .out_offset = eh_frame_offset,
                    .sect_addr = sect.addr,
                });
                eh_records.putAssumeCapacityNoClobber(eh_frame_offset, cie_record);
                gop.value_ptr.* = eh_frame_offset;
                eh_frame_offset += cie_record.getSize();
            }

            var fde_record = try source_fde_record.toOwned(gpa);
            fde_record.setCiePointer(eh_frame_offset + 4 - gop.value_ptr.*);
            try fde_record.relocate(macho_file, @intCast(u32, object_id), .{
                .source_offset = fde_record_offset,
                .out_offset = eh_frame_offset,
                .sect_addr = sect.addr,
            });
            eh_records.putAssumeCapacityNoClobber(eh_frame_offset, fde_record);

            if (unwind_info.records_lookup.get(atom_index)) |record_id| blk: {
                const record = &unwind_info.records.items[record_id];
                const is_dwarf = try UnwindInfo.isDwarf(record.*);
                if (!is_dwarf) break :blk;
                var enc = macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding) catch
                    unreachable;
                enc.dwarf.section_offset = @intCast(u24, eh_frame_offset);
                record.compactUnwindEncoding = enc.toU32();

                const cie_record = eh_records.get(
                    eh_frame_offset + 4 - fde_record.getCiePointer(),
                ).?;
                const lsda_ptr = try fde_record.getLsdaPointer(cie_record, .{
                    .base_addr = sect.addr,
                    .base_offset = eh_frame_offset,
                });
                if (lsda_ptr) |ptr| {
                    record.lsda = ptr - seg.vmaddr;
                }
            }
            eh_frame_offset += fde_record.getSize();
        }
    }

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    const writer = buffer.writer();

    for (eh_records.values()) |record| {
        try writer.writeIntLittle(u32, record.size);
        try buffer.appendSlice(record.data);
    }

    try macho_file.base.file.pwriteAll(buffer.items, sect.offset);
}
const EhFrameRecordTag = enum { cie, fde };

pub fn EhFrameRecord(comptime is_mutable: bool) type {
    return struct {
        tag: EhFrameRecordTag,
        size: u32,
        data: if (is_mutable) []u8 else []const u8,

        const Record = @This();

        pub fn deinit(rec: *Record, gpa: Allocator) void {
            comptime assert(is_mutable);
            gpa.free(rec.data);
        }

        pub fn toOwned(rec: Record, gpa: Allocator) Allocator.Error!EhFrameRecord(true) {
            const data = try gpa.dupe(u8, rec.data);
            return EhFrameRecord(true){
                .tag = rec.tag,
                .size = rec.size,
                .data = data,
            };
        }

        pub inline fn getSize(rec: Record) u32 {
            return 4 + rec.size;
        }

        pub fn scanRelocs(
            rec: Record,
            macho_file: *MachO,
            object_id: u32,
            source_offset: u32,
        ) !void {
            if (rec.getPersonalityPointerReloc(macho_file, object_id, source_offset)) |target| {
                try Atom.addGotEntry(macho_file, target);
            }
        }

        pub fn getPersonalityPointerReloc(
            rec: Record,
            macho_file: *MachO,
            object_id: u32,
            source_offset: u32,
        ) ?MachO.SymbolWithLoc {
            const relocs = getRelocs(macho_file, object_id, source_offset);
            for (relocs) |rel| {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                switch (rel_type) {
                    .ARM64_RELOC_SUBTRACTOR,
                    .ARM64_RELOC_UNSIGNED,
                    => {},
                    .ARM64_RELOC_POINTER_TO_GOT => {
                        const target = UnwindInfo.parseRelocTarget(
                            macho_file,
                            object_id,
                            rel,
                            rec.data,
                            @intCast(i32, source_offset) + 4,
                        );
                        const object = macho_file.objects.items[object_id];
                        const global = object.getGlobal(macho_file, target.sym_index) orelse target;
                        return global;
                    },
                    else => unreachable,
                }
            }
            return null;
        }

        pub fn relocate(rec: *Record, macho_file: *MachO, object_id: u32, ctx: struct {
            source_offset: u32,
            out_offset: u32,
            sect_addr: u64,
        }) !void {
            comptime assert(is_mutable);

            const relocs = getRelocs(macho_file, object_id, ctx.source_offset);

            for (relocs) |rel| {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                const target = UnwindInfo.parseRelocTarget(
                    macho_file,
                    object_id,
                    rel,
                    rec.data,
                    @intCast(i32, ctx.source_offset) + 4,
                );
                const rel_offset = @intCast(u32, rel.r_address - @intCast(i32, ctx.source_offset) - 4);
                const source_addr = ctx.sect_addr + rel_offset + ctx.out_offset + 4;

                switch (rel_type) {
                    .ARM64_RELOC_SUBTRACTOR => {
                        // Address of the __eh_frame in the source object file
                    },
                    .ARM64_RELOC_POINTER_TO_GOT => {
                        const object = macho_file.objects.items[object_id];
                        const global = object.getGlobal(macho_file, target.sym_index) orelse target;
                        const target_addr = try Atom.getRelocTargetAddress(macho_file, global, true, false);
                        const result = math.cast(i32, @intCast(i64, target_addr) - @intCast(i64, source_addr)) orelse
                            return error.Overflow;
                        mem.writeIntLittle(i32, rec.data[rel_offset..][0..4], result);
                    },
                    .ARM64_RELOC_UNSIGNED => {
                        assert(rel.r_extern == 1);
                        const target_addr = try Atom.getRelocTargetAddress(macho_file, target, false, false);
                        const result = @intCast(i64, target_addr) - @intCast(i64, source_addr);
                        mem.writeIntLittle(i64, rec.data[rel_offset..][0..8], @intCast(i64, result));
                    },
                    else => unreachable,
                }
            }
        }

        pub fn getCiePointer(rec: Record) u32 {
            assert(rec.tag == .fde);
            return mem.readIntLittle(u32, rec.data[0..4]);
        }

        pub fn setCiePointer(rec: *Record, ptr: u32) void {
            assert(rec.tag == .fde);
            mem.writeIntLittle(u32, rec.data[0..4], ptr);
        }

        pub fn getAugmentationString(rec: Record) []const u8 {
            assert(rec.tag == .cie);
            return mem.sliceTo(@ptrCast([*:0]const u8, rec.data.ptr + 5), 0);
        }

        pub fn getPersonalityPointer(rec: Record, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) !?u64 {
            assert(rec.tag == .cie);
            const aug_str = rec.getAugmentationString();

            var stream = std.io.fixedBufferStream(rec.data[9 + aug_str.len ..]);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();

            for (aug_str) |ch, i| switch (ch) {
                'z' => if (i > 0) {
                    return error.MalformedAugmentationString;
                } else {
                    _ = try leb.readULEB128(u64, reader);
                },
                'R' => {
                    _ = try reader.readByte();
                },
                'P' => {
                    const enc = try reader.readByte();
                    const offset = ctx.base_offset + 13 + aug_str.len + creader.bytes_read;
                    const ptr = try getEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), reader);
                    return ptr;
                },
                'L' => {
                    _ = try reader.readByte();
                },
                'S', 'B', 'G' => {},
                else => return error.UnknownAugmentationStringValue,
            };

            return null;
        }

        pub fn getLsdaPointer(rec: Record, cie: Record, ctx: struct {
            base_addr: u64,
            base_offset: u64,
        }) !?u64 {
            assert(rec.tag == .fde);
            const enc = (try cie.getLsdaEncoding()) orelse return null;
            var stream = std.io.fixedBufferStream(rec.data[20..]);
            const reader = stream.reader();
            _ = try reader.readByte();
            const offset = ctx.base_offset + 25;
            const ptr = try getEncodedPointer(enc, @intCast(i64, ctx.base_addr + offset), reader);
            return ptr;
        }

        fn getLsdaEncoding(rec: Record) !?u8 {
            assert(rec.tag == .cie);
            const aug_str = rec.getAugmentationString();

            const base_offset = 9 + aug_str.len;
            var stream = std.io.fixedBufferStream(rec.data[base_offset..]);
            var creader = std.io.countingReader(stream.reader());
            const reader = creader.reader();

            for (aug_str) |ch, i| switch (ch) {
                'z' => if (i > 0) {
                    return error.MalformedAugmentationString;
                } else {
                    _ = try leb.readULEB128(u64, reader);
                },
                'R' => {
                    _ = try reader.readByte();
                },
                'P' => {
                    const enc = try reader.readByte();
                    _ = try getEncodedPointer(enc, 0, reader);
                },
                'L' => {
                    const enc = try reader.readByte();
                    return enc;
                },
                'S', 'B', 'G' => {},
                else => return error.UnknownAugmentationStringValue,
            };

            return null;
        }

        fn getEncodedPointer(enc: u8, pcrel_offset: i64, reader: anytype) !?u64 {
            if (enc == EH_PE.omit) return null;

            var ptr: i64 = switch (enc & 0x0F) {
                EH_PE.absptr => @bitCast(i64, try reader.readIntLittle(u64)),
                EH_PE.udata2 => @bitCast(i16, try reader.readIntLittle(u16)),
                EH_PE.udata4 => @bitCast(i32, try reader.readIntLittle(u32)),
                EH_PE.udata8 => @bitCast(i64, try reader.readIntLittle(u64)),
                EH_PE.uleb128 => @bitCast(i64, try leb.readULEB128(u64, reader)),
                EH_PE.sdata2 => try reader.readIntLittle(i16),
                EH_PE.sdata4 => try reader.readIntLittle(i32),
                EH_PE.sdata8 => try reader.readIntLittle(i64),
                EH_PE.sleb128 => try leb.readILEB128(i64, reader),
                else => return null,
            };

            switch (enc & 0x70) {
                EH_PE.absptr => {},
                EH_PE.pcrel => ptr += pcrel_offset,
                EH_PE.datarel,
                EH_PE.textrel,
                EH_PE.funcrel,
                EH_PE.aligned,
                => return null,
                else => return null,
            }

            return @bitCast(u64, ptr);
        }
    };
}

pub fn getRelocs(
    macho_file: *MachO,
    object_id: u32,
    source_offset: u32,
) []align(1) const macho.relocation_info {
    const object = &macho_file.objects.items[object_id];
    const rel_pos = object.eh_frame_relocs_lookup.get(source_offset) orelse
        return &[0]macho.relocation_info{};
    const all_relocs = object.getRelocs(object.eh_frame_sect.?);
    return all_relocs[rel_pos.start..][0..rel_pos.len];
}

pub const Iterator = struct {
    data: []const u8,
    pos: u32 = 0,

    pub fn next(it: *Iterator) !?EhFrameRecord(false) {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        var size = try reader.readIntLittle(u32);
        if (size == 0xFFFFFFFF) {
            log.err("MachO doesn't support 64bit DWARF CFI __eh_frame records", .{});
            return error.UnsupportedDwarfCfiFormat;
        }

        const id = try reader.readIntLittle(u32);
        const tag: EhFrameRecordTag = if (id == 0) .cie else .fde;
        const offset: u32 = 4;
        const record = EhFrameRecord(false){
            .tag = tag,
            .size = size,
            .data = it.data[it.pos + offset ..][0..size],
        };

        it.pos += size + offset;

        return record;
    }

    pub fn reset(it: *Iterator) void {
        it.pos = 0;
    }

    pub fn seekTo(it: *Iterator, pos: u32) void {
        assert(pos >= 0 and pos < it.data.len);
        it.pos = pos;
    }
};

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