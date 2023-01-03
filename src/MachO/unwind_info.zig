const std = @import("std");
const assert = std.debug.assert;
const leb = std.leb;
const log = std.log.scoped(.unwind_info);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");

pub fn scanUnwindInfo(macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();

        var cies = std.AutoHashMap(u32, void).init(gpa);
        defer cies.deinit();

        var it = object.getEhFrameIterator();

        for (object.exec_atoms.items) |atom_index| {
            const record_id = object.unwind_records_lookup.get(atom_index) orelse continue;
            const record = unwind_records[record_id];
            const enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);
            switch (enc) {
                .frame, .frameless => {
                    const relocs = getRecordRelocs(macho_file, @intCast(u31, object_id), record_id);
                    for (relocs) |rel| if (isPersonalityFunction(record_id, rel)) {
                        // Personality function; add GOT pointer.
                        const target = parseRelocTarget(
                            macho_file,
                            @intCast(u31, object_id),
                            rel,
                            mem.asBytes(&record),
                            @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry)),
                        );
                        try Atom.addGotEntry(macho_file, target);
                    };
                },
                .dwarf => {
                    const fde_offset = object.eh_frame_records_lookup.get(atom_index).?; // TODO turn into an error
                    it.seekTo(fde_offset);
                    const fde = (try it.next()).?;

                    const cie_ptr = fde.getCiePointer();
                    const cie_offset = fde_offset + 4 - cie_ptr;

                    if (!cies.contains(cie_offset)) {
                        try cies.putNoClobber(cie_offset, {});
                        it.seekTo(cie_offset);
                        const cie = (try it.next()).?;
                        try cie.scan(macho_file, @intCast(u31, object_id), cie_offset);
                    }

                    try fde.scan(macho_file, @intCast(u31, object_id), fde_offset);
                },
            }
        }
    }
}

pub fn calcUnwindInfoSectionSizes(macho_file: *MachO) !void {
    var sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
    var sect = &macho_file.sections.items(.header)[sect_id];

    // TODO finish this!
    sect.size = 0x1000;
    sect.@"align" = 2;

    sect_id = macho_file.getSectionByName("__TEXT", "__eh_frame") orelse return;
    sect = &macho_file.sections.items(.header)[sect_id];
    sect.size = 0;

    for (macho_file.objects.items) |object| {
        const source_sect = object.eh_frame_sect orelse continue;
        sect.size += source_sect.size;
    }
    sect.@"align" = 2;
}

fn writeEhFrames(macho_file: *MachO, eh_records: anytype) !void {
    const sect_id = macho_file.getSectionByName("__TEXT", "__eh_frame") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];

    const gpa = macho_file.base.allocator;
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    const writer = buffer.writer();

    for (eh_records) |record| {
        try writer.writeIntLittle(u32, record.size);
        try buffer.appendSlice(record.data);
    }

    try macho_file.base.file.pwriteAll(buffer.items, sect.offset);
}

pub fn writeUnwindInfo(macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];
    const seg_id = macho_file.sections.items(.segment_index)[sect_id];
    const seg = macho_file.segments.items[seg_id];

    const eh_sect_addr = if (macho_file.getSectionByName("__TEXT", "__eh_frame")) |eh_sect_id|
        macho_file.sections.items(.header)[eh_sect_id].addr
    else
        null;

    // List of all relocated records
    var records = std.ArrayList(macho.compact_unwind_entry).init(gpa);
    defer records.deinit();

    var eh_records = std.AutoArrayHashMap(u32, EhFrameIterator.Record(true)).init(gpa);
    defer {
        for (eh_records.values()) |*rec| {
            rec.deinit(gpa);
        }
        eh_records.deinit();
    }

    // TODO dead stripping
    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();
        // Contents of unwind records does not have to cover all symbol in executable section
        // so we need insert them ourselves.
        try records.ensureUnusedCapacity(object.exec_atoms.items.len);
        if (object.eh_frame_sect != null) {
            try eh_records.ensureUnusedCapacity(2 * @intCast(u32, object.exec_atoms.items.len));
        }

        var cies = std.AutoHashMap(u32, u32).init(gpa);
        defer cies.deinit();

        var eh_it = object.getEhFrameIterator();
        var eh_frame_offset: u32 = 0;

        for (object.exec_atoms.items) |atom_index| {
            const record_id = object.unwind_records_lookup.get(atom_index) orelse {
                const atom = macho_file.getAtom(atom_index);
                const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
                records.appendAssumeCapacity(.{
                    .rangeStart = sym.n_value - seg.vmaddr,
                    .rangeLength = @intCast(u32, atom.size),
                    .compactUnwindEncoding = 0,
                    .personalityFunction = 0,
                    .lsda = 0,
                });
                continue;
            };
            var record = unwind_records[record_id];
            var enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);

            try relocateRecord(
                macho_file,
                @intCast(u31, object_id),
                record_id,
                &record,
            );
            record.rangeStart -= seg.vmaddr;
            if (record.personalityFunction > 0) {
                record.personalityFunction -= seg.vmaddr;
            }
            if (record.lsda > 0) {
                record.lsda -= seg.vmaddr;
            }

            if (enc == .dwarf) {
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
                    try cie_record.relocate(macho_file, @intCast(u31, object_id), .{
                        .source_offset = cie_offset,
                        .out_offset = eh_frame_offset,
                        .sect_addr = eh_sect_addr.?,
                    });
                    eh_records.putAssumeCapacityNoClobber(eh_frame_offset, cie_record);
                    gop.value_ptr.* = eh_frame_offset;
                    eh_frame_offset += cie_record.getSize();
                }

                var fde_record = try source_fde_record.toOwned(gpa);
                fde_record.setCiePointer(eh_frame_offset + 4 - gop.value_ptr.*);
                try fde_record.relocate(macho_file, @intCast(u31, object_id), .{
                    .source_offset = fde_record_offset,
                    .out_offset = eh_frame_offset,
                    .sect_addr = eh_sect_addr.?,
                });
                eh_records.putAssumeCapacityNoClobber(eh_frame_offset, fde_record);

                enc.dwarf.section_offset = @intCast(u24, eh_frame_offset);

                const cie_record = eh_records.get(eh_frame_offset + 4 - fde_record.getCiePointer()).?;
                const personality_ptr = try cie_record.getPersonalityPointer(.{
                    .base_addr = eh_sect_addr.?,
                    .base_offset = eh_frame_offset + 4 - fde_record.getCiePointer(),
                });
                const lsda_ptr = try fde_record.getLsdaPointer(cie_record, .{
                    .base_addr = eh_sect_addr.?,
                    .base_offset = eh_frame_offset,
                });
                if (personality_ptr) |ptr| {
                    record.personalityFunction = ptr - seg.vmaddr;
                }
                if (lsda_ptr) |ptr| {
                    record.lsda = ptr - seg.vmaddr;
                }

                record.compactUnwindEncoding = enc.toU32();
                eh_frame_offset += fde_record.getSize();
            }

            records.appendAssumeCapacity(record);
        }
    }

    // Write __eh_frame data (if any)
    try writeEhFrames(macho_file, eh_records.values());

    // Collect personalities
    var personalities = std.AutoArrayHashMap(u32, void).init(gpa);
    defer personalities.deinit();

    for (records.items) |record| {
        if (record.personalityFunction == 0) continue;
        _ = try personalities.put(@intCast(u32, record.personalityFunction), {});
    }

    for (personalities.keys()) |key, i| {
        log.debug("Personalities:", .{});
        log.debug("  {d}: 0x{x}", .{ i, key });
    }

    // Fix-up encodings that require personality pointer
    for (records.items) |*record| {
        if (record.personalityFunction == 0) continue;
        const offset = @intCast(u32, record.personalityFunction);
        var enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);
        switch (enc) {
            .frame => |*x| x.personality_index = @intCast(u2, personalities.getIndex(offset).? + 1),
            .frameless => |*x| x.personality_index = @intCast(u2, personalities.getIndex(offset).? + 1),
            .dwarf => |*x| x.personality_index = @intCast(u2, personalities.getIndex(offset).? + 1),
        }
        record.compactUnwindEncoding = enc.toU32();
    }

    for (records.items) |record, i| {
        log.debug("Unwind record at offset 0x{x}", .{i * @sizeOf(macho.compact_unwind_entry)});
        log.debug("  start: 0x{x}", .{record.rangeStart});
        log.debug("  length: 0x{x}", .{record.rangeLength});
        log.debug("  compact encoding: 0x{x:0>8}", .{record.compactUnwindEncoding});
        log.debug("  personality: 0x{x}", .{record.personalityFunction});
        log.debug("  LSDA: 0x{x}", .{record.lsda});
    }

    // Find common encodings
    var common_encodings_counts = std.AutoHashMap(u32, u32).init(gpa);
    defer common_encodings_counts.deinit();

    for (records.items) |record| {
        const gop = try common_encodings_counts.getOrPut(record.compactUnwindEncoding);
        if (!gop.found_existing) {
            gop.value_ptr.* = 0;
        }
        gop.value_ptr.* += 1;
    }

    var common_encodings = std.AutoArrayHashMap(u32, void).init(gpa);
    defer common_encodings.deinit();
    log.debug("Common encodings:", .{});
    {
        var it = common_encodings_counts.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == 1) continue;
            try common_encodings.putNoClobber(entry.key_ptr.*, {});
            log.debug("  {d}: 0x{x:0>8}", .{ common_encodings.getIndex(entry.key_ptr.*).?, entry.key_ptr.* });
        }
    }

    // TODO how do I work out how many records can go in a single page?
    // I think we might need to partition the address space into pages
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    var cwriter = std.io.countingWriter(buffer.writer());
    const writer = cwriter.writer();

    const common_encodings_offset: u32 = @sizeOf(macho.unwind_info_section_header);
    const common_encodings_count: u32 = @intCast(u32, common_encodings.count());
    const personalities_offset: u32 = common_encodings_offset + common_encodings_count * @sizeOf(u32);
    const personalities_count: u32 = @intCast(u32, personalities.count());
    const indexes_offset: u32 = personalities_offset + personalities_count * @sizeOf(u32);
    const indexes_count: u32 = 2;

    try writer.writeStruct(macho.unwind_info_section_header{
        .commonEncodingsArraySectionOffset = common_encodings_offset,
        .commonEncodingsArrayCount = common_encodings_count,
        .personalityArraySectionOffset = personalities_offset,
        .personalityArrayCount = personalities_count,
        .indexSectionOffset = indexes_offset,
        .indexCount = indexes_count,
    });
    try writer.writeAll(mem.sliceAsBytes(common_encodings.keys()));
    try writer.writeAll(mem.sliceAsBytes(personalities.keys()));

    const first_record = records.items[0];
    const last_record = records.items[records.items.len - 1];
    const sentinel_address = @intCast(u32, last_record.rangeStart + last_record.rangeLength);

    const index_headers_backpatch = cwriter.bytes_written;
    try writer.writeStruct(macho.unwind_info_section_header_index_entry{
        .functionOffset = @intCast(u32, first_record.rangeStart),
        .secondLevelPagesSectionOffset = 0,
        .lsdaIndexArraySectionOffset = 0,
    });
    try writer.writeStruct(macho.unwind_info_section_header_index_entry{
        .functionOffset = sentinel_address,
        .secondLevelPagesSectionOffset = 0,
        .lsdaIndexArraySectionOffset = 0,
    });

    const lsda_start_offset = @intCast(u32, cwriter.bytes_written);
    mem.writeIntLittle(u32, buffer.items[index_headers_backpatch + 8 ..][0..4], lsda_start_offset);

    log.debug("LSDAs:", .{});
    for (records.items) |record| {
        if (record.lsda == 0) continue;
        log.debug("  {x}, lsda({x})", .{ record.rangeStart, record.lsda });
        try writer.writeStruct(macho.unwind_info_section_header_lsda_index_entry{
            .functionOffset = @intCast(u32, record.rangeStart),
            .lsdaOffset = @intCast(u32, record.lsda),
        });
    }

    const lsda_end_offset = @intCast(u32, cwriter.bytes_written);
    mem.writeIntLittle(u32, buffer.items[index_headers_backpatch + 4 ..][0..4], lsda_end_offset);
    mem.writeIntLittle(
        u32,
        buffer.items[index_headers_backpatch +
            (indexes_count - 1) * @sizeOf(macho.unwind_info_section_header_index_entry) +
            8 ..][0..4],
        lsda_end_offset,
    );

    var page_encodings = std.AutoArrayHashMap(u32, void).init(gpa);
    defer page_encodings.deinit();

    log.debug("Page encodings", .{});
    for (records.items) |record| {
        if (common_encodings.contains(record.compactUnwindEncoding)) continue;
        try page_encodings.putNoClobber(record.compactUnwindEncoding, {});
        log.debug("  {d}: 0x{x:0>8}", .{
            page_encodings.getIndex(record.compactUnwindEncoding).?,
            record.compactUnwindEncoding,
        });
    }

    try writer.writeStruct(macho.unwind_info_compressed_second_level_page_header{
        .entryPageOffset = 0,
        .entryCount = @intCast(u16, records.items.len),
        .encodingsPageOffset = @sizeOf(macho.unwind_info_compressed_second_level_page_header),
        .encodingsCount = @intCast(u16, page_encodings.count()),
    });

    for (page_encodings.keys()) |enc| {
        try writer.writeIntLittle(u32, enc);
    }

    const page_offset = @intCast(u16, cwriter.bytes_written - lsda_end_offset);
    mem.writeIntLittle(u16, buffer.items[lsda_end_offset + 4 ..][0..2], page_offset);

    log.debug("Compressed page entries", .{});
    for (records.items) |record, i| {
        const compressed = macho.UnwindInfoCompressedEntry{
            .funcOffset = @intCast(u24, record.rangeStart - first_record.rangeStart),
            .encodingIndex = if (common_encodings.getIndex(record.compactUnwindEncoding)) |id|
                @intCast(u8, id)
            else
                @intCast(u8, common_encodings.count() + page_encodings.getIndex(record.compactUnwindEncoding).?),
        };
        log.debug("  {d}: {x}, enc({d}) => {x}, {}", .{
            i,
            compressed.funcOffset,
            compressed.encodingIndex,
            @bitCast(u32, compressed),
            compressed,
        });
        try writer.writeStruct(compressed);
    }

    try macho_file.base.file.pwriteAll(buffer.items, sect.offset);
}

fn relocateRecord(
    macho_file: *MachO,
    object_id: u31,
    record_id: usize,
    record: *macho.compact_unwind_entry,
) !void {
    const object = &macho_file.objects.items[object_id];
    const relocs = getRecordRelocs(macho_file, object_id, record_id);
    const bytes = mem.asBytes(record);
    const base_offset = @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry));

    for (relocs) |rel| {
        const target = parseRelocTarget(
            macho_file,
            object_id,
            rel,
            mem.asBytes(record),
            base_offset,
        );
        const rel_offset = @intCast(u32, rel.r_address - base_offset);
        const is_via_got = isPersonalityFunction(record_id, rel); // Personality function is via GOT.
        const target_base_addr = try Atom.getRelocTargetAddress(macho_file, target, is_via_got, false);
        var addend = mem.readIntLittle(i64, bytes[rel_offset..][0..8]);

        if (rel.r_extern == 0) {
            const base_addr = if (target.sym_index > object.source_address_lookup.len)
                @intCast(i64, object.getSourceSection(@intCast(u16, rel.r_symbolnum - 1)).addr)
            else
                object.source_address_lookup[target.sym_index];
            addend -= base_addr;
        }

        mem.writeIntLittle(i64, bytes[rel_offset..][0..8], @intCast(i64, target_base_addr) + addend);
    }
}

pub fn getRecordRelocs(
    macho_file: *MachO,
    object_id: u31,
    record_id: usize,
) []align(1) const macho.relocation_info {
    const object = &macho_file.objects.items[object_id];
    const rel_pos = object.unwind_relocs_lookup[record_id];
    const relocs = object.getRelocs(object.unwind_info_sect.?);
    return relocs[rel_pos.start..][0..rel_pos.len];
}

pub fn parseRelocTarget(
    macho_file: *MachO,
    object_id: u31,
    rel: macho.relocation_info,
    code: []const u8,
    base_offset: i32,
) MachO.SymbolWithLoc {
    const tracy = trace(@src());
    defer tracy.end();

    const object = &macho_file.objects.items[object_id];

    if (rel.r_extern == 0) {
        const sect_id = @intCast(u8, rel.r_symbolnum - 1);
        const rel_offset = @intCast(u32, rel.r_address - base_offset);

        assert(rel.r_pcrel == 0 and rel.r_length == 3);
        const address_in_section = mem.readIntLittle(i64, code[rel_offset..][0..8]);

        // Find containing atom
        const Predicate = struct {
            addr: i64,

            pub fn predicate(pred: @This(), other: i64) bool {
                return if (other == -1) true else other > pred.addr;
            }
        };

        if (object.source_section_index_lookup[sect_id] > -1) {
            const first_sym_index = @intCast(usize, object.source_section_index_lookup[sect_id]);
            const target_sym_index = MachO.lsearch(i64, object.source_address_lookup[first_sym_index..], Predicate{
                .addr = address_in_section,
            });

            if (target_sym_index > 0) {
                return MachO.SymbolWithLoc{
                    .sym_index = @intCast(u32, first_sym_index + target_sym_index - 1),
                    .file = object_id,
                };
            }
        }

        // Start of section is not contained anywhere, return synthetic atom.
        const sym_index = object.getSectionAliasSymbolIndex(sect_id);
        return MachO.SymbolWithLoc{ .sym_index = sym_index, .file = object_id };
    }

    const sym_index = object.reverse_symtab_lookup[rel.r_symbolnum];
    const sym_loc = MachO.SymbolWithLoc{ .sym_index = sym_index, .file = object_id };
    const sym = macho_file.getSymbol(sym_loc);

    if (sym.sect() and !sym.ext()) {
        return sym_loc;
    } else if (object.globals_lookup[sym_index] > -1) {
        const global_index = @intCast(u32, object.globals_lookup[sym_index]);
        return macho_file.globals.items[global_index];
    } else return sym_loc;
}

inline fn isPersonalityFunction(record_id: usize, rel: macho.relocation_info) bool {
    const base_offset = @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry));
    const rel_offset = rel.r_address - base_offset;
    return rel_offset == 16;
}

pub const EhFrameIterator = struct {
    data: []const u8,
    pos: u32 = 0,

    pub const Tag = enum { cie, fde };

    pub fn Record(comptime mutable: bool) type {
        return struct {
            tag: Tag,
            size: u32,
            data: if (mutable) []u8 else []const u8,

            pub inline fn getSize(rec: @This()) u32 {
                return 4 + rec.size;
            }

            pub fn deinit(rec: *@This(), gpa: Allocator) void {
                comptime assert(mutable);
                gpa.free(rec.data);
            }

            pub fn getRelocs(
                macho_file: *MachO,
                object_id: u31,
                source_offset: u32,
            ) []align(1) const macho.relocation_info {
                const object = &macho_file.objects.items[object_id];
                const rel_pos = object.eh_frame_relocs_lookup.get(source_offset) orelse
                    return &[0]macho.relocation_info{};
                const all_relocs = object.getRelocs(object.eh_frame_sect.?);
                return all_relocs[rel_pos.start..][0..rel_pos.len];
            }

            pub fn scan(rec: @This(), macho_file: *MachO, object_id: u31, source_offset: u32) !void {
                const relocs = @This().getRelocs(macho_file, object_id, source_offset);

                for (relocs) |rel| {
                    const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);

                    switch (rel_type) {
                        .ARM64_RELOC_SUBTRACTOR,
                        .ARM64_RELOC_UNSIGNED,
                        => {},
                        .ARM64_RELOC_POINTER_TO_GOT => {
                            const target = parseRelocTarget(
                                macho_file,
                                object_id,
                                rel,
                                rec.data,
                                @intCast(i32, source_offset) + 4,
                            );
                            try Atom.addGotEntry(macho_file, target);
                        },
                        else => unreachable,
                    }
                }
            }

            pub fn relocate(rec: *@This(), macho_file: *MachO, object_id: u31, ctx: struct {
                source_offset: u32,
                out_offset: u32,
                sect_addr: u64,
            }) !void {
                comptime assert(mutable);

                const relocs = @This().getRelocs(macho_file, object_id, ctx.source_offset);

                for (relocs) |rel| {
                    const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                    const target = parseRelocTarget(
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
                            const target_addr = try Atom.getRelocTargetAddress(macho_file, target, true, false);
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

            pub fn getCiePointer(rec: @This()) u32 {
                assert(rec.tag == .fde);
                return mem.readIntLittle(u32, rec.data[0..4]);
            }

            pub fn setCiePointer(rec: *@This(), ptr: u32) void {
                assert(rec.tag == .fde);
                mem.writeIntLittle(u32, rec.data[0..4], ptr);
            }

            pub fn getAugmentationString(rec: @This()) []const u8 {
                assert(rec.tag == .cie);
                return mem.sliceTo(@ptrCast([*:0]const u8, rec.data.ptr + 5), 0);
            }

            pub fn getPersonalityPointer(rec: @This(), ctx: struct {
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

            pub fn getLsdaPointer(rec: @This(), cie: @This(), ctx: struct {
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

            pub fn toOwned(rec: @This(), gpa: Allocator) Allocator.Error!Record(true) {
                const data = try gpa.dupe(u8, rec.data);
                return Record(true){
                    .tag = rec.tag,
                    .size = rec.size,
                    .data = data,
                };
            }

            fn getLsdaEncoding(rec: @This()) !?u8 {
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

    pub fn next(it: *EhFrameIterator) !?Record(false) {
        if (it.pos >= it.data.len) return null;

        var stream = std.io.fixedBufferStream(it.data[it.pos..]);
        const reader = stream.reader();

        var size = try reader.readIntLittle(u32);
        if (size == 0xFFFFFFFF) {
            log.err("MachO doesn't support 64bit DWARF CFI __eh_frame records", .{});
            return error.UnsupportedDwarfCfiFormat;
        }

        const id = try reader.readIntLittle(u32);
        const tag: Tag = if (id == 0) .cie else .fde;
        const offset: u32 = 4;
        const record = Record(false){
            .tag = tag,
            .size = size,
            .data = it.data[it.pos + offset ..][0..size],
        };

        it.pos += size + offset;

        return record;
    }

    pub fn reset(it: *EhFrameIterator) void {
        it.pos = 0;
    }

    pub fn seekTo(it: *EhFrameIterator, pos: u32) void {
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
