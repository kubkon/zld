const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.unwind_info);
const macho = std.macho;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");

pub fn scanUnwindInfo(macho_file: *MachO) !void {
    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();
        for (unwind_records) |record, record_id| {
            const relocs = getRecordRelocs(macho_file, @intCast(u31, object_id), record_id);
            for (relocs) |rel| {
                if (isPersonalityFunction(record_id, rel)) {
                    // Personality function; add GOT pointer.
                    const target = parseRelocTarget(
                        macho_file,
                        record,
                        record_id,
                        @intCast(u31, object_id),
                        rel,
                    );
                    try Atom.addGotEntry(macho_file, target);
                }
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

    for (macho_file.objects.items) |object| {
        const source_sect = object.eh_frame_sect orelse continue;
        sect.size += source_sect.size;
    }
    sect.@"align" = 2;
}

pub fn writeUnwindInfo(macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];
    const seg_id = macho_file.sections.items(.segment_index)[sect_id];
    const seg = macho_file.segments.items[seg_id];

    // List of all relocated records
    var records = std.ArrayList(macho.compact_unwind_entry).init(gpa);
    defer records.deinit();

    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();
        // Contents of unwind records does not have to cover all symbol in executable section
        // so we need insert them ourselves.
        try records.ensureUnusedCapacity(object.exec_atoms.items.len);

        for (object.exec_atoms.items) |atom_index| {
            // TODO dead stripped?
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
            records.appendAssumeCapacity(record);
        }
    }

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
    log.debug("Common encodings", .{});
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
        .encodingsPageOffset = @intCast(u16, lsda_end_offset + @sizeOf(macho.unwind_info_compressed_second_level_page_header)),
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
            record.*,
            record_id,
            object_id,
            rel,
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
    record: macho.compact_unwind_entry,
    record_id: usize,
    object_id: u31,
    rel: macho.relocation_info,
) MachO.SymbolWithLoc {
    const tracy = trace(@src());
    defer tracy.end();

    const object = &macho_file.objects.items[object_id];

    if (rel.r_extern == 0) {
        const sect_id = @intCast(u8, rel.r_symbolnum - 1);
        const base_offset = @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry));
        const rel_offset = @intCast(u32, rel.r_address - base_offset);
        const bytes = mem.asBytes(&record);

        assert(rel.r_pcrel == 0 and rel.r_length == 3);
        const address_in_section = mem.readIntLittle(i64, bytes[rel_offset..][0..8]);

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
