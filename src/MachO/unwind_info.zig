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

pub fn calcUnwindInfoSectionSize(macho_file: *MachO) !void {
    const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];

    // TODO finish this!
    sect.size = 0x1000;
    sect.@"align" = 2;
}

pub fn writeUnwindInfo(macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];
    _ = sect;

    // List of all relocated records
    var records = std.ArrayList(macho.compact_unwind_entry).init(gpa);
    defer records.deinit();

    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();
        try records.ensureUnusedCapacity(unwind_records.len);

        for (unwind_records) |record, record_id| {
            var out_record = record;
            try relocateRecord(
                macho_file,
                @intCast(u31, object_id),
                record_id,
                &out_record,
            );

            log.debug("Unwind record at offset 0x{x}", .{record_id * @sizeOf(macho.compact_unwind_entry)});
            log.debug("  start: 0x{x}", .{out_record.rangeStart});
            log.debug("  length: 0x{x}", .{out_record.rangeLength});
            log.debug("  compact encoding: 0x{x:0>8}", .{out_record.compactUnwindEncoding});
            log.debug("  personality: 0x{x}", .{out_record.personalityFunction});
            log.debug("  LSDA: 0x{x}", .{out_record.lsda});

            records.appendAssumeCapacity(out_record);
        }
    }

    // Collect personalities
    var personalities = std.AutoArrayHashMap(u64, void).init(gpa);
    defer personalities.deinit();

    for (records.items) |record| {
        if (record.personalityFunction > 0) {
            _ = try personalities.put(record.personalityFunction, {});
        }
    }

    for (personalities.keys()) |key, i| {
        log.debug("Personalities:", .{});
        log.debug("  {d}: 0x{x}", .{ i, key });
    }
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
