const UnwindInfo = @This();

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
const AtomIndex = MachO.AtomIndex;
const EhFrameRecord = @import("EhFrameRecord.zig");
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");

gpa: Allocator,

/// List of all unwind records gathered from all objects and sorted
/// by source function address
records: std.ArrayListUnmanaged(macho.compact_unwind_entry) = .{},
records_lookup: std.AutoHashMapUnmanaged(AtomIndex, u32) = .{},

/// List of all personalities referenced by either unwind info entries or __eh_frame entries.
personalities: std.ArrayListUnmanaged(MachO.SymbolWithLoc) = .{},

pub fn deinit(info: *UnwindInfo) void {
    info.records.deinit(info.gpa);
    info.records_lookup.deinit(info.gpa);
    info.personalities.deinit(info.gpa);
}

pub fn scanRelocs(info: UnwindInfo, macho_file: *MachO) !void {
    _ = info;
    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();
        for (object.exec_atoms.items) |atom_index| {
            const record_id = object.unwind_records_lookup.get(atom_index) orelse continue;
            const record = unwind_records[record_id];
            const enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);
            switch (enc) {
                .frame, .frameless => if (getPersonalityFunctionReloc(
                    macho_file,
                    @intCast(u31, object_id),
                    record_id,
                )) |rel| {
                    // Personality function; add GOT pointer.
                    const target = parseRelocTarget(
                        macho_file,
                        @intCast(u31, object_id),
                        rel,
                        mem.asBytes(&record),
                        @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry)),
                    );
                    try Atom.addGotEntry(macho_file, target);
                },
                .dwarf => {
                    // Done separately
                },
            }
        }
    }
}

pub fn collect(info: *UnwindInfo, macho_file: *MachO) !void {
    try info.personalities.ensureTotalCapacityPrecise(info.gpa, 3);

    // TODO handle dead stripping
    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();

        // Contents of unwind records does not have to cover all symbol in executable section
        // so we need insert them ourselves.
        try info.records.ensureUnusedCapacity(info.gpa, object.exec_atoms.items.len);
        try info.records_lookup.ensureUnusedCapacity(info.gpa, @intCast(u32, object.exec_atoms.items.len));

        for (object.exec_atoms.items) |atom_index| {
            var record = if (object.unwind_records_lookup.get(atom_index)) |record_id| blk: {
                var record = unwind_records[record_id];
                if (getPersonalityFunctionReloc(
                    macho_file,
                    @intCast(u31, object_id),
                    record_id,
                )) |rel| {
                    // Personality function; add GOT pointer.
                    const target = parseRelocTarget(
                        macho_file,
                        @intCast(u31, object_id),
                        rel,
                        mem.asBytes(&record),
                        @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry)),
                    );
                    const personality_index = info.getPersonalityFunction(target) orelse inner: {
                        const personality_index = @intCast(u2, info.personalities.items.len);
                        info.personalities.appendAssumeCapacity(target);
                        break :inner personality_index;
                    };

                    record.personalityFunction = personality_index + 1;

                    var enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);
                    switch (enc) {
                        .frame => |*x| x.personality_index = personality_index + 1,
                        .frameless => |*x| x.personality_index = personality_index + 1,
                        .dwarf => |*x| x.personality_index = personality_index + 1,
                    }
                    record.compactUnwindEncoding = enc.toU32();
                }
                break :blk record;
            } else macho.compact_unwind_entry{
                .rangeStart = 0,
                .rangeLength = 0,
                .compactUnwindEncoding = 0,
                .personalityFunction = 0,
                .lsda = 0,
            };

            const atom = macho_file.getAtom(atom_index);
            const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            record.rangeStart = sym.n_value;
            record.rangeLength = @intCast(u32, atom.size);

            const record_id = @intCast(u32, info.records.items.len);
            info.records.appendAssumeCapacity(record);
            info.records_lookup.putAssumeCapacityNoClobber(atom_index, record_id);
        }
    }

    for (info.records.items) |record, i| {
        log.debug("Unwind record at offset 0x{x}", .{i * @sizeOf(macho.compact_unwind_entry)});
        log.debug("  start: 0x{x}", .{record.rangeStart});
        log.debug("  length: 0x{x}", .{record.rangeLength});
        log.debug("  compact encoding: 0x{x:0>8}", .{record.compactUnwindEncoding});
        log.debug("  personality: 0x{x}", .{record.personalityFunction});
        log.debug("  LSDA: 0x{x}", .{record.lsda});
    }
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

fn getRelocs(
    macho_file: *MachO,
    object_id: u31,
    record_id: usize,
) []align(1) const macho.relocation_info {
    const object = &macho_file.objects.items[object_id];
    const rel_pos = object.unwind_relocs_lookup[record_id];
    const relocs = object.getRelocs(object.unwind_info_sect.?);
    return relocs[rel_pos.start..][0..rel_pos.len];
}

fn getPersonalityFunctionReloc(
    macho_file: *MachO,
    object_id: u31,
    record_id: usize,
) ?macho.relocation_info {
    const relocs = getRelocs(macho_file, object_id, record_id);
    const base_offset = @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry));
    for (relocs) |rel| {
        const rel_offset = rel.r_address - base_offset;
        if (rel_offset == 16) return rel;
    }
    return null;
}

fn getPersonalityFunction(info: UnwindInfo, global_index: MachO.SymbolWithLoc) ?u2 {
    for (info.personalities.items) |val, i| {
        if (val.eql(global_index)) return @intCast(u2, i);
    }
    return null;
}
