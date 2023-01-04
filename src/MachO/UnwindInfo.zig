const UnwindInfo = @This();

const std = @import("std");
const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const fs = std.fs;
const leb = std.leb;
const log = std.log.scoped(.unwind_info);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const AtomIndex = MachO.AtomIndex;
const EhFrameRecord = eh_frame.EhFrameRecord;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");

gpa: Allocator,

/// List of all unwind records gathered from all objects and sorted
/// by source function address.
records: std.ArrayListUnmanaged(macho.compact_unwind_entry) = .{},
records_lookup: std.ArrayListUnmanaged(AtomIndex) = .{},

/// List of all personalities referenced by either unwind info entries
/// or __eh_frame entries.
personalities: std.ArrayListUnmanaged(MachO.SymbolWithLoc) = .{},

pub fn deinit(info: *UnwindInfo) void {
    info.records.deinit(info.gpa);
    info.records_lookup.deinit(info.gpa);
    info.personalities.deinit(info.gpa);
}

pub fn scanRelocs(info: UnwindInfo, macho_file: *MachO) !void {
    for (macho_file.objects.items) |*object, object_id| {
        const unwind_records = object.getUnwindRecords();

        var cies = std.AutoHashMap(u32, void).init(info.gpa);
        defer cies.deinit();

        var it = object.getEhFrameRecordsIterator();

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
                    const fde_offset = object.eh_frame_records_lookup.get(atom_index).?; // TODO turn into an error
                    it.seekTo(fde_offset);
                    const fde = (try it.next()).?;

                    const cie_ptr = fde.getCiePointer();
                    const cie_offset = fde_offset + 4 - cie_ptr;

                    if (!cies.contains(cie_offset)) {
                        try cies.putNoClobber(cie_offset, {});
                        it.seekTo(cie_offset);
                        const cie = (try it.next()).?;
                        try cie.scanRelocs(macho_file, @intCast(u31, object_id), cie_offset);
                    }

                    try fde.scanRelocs(macho_file, @intCast(u31, object_id), fde_offset);
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
        try info.records_lookup.ensureUnusedCapacity(info.gpa, object.exec_atoms.items.len);

        var cies = std.AutoHashMap(u32, void).init(info.gpa);
        defer cies.deinit();

        var it = object.getEhFrameRecordsIterator();

        for (object.exec_atoms.items) |atom_index| {
            var record = if (object.unwind_records_lookup.get(atom_index)) |record_id| blk: {
                var record = unwind_records[record_id];
                var enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);
                switch (enc) {
                    .frame, .frameless => {
                        if (getPersonalityFunctionReloc(
                            macho_file,
                            @intCast(u31, object_id),
                            record_id,
                        )) |rel| {
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

                            switch (enc) {
                                .frame => |*x| x.personality_index = personality_index + 1,
                                .frameless => |*x| x.personality_index = personality_index + 1,
                                .dwarf => unreachable,
                            }
                        }

                        if (getLsdaReloc(macho_file, @intCast(u31, object_id), record_id)) |rel| {
                            const target = parseRelocTarget(
                                macho_file,
                                @intCast(u31, object_id),
                                rel,
                                mem.asBytes(&record),
                                @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry)),
                            );
                            record.lsda = @bitCast(u64, target);
                        } else {
                            record.lsda = @bitCast(u64, MachO.SymbolWithLoc{
                                .sym_index = 0,
                                .file = -1,
                            });
                        }
                    },
                    .dwarf => |*x| {
                        const fde_offset = object.eh_frame_records_lookup.get(atom_index).?;
                        it.seekTo(fde_offset);
                        const fde = (try it.next()).?;
                        const cie_ptr = fde.getCiePointer();
                        const cie_offset = fde_offset + 4 - cie_ptr;

                        if (fde.getPersonalityPointerReloc(
                            macho_file,
                            @intCast(u31, object_id),
                            cie_offset,
                        )) |target| {
                            const personality_index = info.getPersonalityFunction(target) orelse inner: {
                                const personality_index = @intCast(u2, info.personalities.items.len);
                                info.personalities.appendAssumeCapacity(target);
                                break :inner personality_index;
                            };

                            record.personalityFunction = personality_index + 1;
                            x.personality_index = personality_index + 1;
                        }
                    },
                }
                record.compactUnwindEncoding = enc.toU32();
                break :blk record;
            } else macho.compact_unwind_entry{
                .rangeStart = 0,
                .rangeLength = 0,
                .compactUnwindEncoding = 0,
                .personalityFunction = 0,
                .lsda = @bitCast(u64, MachO.SymbolWithLoc{ .sym_index = 0, .file = -1 }),
            };

            const atom = macho_file.getAtom(atom_index);
            const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
            record.rangeStart = sym.n_value;
            record.rangeLength = @intCast(u32, atom.size);

            info.records.appendAssumeCapacity(record);
            info.records_lookup.appendAssumeCapacity(atom_index);
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

    // TODO dedup records here
    // TODO calculate required __TEXT,__unwind_info size
}

pub fn write(info: *UnwindInfo, macho_file: *MachO, file: fs.File) !void {
    _ = file;
    const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];
    _ = sect;
    const seg_id = macho_file.sections.items(.segment_index)[sect_id];
    const seg = macho_file.segments.items[seg_id];

    const text_sect_id = macho_file.getSectionByName("__TEXT", "__text").?;
    const text_sect = macho_file.sections.items(.header)[text_sect_id];

    var personalities = try std.ArrayList(u32).initCapacity(info.gpa, 3);
    defer personalities.deinit();

    for (info.personalities.items) |target| {
        const atom_index = macho_file.getGotAtomIndexForSymbol(target).?;
        const atom = macho_file.getAtom(atom_index);
        const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
        personalities.appendAssumeCapacity(@intCast(u32, sym.n_value - seg.vmaddr));
    }

    for (personalities.items) |offset, i| {
        log.debug("Personalities:", .{});
        log.debug("  {d}: 0x{x}", .{ i, offset });
    }

    for (info.records.items) |*rec| {
        // Finalize missing address values
        rec.rangeStart += text_sect.addr - seg.vmaddr;
        if (rec.personalityFunction > 0) {
            rec.personalityFunction = personalities.items[rec.personalityFunction - 1];
        }
        const lsda_target = @bitCast(MachO.SymbolWithLoc, rec.lsda);
        if (lsda_target.getFile()) |_| {
            const sym = macho_file.getSymbol(lsda_target);
            rec.lsda = sym.n_value - seg.vmaddr;
        } else {
            rec.lsda = 0;
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

fn relocate(
    macho_file: *MachO,
    object_id: u31,
    record_id: usize,
    record: *macho.compact_unwind_entry,
) !void {
    const object = &macho_file.objects.items[object_id];
    const relocs = getRelocs(macho_file, object_id, record_id);
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

fn isPersonalityFunction(record_id: usize, rel: macho.relocation_info) bool {
    const base_offset = @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry));
    const rel_offset = rel.r_address - base_offset;
    return rel_offset == 16;
}

fn getPersonalityFunctionReloc(
    macho_file: *MachO,
    object_id: u31,
    record_id: usize,
) ?macho.relocation_info {
    const relocs = getRelocs(macho_file, object_id, record_id);
    for (relocs) |rel| {
        if (isPersonalityFunction(record_id, rel)) return rel;
    }
    return null;
}

fn getPersonalityFunction(info: UnwindInfo, global_index: MachO.SymbolWithLoc) ?u2 {
    for (info.personalities.items) |val, i| {
        if (val.eql(global_index)) return @intCast(u2, i);
    }
    return null;
}

fn isLsda(record_id: usize, rel: macho.relocation_info) bool {
    const base_offset = @intCast(i32, record_id * @sizeOf(macho.compact_unwind_entry));
    const rel_offset = rel.r_address - base_offset;
    return rel_offset == 24;
}

fn getLsdaReloc(macho_file: *MachO, object_id: u31, record_id: usize) ?macho.relocation_info {
    const relocs = getRelocs(macho_file, object_id, record_id);
    for (relocs) |rel| {
        if (isLsda(record_id, rel)) return rel;
    }
    return null;
}

// TODO just a temp; remove!
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
