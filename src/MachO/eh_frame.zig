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
const EhFrameRecord = @import("../eh_frame.zig").EhFrameRecord;
pub const Iterator = @import("../eh_frame.zig").Iterator;
const MachO = @import("../MachO.zig");
const UnwindInfo = @import("UnwindInfo.zig");

pub fn scanRelocs(macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    for (macho_file.objects.items, 0..) |*object, object_id| {
        var cies = std.AutoHashMap(u32, void).init(gpa);
        defer cies.deinit();

        var it = object.getEhFrameRecordsIterator();

        for (object.exec_atoms.items) |atom_index| {
            const fde_offset = object.eh_frame_records_lookup.get(atom_index) orelse continue;
            if (object.eh_frame_relocs_lookup.get(fde_offset).?.dead) continue;
            it.seekTo(fde_offset);
            const fde = (try it.next()).?;

            const cie_ptr = fde.getCiePointer();
            const cie_offset = fde_offset + 4 - cie_ptr;

            if (!cies.contains(cie_offset)) {
                try cies.putNoClobber(cie_offset, {});
                it.seekTo(cie_offset);
                const cie = (try it.next()).?;
                if (getPersonalityPointerReloc(cie, macho_file, @intCast(u32, object_id), cie_offset)) |target| {
                    try Atom.addGotEntry(macho_file, target);
                }
            }
        }
    }
}

pub fn getPersonalityPointerReloc(
    rec: anytype,
    macho_file: *MachO,
    object_id: u32,
    source_offset: u32,
) ?MachO.SymbolWithLoc {
    const cpu_arch = macho_file.options.target.cpu_arch.?;
    const relocs = getRelocs(macho_file, object_id, source_offset);
    for (relocs) |rel| {
        switch (cpu_arch) {
            .aarch64 => {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
                switch (rel_type) {
                    .ARM64_RELOC_SUBTRACTOR,
                    .ARM64_RELOC_UNSIGNED,
                    => continue,
                    .ARM64_RELOC_POINTER_TO_GOT => {},
                    else => unreachable,
                }
            },
            .x86_64 => {
                const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
                switch (rel_type) {
                    .X86_64_RELOC_GOT => {},
                    else => unreachable,
                }
            },
            else => unreachable,
        }
        const target = Atom.parseRelocTarget(macho_file, .{
            .object_id = object_id,
            .rel = rel,
            .code = rec.data,
            .base_offset = @intCast(i32, source_offset) + 4,
        });
        return target;
    }
    return null;
}

pub fn relocate(rec: *EhFrameRecord(true), macho_file: *MachO, object_id: u32, ctx: struct {
    source_offset: u32,
    out_offset: u32,
    sect_addr: u64,
}) !void {
    const cpu_arch = macho_file.options.target.cpu_arch.?;
    const relocs = getRelocs(macho_file, object_id, ctx.source_offset);

    for (relocs) |rel| {
        const target = Atom.parseRelocTarget(macho_file, .{
            .object_id = object_id,
            .rel = rel,
            .code = rec.data,
            .base_offset = @intCast(i32, ctx.source_offset) + 4,
        });
        const rel_offset = @intCast(u32, rel.r_address - @intCast(i32, ctx.source_offset) - 4);
        const source_addr = ctx.sect_addr + rel_offset + ctx.out_offset + 4;

        switch (cpu_arch) {
            .aarch64 => {
                const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
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
            },
            .x86_64 => {
                const rel_type = @intToEnum(macho.reloc_type_x86_64, rel.r_type);
                switch (rel_type) {
                    .X86_64_RELOC_GOT => {
                        const target_addr = try Atom.getRelocTargetAddress(macho_file, target, true, false);
                        const addend = mem.readIntLittle(i32, rec.data[rel_offset..][0..4]);
                        const adjusted_target_addr = @intCast(u64, @intCast(i64, target_addr) + addend);
                        const disp = try Atom.calcPcRelativeDisplacementX86(source_addr, adjusted_target_addr, 0);
                        mem.writeIntLittle(i32, rec.data[rel_offset..][0..4], disp);
                    },
                    else => unreachable,
                }
            },
            else => unreachable,
        }
    }
}

pub fn calcSectionSize(macho_file: *MachO, unwind_info: *const UnwindInfo) !void {
    const sect_id = macho_file.getSectionByName("__TEXT", "__eh_frame") orelse return;
    const sect = &macho_file.sections.items(.header)[sect_id];
    sect.@"align" = 3;
    sect.size = 0;

    const cpu_arch = macho_file.options.target.cpu_arch.?;
    const gpa = macho_file.base.allocator;
    var size: u32 = 0;

    for (macho_file.objects.items) |*object| {
        var cies = std.AutoHashMap(u32, u32).init(gpa);
        defer cies.deinit();

        var eh_it = object.getEhFrameRecordsIterator();

        for (object.exec_atoms.items) |atom_index| {
            const fde_record_offset = object.eh_frame_records_lookup.get(atom_index) orelse continue;
            if (object.eh_frame_relocs_lookup.get(fde_record_offset).?.dead) continue;

            const record_id = unwind_info.records_lookup.get(atom_index) orelse continue;
            const record = unwind_info.records.items[record_id];

            // TODO skip this check if no __compact_unwind is present
            const is_dwarf = UnwindInfo.UnwindEncoding.isDwarf(record.compactUnwindEncoding, cpu_arch);
            if (!is_dwarf) continue;

            eh_it.seekTo(fde_record_offset);
            const source_fde_record = (try eh_it.next()).?;

            const cie_ptr = source_fde_record.getCiePointer();
            const cie_offset = fde_record_offset + 4 - cie_ptr;

            const gop = try cies.getOrPut(cie_offset);
            if (!gop.found_existing) {
                eh_it.seekTo(cie_offset);
                const source_cie_record = (try eh_it.next()).?;
                gop.value_ptr.* = size;
                size += source_cie_record.getSize();
            }

            size += source_fde_record.getSize();
        }
    }

    sect.size = size;
}

pub fn write(macho_file: *MachO, unwind_info: *UnwindInfo) !void {
    const sect_id = macho_file.getSectionByName("__TEXT", "__eh_frame") orelse return;
    const sect = macho_file.sections.items(.header)[sect_id];
    const seg_id = macho_file.sections.items(.segment_index)[sect_id];
    const seg = macho_file.segments.items[seg_id];

    const cpu_arch = macho_file.options.target.cpu_arch.?;

    const gpa = macho_file.base.allocator;
    var eh_records = std.AutoArrayHashMap(u32, EhFrameRecord(true)).init(gpa);
    defer {
        for (eh_records.values()) |*rec| {
            rec.deinit(gpa);
        }
        eh_records.deinit();
    }

    var eh_frame_offset: u32 = 0;

    for (macho_file.objects.items, 0..) |*object, object_id| {
        try eh_records.ensureUnusedCapacity(2 * @intCast(u32, object.exec_atoms.items.len));

        var cies = std.AutoHashMap(u32, u32).init(gpa);
        defer cies.deinit();

        var eh_it = object.getEhFrameRecordsIterator();

        for (object.exec_atoms.items) |atom_index| {
            const fde_record_offset = object.eh_frame_records_lookup.get(atom_index) orelse continue;
            if (object.eh_frame_relocs_lookup.get(fde_record_offset).?.dead) continue;

            const record_id = unwind_info.records_lookup.get(atom_index) orelse continue;
            const record = &unwind_info.records.items[record_id];

            // TODO skip this check if no __compact_unwind is present
            const is_dwarf = UnwindInfo.UnwindEncoding.isDwarf(record.compactUnwindEncoding, cpu_arch);
            if (!is_dwarf) continue;

            eh_it.seekTo(fde_record_offset);
            const source_fde_record = (try eh_it.next()).?;

            const cie_ptr = source_fde_record.getCiePointer();
            const cie_offset = fde_record_offset + 4 - cie_ptr;

            const gop = try cies.getOrPut(cie_offset);
            if (!gop.found_existing) {
                eh_it.seekTo(cie_offset);
                const source_cie_record = (try eh_it.next()).?;
                var cie_record = try source_cie_record.toOwned(gpa);
                try relocate(&cie_record, macho_file, @intCast(u32, object_id), .{
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
            try relocate(&fde_record, macho_file, @intCast(u32, object_id), .{
                .source_offset = fde_record_offset,
                .out_offset = eh_frame_offset,
                .sect_addr = sect.addr,
            });

            switch (cpu_arch) {
                .aarch64 => {}, // relocs take care of LSDA pointers
                .x86_64 => {
                    // We need to relocate target symbol address ourselves.
                    const atom = macho_file.getAtom(atom_index);
                    const atom_sym = macho_file.getSymbol(atom.getSymbolWithLoc());
                    try fde_record.setTargetSymbolAddress(atom_sym.n_value, .{
                        .base_addr = sect.addr,
                        .base_offset = eh_frame_offset,
                    });

                    // We need to parse LSDA pointer and relocate ourselves.
                    const cie_record = eh_records.get(
                        eh_frame_offset + 4 - fde_record.getCiePointer(),
                    ).?;
                    const eh_frame_sect = object.getSourceSection(object.eh_frame_sect_id.?);
                    const source_lsda_ptr = try fde_record.getLsdaPointer(cie_record, .{
                        .base_addr = eh_frame_sect.addr,
                        .base_offset = fde_record_offset,
                    });
                    if (source_lsda_ptr) |ptr| {
                        const sym_index = object.getSymbolByAddress(ptr, null);
                        const sym = object.symtab[sym_index];
                        try fde_record.setLsdaPointer(cie_record, sym.n_value, .{
                            .base_addr = sect.addr,
                            .base_offset = eh_frame_offset,
                        });
                    }
                },
                else => unreachable,
            }

            eh_records.putAssumeCapacityNoClobber(eh_frame_offset, fde_record);

            UnwindInfo.UnwindEncoding.setDwarfSectionOffset(
                &record.compactUnwindEncoding,
                cpu_arch,
                @intCast(u24, eh_frame_offset),
            );

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

pub fn getRelocs(macho_file: *MachO, object_id: u32, source_offset: u32) []const macho.relocation_info {
    const object = &macho_file.objects.items[object_id];
    assert(object.hasEhFrameRecords());
    const urel = object.eh_frame_relocs_lookup.get(source_offset) orelse
        return &[0]macho.relocation_info{};
    const all_relocs = object.getRelocs(object.eh_frame_sect_id.?);
    return all_relocs[urel.reloc.start..][0..urel.reloc.len];
}
