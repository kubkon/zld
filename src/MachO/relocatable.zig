pub fn flush(macho_file: *MachO) !void {
    claimUnresolved(macho_file);
    try initOutputSections(macho_file);
    try macho_file.sortSections();
    try macho_file.addAtomsToSections();
    try calcSectionSizes(macho_file);

    state_log.debug("{}", .{macho_file.dumpState()});

    macho_file.base.fatal("-r mode unimplemented", .{});
    return error.Unimplemented;
}

fn claimUnresolved(macho_file: *MachO) void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;

        for (object.symbols.items, 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @intCast(i));
            const nlist = object.symtab.items(.nlist)[nlist_idx];
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = macho_file.getSymbol(sym_index);
            if (sym.getFile(macho_file) != null) continue;

            sym.value = 0;
            sym.atom = 0;
            sym.nlist_idx = nlist_idx;
            sym.file = index;
            sym.flags.weak_ref = nlist.weakRef();
            sym.flags.import = true;
        }
    }
}

fn initOutputSections(macho_file: *MachO) !void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = macho_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.initOutputSection(atom.getInputSection(macho_file), macho_file);
        }
    }

    const needs_unwind_info = for (macho_file.objects.items) |index| {
        if (macho_file.getFile(index).?.object.has_unwind) break true;
    } else false;
    if (needs_unwind_info) {
        macho_file.unwind_info_sect_index = try macho_file.addSection("__TEXT", "__compact_unwind", .{
            .flags = macho.S_ATTR_DEBUG,
        });
    }

    const needs_eh_frame = for (macho_file.objects.items) |index| {
        if (macho_file.getFile(index).?.object.has_eh_frame) break true;
    } else false;
    if (needs_eh_frame) {
        assert(needs_unwind_info);
        macho_file.eh_frame_sect_index = try macho_file.addSection("__TEXT", "__eh_frame", .{});
    }

    // TODO __DWARF sections
}

fn calcSectionSizes(macho_file: *MachO) !void {
    const slice = macho_file.sections.slice();
    for (slice.items(.header), slice.items(.atoms)) |*header, atoms| {
        if (atoms.items.len == 0) continue;
        for (atoms.items) |atom_index| {
            const atom = macho_file.getAtom(atom_index).?;
            const atom_alignment = try math.powi(u32, 2, atom.alignment);
            const offset = mem.alignForward(u64, header.size, atom_alignment);
            const padding = offset - header.size;
            atom.value = offset;
            header.size += padding + atom.size;
            header.@"align" = @max(header.@"align", atom.alignment);
        }
    }

    if (macho_file.unwind_info_sect_index) |index| {
        const sect = &macho_file.sections.items(.header)[index];
        sect.size = calcCompactUnwindSize(macho_file);
        sect.@"align" = 2;
    }

    if (macho_file.eh_frame_sect_index) |index| {
        const sect = &macho_file.sections.items(.header)[index];
        sect.size = try eh_frame.calcSize(macho_file);
        sect.@"align" = 3;
    }

    // TODO __DWARF sections
}

fn calcCompactUnwindSize(macho_file: *MachO) usize {
    var size: usize = 0;
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.unwind_records.items) |irec| {
            const rec = macho_file.getUnwindRecord(irec);
            if (rec.alive) {
                size += 1;
            }
        }
    }
    return size * @sizeOf(u32);
}

const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const state_log = std.log.scoped(.state);
const std = @import("std");

const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
