pub fn flush(macho_file: *MachO) !void {
    claimUnresolved(macho_file);
    try initOutputSections(macho_file);
    try macho_file.sortSections();
    try macho_file.addAtomsToSections();
    try calcSectionSizes(macho_file);

    {
        // For relocatable, we only ever need a single segment so create it now.
        const prot: macho.vm_prot_t = macho.PROT.READ | macho.PROT.WRITE | macho.PROT.EXEC;
        try macho_file.segments.append(macho_file.base.allocator, .{
            .cmdsize = @sizeOf(macho.segment_command_64),
            .segname = MachO.makeStaticString(""),
            .maxprot = prot,
            .initprot = prot,
        });
    }

    try allocateSections(macho_file);

    {
        // Allocate the single segment.
        assert(macho_file.segments.items.len == 1);
        const seg = &macho_file.segments.items[0];
        var vmaddr: u64 = 0;
        var fileoff: u64 = load_commands.calcLoadCommandsSizeObject(macho_file);
        seg.vmaddr = vmaddr;
        seg.fileoff = fileoff;

        for (macho_file.sections.items(.header)) |header| {
            vmaddr = header.addr + header.size;
            if (!header.isZerofill()) {
                fileoff = header.offset + header.size;
            }
        }

        seg.vmsize = vmaddr - seg.vmaddr;
        seg.filesize = fileoff - seg.fileoff;
    }

    macho_file.allocateAtoms();

    state_log.debug("{}", .{macho_file.dumpState()});

    try writeAtoms(macho_file);
    try writeCompactUnwind(macho_file);
    try writeEhFrame(macho_file);
    // try macho_file.calcSymtabSize();
    // try macho_file.writeSymtab();
    // TODO write data-in-code

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
        sect.@"align" = 3;
    }

    if (macho_file.eh_frame_sect_index) |index| {
        const sect = &macho_file.sections.items(.header)[index];
        sect.size = try eh_frame.calcSize(macho_file);
        sect.@"align" = 3;
    }

    // TODO __DWARF sections

    // TODO relocations
    // they should follow contiguously *after* we lay out contents of each section
    // *but* they should be before __LINKEDIT sections (symtab, data-in-code)

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
    return size * @sizeOf(macho.compact_unwind_entry);
}

fn allocateSections(macho_file: *MachO) !void {
    var fileoff = load_commands.calcLoadCommandsSizeObject(macho_file);
    var vmaddr: u64 = 0;
    const slice = macho_file.sections.slice();

    for (slice.items(.header)) |*header| {
        const alignment = try math.powi(u32, 2, header.@"align");
        vmaddr = mem.alignForward(u64, vmaddr, alignment);
        header.addr = vmaddr;
        vmaddr += header.size;

        if (!header.isZerofill()) {
            fileoff = mem.alignForward(u32, fileoff, alignment);
            header.offset = fileoff;
            fileoff += @intCast(header.size);
        }
    }
}

fn writeAtoms(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    const cpu_arch = macho_file.options.cpu_arch.?;
    const slice = macho_file.sections.slice();

    for (slice.items(.header), slice.items(.atoms)) |header, atoms| {
        if (atoms.items.len == 0) continue;
        if (header.isZerofill()) continue;

        const buffer = try gpa.alloc(u8, header.size);
        defer gpa.free(buffer);
        const padding_byte: u8 = if (header.isCode() and cpu_arch == .x86_64) 0xcc else 0;
        @memset(buffer, padding_byte);

        for (atoms.items) |atom_index| {
            const atom = macho_file.getAtom(atom_index).?;
            assert(atom.flags.alive);
            const off = atom.value - header.addr;
            @memcpy(buffer[off..][0..atom.size], atom.getCode(macho_file));
            // TODO write relocs
        }

        try macho_file.base.file.pwriteAll(buffer, header.offset);
    }
}

fn writeCompactUnwind(macho_file: *MachO) !void {
    const sect_index = macho_file.unwind_info_sect_index orelse return;
    const gpa = macho_file.base.allocator;
    const header = macho_file.sections.items(.header)[sect_index];

    const nrecs = @divExact(header.size, @sizeOf(macho.compact_unwind_entry));
    var buffer = try std.ArrayList(macho.compact_unwind_entry).initCapacity(gpa, nrecs);
    defer buffer.deinit();

    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.unwind_records.items) |irec| {
            const rec = macho_file.getUnwindRecord(irec);
            if (!rec.alive) continue;
            buffer.appendAssumeCapacity(rec.encodeCompact(macho_file));
            // TODO write relocs
        }
    }

    assert(buffer.items.len == nrecs);
    try macho_file.base.file.pwriteAll(mem.sliceAsBytes(buffer.items), header.offset);
}

fn writeEhFrame(macho_file: *MachO) !void {
    const sect_index = macho_file.eh_frame_sect_index orelse return;
    const gpa = macho_file.base.allocator;
    const header = macho_file.sections.items(.header)[sect_index];
    const buffer = try gpa.alloc(u8, header.size);
    defer gpa.free(buffer);
    eh_frame.write(macho_file, buffer);
    try macho_file.base.file.pwriteAll(buffer, header.offset);
    // TODO write relocs
}

const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const load_commands = @import("load_commands.zig");
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const state_log = std.log.scoped(.state);
const std = @import("std");
const trace = @import("../tracy.zig").trace;

const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
