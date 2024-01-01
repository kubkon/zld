pub fn flush(macho_file: *MachO) !void {
    markExports(macho_file);
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
        const seg = &macho_file.segments.items[0];
        seg.nsects = @intCast(macho_file.sections.items(.header).len);
        seg.cmdsize += seg.nsects * @sizeOf(macho.section_64);
    }

    try allocateSections(macho_file);

    {
        // Allocate the single segment.
        assert(macho_file.segments.items.len == 1);
        const seg = &macho_file.segments.items[0];
        var vmaddr: u64 = 0;
        var fileoff: u64 = load_commands.calcLoadCommandsSizeObject(macho_file) + @sizeOf(macho.mach_header_64);
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

    var off = off: {
        const seg = macho_file.segments.items[0];
        break :off mem.alignForward(u64, seg.fileoff + seg.filesize, @alignOf(u64));
    };
    try macho_file.calcSymtabSize();
    off = try macho_file.writeSymtab(off);
    off = try macho_file.writeStrtab(off);
    // TODO write data-in-code

    const ncmds, const sizeofcmds = try writeLoadCommands(macho_file);
    try writeHeader(macho_file, ncmds, sizeofcmds);
}

fn markExports(macho_file: *MachO) void {
    for (macho_file.objects.items) |index| {
        for (macho_file.getFile(index).?.getSymbols()) |sym_index| {
            const sym = macho_file.getSymbol(sym_index);
            const file = sym.getFile(macho_file) orelse continue;
            if (sym.visibility != .global) continue;
            if (file.getIndex() == index) {
                sym.flags.@"export" = true;
            }
        }
    }
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
            sym.visibility = .global;
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
    var fileoff = load_commands.calcLoadCommandsSizeObject(macho_file) + @sizeOf(macho.mach_header_64);
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

fn writeLoadCommands(macho_file: *MachO) !struct { usize, usize } {
    const gpa = macho_file.base.allocator;
    const needed_size = load_commands.calcLoadCommandsSizeObject(macho_file);
    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);

    var stream = std.io.fixedBufferStream(buffer);
    var cwriter = std.io.countingWriter(stream.writer());
    const writer = cwriter.writer();

    var ncmds: usize = 0;

    // Segment and section load commands
    {
        assert(macho_file.segments.items.len == 1);
        const seg = macho_file.segments.items[0];
        try writer.writeStruct(seg);
        for (macho_file.sections.items(.header)) |header| {
            try writer.writeStruct(header);
        }
        ncmds += 1;
    }

    try writer.writeStruct(macho_file.data_in_code_cmd);
    ncmds += 1;
    try writer.writeStruct(macho_file.symtab_cmd);
    ncmds += 1;
    try writer.writeStruct(macho_file.dysymtab_cmd);
    ncmds += 1;

    if (macho_file.options.platform) |platform| {
        if (platform.isBuildVersionCompatible()) {
            try load_commands.writeBuildVersionLC(platform, macho_file.options.sdk_version, writer);
            ncmds += 1;
        } else {
            try load_commands.writeVersionMinLC(platform, macho_file.options.sdk_version, writer);
            ncmds += 1;
        }
    }

    assert(cwriter.bytes_written == needed_size);

    try macho_file.base.file.pwriteAll(buffer, @sizeOf(macho.mach_header_64));

    return .{ ncmds, buffer.len };
}

fn writeHeader(macho_file: *MachO, ncmds: usize, sizeofcmds: usize) !void {
    var header: macho.mach_header_64 = .{};
    header.filetype = macho.MH_OBJECT;

    const subsections_via_symbols = for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        if (object.hasSubsections()) break true;
    } else false;
    if (subsections_via_symbols) {
        header.flags |= macho.MH_SUBSECTIONS_VIA_SYMBOLS;
    }

    switch (macho_file.options.cpu_arch.?) {
        .aarch64 => {
            header.cputype = macho.CPU_TYPE_ARM64;
            header.cpusubtype = macho.CPU_SUBTYPE_ARM_ALL;
        },
        .x86_64 => {
            header.cputype = macho.CPU_TYPE_X86_64;
            header.cpusubtype = macho.CPU_SUBTYPE_X86_64_ALL;
        },
        else => {},
    }

    if (macho_file.has_tlv) {
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
    }
    if (macho_file.binds_to_weak) {
        header.flags |= macho.MH_BINDS_TO_WEAK;
    }
    if (macho_file.weak_defines) {
        header.flags |= macho.MH_WEAK_DEFINES;
    }

    header.ncmds = @intCast(ncmds);
    header.sizeofcmds = @intCast(sizeofcmds);

    try macho_file.base.file.pwriteAll(mem.asBytes(&header), 0);
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
