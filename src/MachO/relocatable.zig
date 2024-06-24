pub fn flush(macho_file: *MachO) !void {
    try macho_file.dedupLiterals();
    markExports(macho_file);
    claimUnresolved(macho_file);
    try initOutputSections(macho_file);
    try macho_file.sortSections();
    try macho_file.addAtomsToSections();
    try calcSectionSizes(macho_file);
    calcSymtabSize(macho_file);
    try macho_file.data_in_code.updateSize(macho_file);

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

    state_log.debug("{}", .{macho_file.dumpState()});

    try writeAtoms(macho_file);
    try writeCompactUnwind(macho_file);
    try writeEhFrame(macho_file);

    try writeDataInCode(macho_file);
    try writeSymtab(macho_file);

    const ncmds, const sizeofcmds = try writeLoadCommands(macho_file);
    try writeHeader(macho_file, ncmds, sizeofcmds);
}

fn markExports(macho_file: *MachO) void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.symbols.items, 0..) |*sym, i| {
            const ref = object.getSymbolRef(@intCast(i), macho_file);
            const file = ref.getFile(macho_file) orelse continue;
            if (file.getIndex() != index) continue;
            if (sym.visibility != .global) continue;
            sym.flags.@"export" = true;
        }
    }
}

fn claimUnresolved(macho_file: *MachO) void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        object.claimUnresolvedRelocatable(macho_file);
    }
}

fn initOutputSections(macho_file: *MachO) !void {
    for (macho_file.objects.items) |index| {
        const file = macho_file.getFile(index).?;
        for (file.getAtoms()) |atom_index| {
            const atom = file.getAtom(atom_index) orelse continue;
            if (!atom.alive.load(.seq_cst)) continue;
            atom.out_n_sect = try Atom.initOutputSection(atom.getInputSection(macho_file), macho_file);
        }
    }

    const needs_unwind_info = for (macho_file.objects.items) |index| {
        if (macho_file.getFile(index).?.object.hasUnwindRecords()) break true;
    } else false;
    if (needs_unwind_info) {
        macho_file.unwind_info_sect_index = try macho_file.addSection("__LD", "__compact_unwind", .{
            .flags = macho.S_ATTR_DEBUG,
        });
    }

    const needs_eh_frame = for (macho_file.objects.items) |index| {
        if (macho_file.getFile(index).?.object.hasEhFrameRecords()) break true;
    } else false;
    if (needs_eh_frame) {
        assert(needs_unwind_info);
        macho_file.eh_frame_sect_index = try macho_file.addSection("__TEXT", "__eh_frame", .{});
    }
}

fn calcSymtabSize(macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    var nlocals: u32 = 0;
    var nstabs: u32 = 0;
    var nexports: u32 = 0;
    var nimports: u32 = 0;
    var strsize: u32 = 1;

    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        const ctx = &object.output_symtab_ctx;
        ctx.ilocal = nlocals;
        ctx.istab = nstabs;
        ctx.iexport = nexports;
        ctx.iimport = nimports;
        ctx.stroff = strsize;
        object.calcSymtabSize(macho_file);
        nlocals += ctx.nlocals;
        nstabs += ctx.nstabs;
        nexports += ctx.nexports;
        nimports += ctx.nimports;
        strsize += ctx.strsize;
    }

    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        const ctx = &object.output_symtab_ctx;
        ctx.istab += nlocals;
        ctx.iexport += nlocals + nstabs;
        ctx.iimport += nlocals + nstabs + nexports;
    }

    {
        const cmd = &macho_file.symtab_cmd;
        cmd.nsyms = nlocals + nstabs + nexports + nimports;
        cmd.strsize = strsize;
    }

    {
        const cmd = &macho_file.dysymtab_cmd;
        cmd.ilocalsym = 0;
        cmd.nlocalsym = nlocals + nstabs;
        cmd.iextdefsym = nlocals + nstabs;
        cmd.nextdefsym = nexports;
        cmd.iundefsym = nlocals + nstabs + nexports;
        cmd.nundefsym = nimports;
    }
}

fn calcSectionSizes(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    var wg: WaitGroup = .{};

    {
        wg.reset();
        defer wg.wait();

        const slice = macho_file.sections.slice();
        for (slice.items(.atoms), 0..) |atoms, i| {
            if (atoms.items.len == 0) continue;
            macho_file.base.thread_pool.spawnWg(&wg, calcSectionSizeWorker, .{ macho_file, @as(u8, @intCast(i)) });
        }

        if (macho_file.eh_frame_sect_index) |_| {
            macho_file.base.thread_pool.spawnWg(&wg, calcEhFrameSizeWorker, .{macho_file});
        }

        if (macho_file.unwind_info_sect_index) |_| {
            macho_file.base.thread_pool.spawnWg(&wg, calcCompactUnwindSizeWorker, .{macho_file});
        }
    }

    if (macho_file.has_errors.swap(false, .seq_cst)) return error.FlushFailed;
}

fn calcSectionSizeWorker(macho_file: *MachO, sect_id: u8) void {
    const tracy = trace(@src());
    defer tracy.end();

    const doWork = struct {
        fn doWork(mfile: *MachO, header: *macho.section_64, atoms: []const MachO.Ref) !void {
            for (atoms) |ref| {
                const atom = ref.getAtom(mfile).?;
                const p2align = atom.alignment.load(.seq_cst);
                const atom_alignment = try math.powi(u32, 2, p2align);
                const offset = mem.alignForward(u64, header.size, atom_alignment);
                const padding = offset - header.size;
                atom.value = offset;
                header.size += padding + atom.size;
                header.@"align" = @max(header.@"align", p2align);
                header.nreloc += atom.calcNumRelocs(mfile);
            }
        }
    }.doWork;

    const slice = macho_file.sections.slice();
    const header = &slice.items(.header)[sect_id];
    const atoms = slice.items(.atoms)[sect_id].items;
    doWork(macho_file, header, atoms) catch |err| {
        macho_file.base.fatal("failed to calculate size of section '{s},{s}': {s}", .{
            header.segName(),
            header.sectName(),
            @errorName(err),
        });
        _ = macho_file.has_errors.swap(true, .seq_cst);
    };
}

fn calcCompactUnwindSizeWorker(macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    var size: u32 = 0;
    var nreloc: u32 = 0;

    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.unwind_records_indexes.items) |irec| {
            const rec = object.getUnwindRecord(irec);
            if (!rec.alive) continue;
            size += @sizeOf(macho.compact_unwind_entry);
            nreloc += 1;
            if (rec.getPersonality(macho_file)) |_| {
                nreloc += 1;
            }
            if (rec.getLsdaAtom(macho_file)) |_| {
                nreloc += 1;
            }
        }
    }

    const sect = &macho_file.sections.items(.header)[macho_file.unwind_info_sect_index.?];
    sect.size = size;
    sect.nreloc = nreloc;
    sect.@"align" = 3;
}

fn calcEhFrameSizeWorker(macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    const doWork = struct {
        fn doWork(mfile: *MachO, header: *macho.section_64) !void {
            header.size = try eh_frame.calcSize(mfile);
            header.@"align" = 3;
            header.nreloc = eh_frame.calcNumRelocs(mfile);
        }
    }.doWork;

    const header = &macho_file.sections.items(.header)[macho_file.eh_frame_sect_index.?];
    doWork(macho_file, header) catch |err| {
        macho_file.base.fatal("failed to calculate size of section '__TEXT,__eh_frame': {s}", .{
            @errorName(err),
        });
        _ = macho_file.has_errors.swap(true, .seq_cst);
    };
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

    for (slice.items(.header)) |*header| {
        if (header.nreloc == 0) continue;
        header.reloff = mem.alignForward(u32, fileoff, @alignOf(macho.relocation_info));
        fileoff = header.reloff + header.nreloc * @sizeOf(macho.relocation_info);
    }

    // In -r mode, there is no LINKEDIT segment and so we allocate required LINKEDIT commands
    // as if they were detached or part of the single segment.

    // DATA_IN_CODE
    {
        const cmd = &macho_file.data_in_code_cmd;
        cmd.dataoff = fileoff;
        fileoff += cmd.datasize;
        fileoff = mem.alignForward(u32, fileoff, @alignOf(u64));
    }

    // SYMTAB
    {
        const cmd = &macho_file.symtab_cmd;
        cmd.symoff = fileoff;
        fileoff += cmd.nsyms * @sizeOf(macho.nlist_64);
        fileoff = mem.alignForward(u32, fileoff, @alignOf(u32));
        cmd.stroff = fileoff;
    }
}

// We need to sort relocations in descending order to be compatible with Apple's linker.
fn sortReloc(ctx: void, lhs: macho.relocation_info, rhs: macho.relocation_info) bool {
    _ = ctx;
    return lhs.r_address > rhs.r_address;
}

fn writeAtoms(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    const cpu_arch = macho_file.options.cpu_arch.?;
    const slice = macho_file.sections.slice();

    var relocs = std.ArrayList(macho.relocation_info).init(gpa);
    defer relocs.deinit();

    for (slice.items(.header), slice.items(.atoms)) |header, atoms| {
        if (atoms.items.len == 0) continue;
        if (header.isZerofill()) continue;

        const code = try gpa.alloc(u8, header.size);
        defer gpa.free(code);
        const padding_byte: u8 = if (header.isCode() and cpu_arch == .x86_64) 0xcc else 0;
        @memset(code, padding_byte);

        try relocs.ensureTotalCapacity(header.nreloc);

        for (atoms.items) |ref| {
            const atom = ref.getAtom(macho_file).?;
            assert(atom.alive.load(.seq_cst));
            const off = atom.value;
            try atom.getCode(macho_file, code[off..][0..atom.size]);
            try atom.writeRelocs(macho_file, code[off..][0..atom.size], &relocs);
        }

        assert(relocs.items.len == header.nreloc);

        mem.sort(macho.relocation_info, relocs.items, {}, sortReloc);

        // TODO scattered writes?
        try macho_file.base.file.pwriteAll(code, header.offset);
        try macho_file.base.file.pwriteAll(mem.sliceAsBytes(relocs.items), header.reloff);

        relocs.clearRetainingCapacity();
    }
}

fn writeCompactUnwind(macho_file: *MachO) !void {
    const sect_index = macho_file.unwind_info_sect_index orelse return;
    const gpa = macho_file.base.allocator;
    const header = macho_file.sections.items(.header)[sect_index];

    const nrecs = @divExact(header.size, @sizeOf(macho.compact_unwind_entry));
    var entries = try std.ArrayList(macho.compact_unwind_entry).initCapacity(gpa, nrecs);
    defer entries.deinit();

    var relocs = try std.ArrayList(macho.relocation_info).initCapacity(gpa, header.nreloc);
    defer relocs.deinit();

    const addReloc = struct {
        fn addReloc(offset: i32, cpu_arch: std.Target.Cpu.Arch) macho.relocation_info {
            return .{
                .r_address = offset,
                .r_symbolnum = 0,
                .r_pcrel = 0,
                .r_length = 3,
                .r_extern = 0,
                .r_type = switch (cpu_arch) {
                    .aarch64 => @intFromEnum(macho.reloc_type_arm64.ARM64_RELOC_UNSIGNED),
                    .x86_64 => @intFromEnum(macho.reloc_type_x86_64.X86_64_RELOC_UNSIGNED),
                    else => unreachable,
                },
            };
        }
    }.addReloc;

    var offset: i32 = 0;
    for (macho_file.objects.items) |index| {
        const object = macho_file.getFile(index).?.object;
        for (object.unwind_records_indexes.items) |irec| {
            const rec = object.getUnwindRecord(irec);
            if (!rec.alive) continue;

            var out: macho.compact_unwind_entry = .{
                .rangeStart = 0,
                .rangeLength = rec.length,
                .compactUnwindEncoding = rec.enc.enc,
                .personalityFunction = 0,
                .lsda = 0,
            };

            {
                // Function address
                const atom = rec.getAtom(macho_file);
                const addr = rec.getAtomAddress(macho_file);
                out.rangeStart = addr;
                var reloc = addReloc(offset, macho_file.options.cpu_arch.?);
                reloc.r_symbolnum = atom.out_n_sect + 1;
                relocs.appendAssumeCapacity(reloc);
            }

            // Personality function
            if (rec.getPersonality(macho_file)) |sym| {
                const r_symbolnum = math.cast(u24, sym.getOutputSymtabIndex(macho_file).?) orelse return error.Overflow;
                var reloc = addReloc(offset + 16, macho_file.options.cpu_arch.?);
                reloc.r_symbolnum = r_symbolnum;
                reloc.r_extern = 1;
                relocs.appendAssumeCapacity(reloc);
            }

            // LSDA address
            if (rec.getLsdaAtom(macho_file)) |atom| {
                const addr = rec.getLsdaAddress(macho_file);
                out.lsda = addr;
                var reloc = addReloc(offset + 24, macho_file.options.cpu_arch.?);
                reloc.r_symbolnum = atom.out_n_sect + 1;
                relocs.appendAssumeCapacity(reloc);
            }

            entries.appendAssumeCapacity(out);
            offset += @sizeOf(macho.compact_unwind_entry);
        }
    }

    assert(entries.items.len == nrecs);
    assert(relocs.items.len == header.nreloc);

    mem.sort(macho.relocation_info, relocs.items, {}, sortReloc);

    // TODO scattered writes?
    try macho_file.base.file.pwriteAll(mem.sliceAsBytes(entries.items), header.offset);
    try macho_file.base.file.pwriteAll(mem.sliceAsBytes(relocs.items), header.reloff);
}

fn writeEhFrame(macho_file: *MachO) !void {
    const sect_index = macho_file.eh_frame_sect_index orelse return;
    const gpa = macho_file.base.allocator;
    const header = macho_file.sections.items(.header)[sect_index];

    const code = try gpa.alloc(u8, header.size);
    defer gpa.free(code);

    var relocs = try std.ArrayList(macho.relocation_info).initCapacity(gpa, header.nreloc);
    defer relocs.deinit();

    try eh_frame.writeRelocs(macho_file, code, &relocs);
    assert(relocs.items.len == header.nreloc);

    mem.sort(macho.relocation_info, relocs.items, {}, sortReloc);

    // TODO scattered writes?
    try macho_file.base.file.pwriteAll(code, header.offset);
    try macho_file.base.file.pwriteAll(mem.sliceAsBytes(relocs.items), header.reloff);
}

/// TODO just a temp
fn writeDataInCode(macho_file: *MachO) !void {
    const cmd = macho_file.data_in_code_cmd;
    try macho_file.base.file.pwriteAll(
        mem.sliceAsBytes(macho_file.data_in_code.entries.items),
        cmd.dataoff,
    );
}

/// TODO just a temp
fn writeSymtab(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.allocator;
    const cmd = macho_file.symtab_cmd;

    try macho_file.symtab.resize(gpa, cmd.nsyms);
    try macho_file.strtab.resize(gpa, cmd.strsize);
    macho_file.strtab.items[0] = 0;

    for (macho_file.objects.items) |index| {
        macho_file.getFile(index).?.writeSymtab(macho_file);
    }
    for (macho_file.dylibs.items) |index| {
        macho_file.getFile(index).?.writeSymtab(macho_file);
    }
    if (macho_file.getInternalObject()) |internal| {
        internal.writeSymtab(macho_file);
    }

    try macho_file.base.file.pwriteAll(mem.sliceAsBytes(macho_file.symtab.items), cmd.symoff);
    try macho_file.base.file.pwriteAll(macho_file.strtab.items, cmd.stroff);
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
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
const WaitGroup = std.Thread.WaitGroup;
