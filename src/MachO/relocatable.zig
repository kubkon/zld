pub fn flush(macho_file: *MachO) !void {
    try macho_file.dedupLiterals();
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

    state_log.debug("{}", .{macho_file.dumpState()});

    try writeSections(macho_file);
    sortRelocs(macho_file);
    try writeSectionsToFile(macho_file);

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

        for (macho_file.objects.items) |index| {
            if (macho_file.unwind_info_sect_index) |_| {
                macho_file.base.thread_pool.spawnWg(&wg, Object.calcCompactUnwindSizeRelocatable, .{
                    macho_file.getFile(index).?.object,
                    macho_file,
                });
            }

            macho_file.base.thread_pool.spawnWg(&wg, File.calcSymtabSize, .{ macho_file.getFile(index).?, macho_file });
        }

        macho_file.base.thread_pool.spawnWg(&wg, MachO.updateLinkeditSizeWorker, .{ macho_file, .data_in_code });
    }

    calcCompactUnwindSize(macho_file);
    calcSymtabSize(macho_file);

    if (macho_file.has_errors.swap(false, .seq_cst)) return error.FlushFailed;
}

fn calcSectionSizeWorker(macho_file: *MachO, sect_id: u8) void {
    const tracy = trace(@src());
    defer tracy.end();

    const doWork = struct {
        fn doWork(mfile: *MachO, header: *macho.section_64, atoms: []const MachO.Ref) !void {
            for (atoms) |ref| {
                const atom = ref.getAtom(mfile).?;
                const p2align = atom.alignment;
                const atom_alignment = try math.powi(u32, 2, p2align);
                const offset = mem.alignForward(u64, header.size, atom_alignment);
                const padding = offset - header.size;
                atom.value = offset;
                header.size += padding + atom.size;
                header.@"align" = @max(header.@"align", p2align);
                const nreloc = atom.calcNumRelocs(mfile);
                atom.addExtra(.{ .rel_out_index = header.nreloc, .rel_out_count = nreloc }, mfile);
                header.nreloc += nreloc;
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

fn calcCompactUnwindSize(macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    var nrec: u32 = 0;
    var nreloc: u32 = 0;

    for (macho_file.objects.items) |index| {
        const ctx = &macho_file.getFile(index).?.object.compact_unwind_ctx;
        ctx.rec_index = nrec;
        ctx.reloc_index = nreloc;
        nrec += ctx.rec_count;
        nreloc += ctx.reloc_count;
    }

    const sect = &macho_file.sections.items(.header)[macho_file.unwind_info_sect_index.?];
    sect.size = nrec * @sizeOf(macho.compact_unwind_entry);
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

fn writeSections(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;
    const slice = macho_file.sections.slice();
    for (slice.items(.header), slice.items(.out), slice.items(.relocs)) |header, *out, *relocs| {
        if (header.isZerofill()) continue;
        const cpu_arch = macho_file.options.cpu_arch.?;
        try out.resize(macho_file.base.allocator, header.size);
        const padding_byte: u8 = if (header.isCode() and cpu_arch == .x86_64) 0xcc else 0;
        @memset(out.items, padding_byte);
        try relocs.resize(macho_file.base.allocator, header.nreloc);
    }

    const cmd = macho_file.symtab_cmd;
    try macho_file.symtab.resize(gpa, cmd.nsyms);
    try macho_file.strtab.resize(gpa, cmd.strsize);
    macho_file.strtab.items[0] = 0;

    var wg: WaitGroup = .{};
    {
        wg.reset();
        defer wg.wait();

        for (macho_file.objects.items) |index| {
            macho_file.base.thread_pool.spawnWg(&wg, writeAtomsWorker, .{ macho_file, macho_file.getFile(index).?.object });
            macho_file.base.thread_pool.spawnWg(&wg, Object.writeSymtab, .{ macho_file.getFile(index).?.object.*, macho_file });
        }

        if (macho_file.eh_frame_sect_index) |_| {
            macho_file.base.thread_pool.spawnWg(&wg, writeEhFrameWorker, .{macho_file});
        }

        if (macho_file.unwind_info_sect_index) |_| {
            for (macho_file.objects.items) |index| {
                macho_file.base.thread_pool.spawnWg(&wg, writeCompactUnwindWorker, .{
                    macho_file,
                    macho_file.getFile(index).?.object,
                });
            }
        }
    }

    if (macho_file.has_errors.swap(false, .seq_cst)) return error.FlushFailed;
}

fn writeAtomsWorker(macho_file: *MachO, object: *Object) void {
    const tracy = trace(@src());
    defer tracy.end();
    object.writeAtomsRelocatable(macho_file) catch |err| {
        macho_file.base.fatal("{}: failed to write atoms: {s}", .{ object.fmtPath(), @errorName(err) });
        _ = macho_file.has_errors.swap(true, .seq_cst);
    };
}

fn sortRelocs(macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    const worker = struct {
        fn worker(relocs: []macho.relocation_info) void {
            const tr = trace(@src());
            defer tr.end();
            mem.sort(macho.relocation_info, relocs, {}, sortReloc);
        }
    }.worker;

    var wg: WaitGroup = .{};
    {
        wg.reset();
        defer wg.wait();

        for (macho_file.sections.items(.relocs)) |*relocs| {
            macho_file.base.thread_pool.spawnWg(&wg, worker, .{relocs.items});
        }
    }
}

fn writeSectionsToFile(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const slice = macho_file.sections.slice();
    for (slice.items(.header), slice.items(.out), slice.items(.relocs)) |header, out, relocs| {
        try macho_file.base.file.pwriteAll(out.items, header.offset);
        try macho_file.base.file.pwriteAll(mem.sliceAsBytes(relocs.items), header.reloff);
    }

    try macho_file.writeDataInCode();
    try macho_file.base.file.pwriteAll(mem.sliceAsBytes(macho_file.symtab.items), macho_file.symtab_cmd.symoff);
    try macho_file.base.file.pwriteAll(macho_file.strtab.items, macho_file.symtab_cmd.stroff);
}

fn writeCompactUnwindWorker(macho_file: *MachO, object: *Object) void {
    const tracy = trace(@src());
    defer tracy.end();
    object.writeCompactUnwindRelocatable(macho_file) catch |err| {
        macho_file.base.fatal("failed to write '__LD,__eh_frame' section: {s}", .{@errorName(err)});
        _ = macho_file.has_errors.swap(true, .seq_cst);
    };
}

fn writeEhFrameWorker(macho_file: *MachO) void {
    const sect_index = macho_file.eh_frame_sect_index.?;
    const buffer = macho_file.sections.items(.out)[sect_index];
    const relocs = macho_file.sections.items(.relocs)[sect_index];
    eh_frame.writeRelocs(macho_file, buffer.items, relocs.items) catch |err| {
        macho_file.base.fatal("failed to write '__TEXT,__eh_frame' section: {s}", .{@errorName(err)});
        _ = macho_file.has_errors.swap(true, .seq_cst);
    };
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
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const WaitGroup = std.Thread.WaitGroup;
