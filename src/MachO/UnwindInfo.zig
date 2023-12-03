/// List of all unwind records gathered from all objects and sorted
/// by allocated relative function address within the section.
records: std.ArrayListUnmanaged(Record.Index) = .{},
// records_lookup: std.AutoHashMapUnmanaged(SymbolWithLoc, RecordIndex) = .{},

/// List of all personalities referenced by either unwind info entries
/// or __eh_frame entries.
personalities: [max_personalities]Symbol.Index = undefined,
personalities_count: u2 = 0,

/// List of common encodings sorted in descending order with the most common first.
common_encodings: [max_common_encodings]Encoding = undefined,
common_encodings_count: u7 = 0,

/// List of record indexes containing an LSDA pointer.
lsdas: std.ArrayListUnmanaged(Record.Index) = .{},
lsdas_lookup: std.AutoHashMapUnmanaged(Record.Index, u32) = .{},

/// List of second level pages.
pages: std.ArrayListUnmanaged(Page) = .{},

pub fn deinit(info: *UnwindInfo, allocator: Allocator) void {
    info.records.deinit(allocator);
    // info.records_lookup.deinit(info.gpa);
    info.pages.deinit(allocator);
    info.lsdas.deinit(allocator);
    info.lsdas_lookup.deinit(allocator);
}

fn canFold(macho_file: *MachO, lhs_index: Record.Index, rhs_index: Record.Index) bool {
    const cpu_arch = macho_file.options.cpu_arch.?;
    const lhs = macho_file.getUnwindRecord(lhs_index);
    const rhs = macho_file.getUnwindRecord(rhs_index);
    if (cpu_arch == .x86_64) {
        if (lhs.enc.getMode() == @intFromEnum(macho.UNWIND_X86_64_MODE.STACK_IND) or
            rhs.enc.getMode() == @intFromEnum(macho.UNWIND_X86_64_MODE.STACK_IND)) return false;
    }
    const lhs_per = lhs.personality orelse 0;
    const rhs_per = rhs.personality orelse 0;
    return lhs.getAtomAddress(macho_file) + lhs.length == rhs.getAtomAddress(macho_file) and
        lhs.enc.eql(rhs.enc) and
        lhs_per == rhs_per and
        lhs.fde == rhs.fde and
        lhs.getLsdaAtom(macho_file) == null and rhs.getLsdaAtom(macho_file) == null;
}

pub fn generate(info: *UnwindInfo, macho_file: *MachO) !void {
    const gpa = macho_file.base.allocator;

    // Collect all unwind records
    for (macho_file.sections.items(.atoms)) |atoms| {
        for (atoms.items) |atom_index| {
            const atom = macho_file.getAtom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const recs = atom.getUnwindRecords(macho_file);
            try info.records.ensureUnusedCapacity(gpa, recs.len);
            for (recs) |rec| {
                if (!macho_file.getUnwindRecord(rec).alive) continue;
                info.records.appendAssumeCapacity(rec);
            }
        }
    }

    // Encode records
    for (info.records.items) |index| {
        const rec = macho_file.getUnwindRecord(index);
        if (rec.getFde(macho_file)) |fde| {
            rec.enc.setDwarfSectionOffset(@intCast(fde.out_offset));
        } else if (rec.getPersonality(macho_file)) |_| {
            const personality_index = try info.getOrPutPersonalityFunction(rec.personality.?); // TODO handle error
            rec.enc.setPersonalityIndex(personality_index + 1);
        }
    }

    // Sort by assigned relative address within each output section
    const sortFn = struct {
        fn sortFn(ctx: *MachO, lhs_index: Record.Index, rhs_index: Record.Index) bool {
            const lhs = ctx.getUnwindRecord(lhs_index).getAtom(ctx);
            const rhs = ctx.getUnwindRecord(rhs_index).getAtom(ctx);
            const lhs_addr = lhs.value + lhs.off;
            const rhs_addr = rhs.value + rhs.off;
            if (lhs.out_n_sect == rhs.out_n_sect) return lhs_addr < rhs_addr;
            return lhs.out_n_sect < rhs.out_n_sect;
        }
    }.sortFn;
    mem.sort(Record.Index, info.records.items, macho_file, sortFn);

    // Fold the records
    // Any adjacent two records that share encoding can be folded into one.
    {
        var i: usize = 0;
        var j: usize = 1;
        while (j < info.records.items.len) : (j += 1) {
            if (canFold(macho_file, info.records.items[i], info.records.items[j])) {
                const rec = macho_file.getUnwindRecord(info.records.items[i]);
                rec.length += macho_file.getUnwindRecord(info.records.items[j]).length;
            } else {
                i += 1;
                info.records.items[i] = info.records.items[j];
            }
        }
        info.records.shrinkAndFree(gpa, i);
    }

    for (info.records.items) |rec_index| {
        const rec = macho_file.getUnwindRecord(rec_index);
        const atom = rec.getAtom(macho_file);
        std.debug.print("@{x} : {s} : rec({d})\n", .{ atom.value + atom.off, atom.getName(macho_file), rec_index });
    }

    // Calculate common encodings
    {
        const CommonEncWithCount = struct {
            enc: Encoding,
            count: u32,

            fn greaterThan(ctx: void, lhs: @This(), rhs: @This()) bool {
                _ = ctx;
                return lhs.count > rhs.count;
            }
        };

        const Context = struct {
            pub fn hash(ctx: @This(), key: Encoding) u32 {
                _ = ctx;
                return key.enc;
            }

            pub fn eql(
                ctx: @This(),
                key1: Encoding,
                key2: Encoding,
                b_index: usize,
            ) bool {
                _ = ctx;
                _ = b_index;
                return key1.eql(key2);
            }
        };

        var common_encodings_counts = std.ArrayHashMap(
            Encoding,
            CommonEncWithCount,
            Context,
            false,
        ).init(gpa);
        defer common_encodings_counts.deinit();

        for (info.records.items) |rec_index| {
            const rec = macho_file.getUnwindRecord(rec_index);
            if (rec.enc.isDwarf(macho_file)) continue;
            const gop = try common_encodings_counts.getOrPut(rec.enc);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .enc = rec.enc,
                    .count = 0,
                };
            }
            gop.value_ptr.count += 1;
        }

        const slice = common_encodings_counts.values();
        mem.sort(CommonEncWithCount, slice, {}, CommonEncWithCount.greaterThan);

        var i: u7 = 0;
        while (i < slice.len) : (i += 1) {
            if (i >= max_common_encodings) break;
            if (slice[i].count < 2) continue;
            info.appendCommonEncoding(slice[i].enc);
            std.debug.print("adding common encoding: {d} => {}\n", .{ i, slice[i].enc });
        }
    }

    // // Compute page allocations
    // {
    //     var i: u32 = 0;
    //     while (i < info.records.items.len) {
    //         const range_start_max: u64 =
    //             info.records.items[i].rangeStart + compressed_entry_func_offset_mask;
    //         var encoding_count: u9 = info.common_encodings_count;
    //         var space_left: u32 = second_level_page_words -
    //             @sizeOf(macho.unwind_info_compressed_second_level_page_header) / @sizeOf(u32);
    //         var page = Page{
    //             .kind = undefined,
    //             .start = i,
    //             .count = 0,
    //         };

    //         while (space_left >= 1 and i < info.records.items.len) {
    //             const record = info.records.items[i];
    //             const enc = record.compactUnwindEncoding;
    //             const is_dwarf = UnwindEncoding.isDwarf(record.compactUnwindEncoding, cpu_arch);

    //             if (record.rangeStart >= range_start_max) {
    //                 break;
    //             } else if (info.getCommonEncoding(enc) != null or
    //                 page.getPageEncoding(info, enc) != null and !is_dwarf)
    //             {
    //                 i += 1;
    //                 space_left -= 1;
    //             } else if (space_left >= 2 and encoding_count < max_compact_encodings) {
    //                 page.appendPageEncoding(i);
    //                 i += 1;
    //                 space_left -= 2;
    //                 encoding_count += 1;
    //             } else {
    //                 break;
    //             }
    //         }

    //         page.count = @as(u16, @intCast(i - page.start));

    //         if (i < info.records.items.len and page.count < max_regular_second_level_entries) {
    //             page.kind = .regular;
    //             page.count = @as(u16, @intCast(@min(
    //                 max_regular_second_level_entries,
    //                 info.records.items.len - page.start,
    //             )));
    //             i = page.start + page.count;
    //         } else {
    //             page.kind = .compressed;
    //         }

    //         log.debug("{}", .{page.fmtDebug(info)});

    //         try info.pages.append(info.gpa, page);
    //     }
    // }

    // // Save indices of records requiring LSDA relocation
    // try info.lsdas_lookup.ensureTotalCapacity(info.gpa, @as(u32, @intCast(info.records.items.len)));
    // for (info.records.items, 0..) |rec, i| {
    //     info.lsdas_lookup.putAssumeCapacityNoClobber(@as(RecordIndex, @intCast(i)), @as(u32, @intCast(info.lsdas.items.len)));
    //     if (rec.lsda == 0) continue;
    //     try info.lsdas.append(info.gpa, @as(RecordIndex, @intCast(i)));
    // }
}

// pub fn scanRelocs(macho_file: *MachO) !void {
//     if (macho_file.getSectionByName("__TEXT", "__unwind_info") == null) return;

//     const cpu_arch = macho_file.options.cpu_arch.?;
//     for (macho_file.objects.items, 0..) |*object, object_id| {
//         const unwind_records = object.getUnwindRecords();
//         for (object.exec_atoms.items) |atom_index| {
//             var inner_syms_it = Atom.getInnerSymbolsIterator(macho_file, atom_index);
//             while (inner_syms_it.next()) |sym| {
//                 const record_id = object.unwind_records_lookup.get(sym) orelse continue;
//                 if (object.unwind_relocs_lookup[record_id].dead) continue;
//                 const record = unwind_records[record_id];
//                 if (!UnwindEncoding.isDwarf(record.compactUnwindEncoding, cpu_arch)) {
//                     if (getPersonalityFunctionReloc(
//                         macho_file,
//                         @as(u32, @intCast(object_id)),
//                         record_id,
//                     )) |rel| {
//                         // Personality function; add GOT pointer.
//                         const target = Atom.parseRelocTarget(macho_file, .{
//                             .object_id = @as(u32, @intCast(object_id)),
//                             .rel = rel,
//                             .code = mem.asBytes(&record),
//                             .base_offset = @as(i32, @intCast(record_id * @sizeOf(macho.compact_unwind_entry))),
//                         });
//                         try Atom.addGotEntry(macho_file, target);
//                     }
//                 }
//             }
//         }
//     }
// }

// fn collectPersonalityFromDwarf(
//     info: *UnwindInfo,
//     macho_file: *MachO,
//     object_id: u32,
//     sym_loc: SymbolWithLoc,
//     record: *macho.compact_unwind_entry,
// ) !void {
//     const object = &macho_file.objects.items[object_id];
//     var it = object.getEhFrameRecordsIterator();
//     const fde_offset = object.eh_frame_records_lookup.get(sym_loc).?;
//     it.seekTo(fde_offset);
//     const fde = (try it.next(macho_file)).?;
//     const cie_ptr = fde.getCiePointerSource(object_id, macho_file, fde_offset);
//     const cie_offset = fde_offset + 4 - cie_ptr;
//     it.seekTo(cie_offset);
//     const cie = (try it.next(macho_file)).?;

//     if (cie.getPersonalityPointerReloc(
//         macho_file,
//         @as(u32, @intCast(object_id)),
//         cie_offset,
//     )) |target| {
//         const personality_index = info.getPersonalityFunction(target) orelse inner: {
//             const personality_index = info.personalities_count;
//             info.personalities[personality_index] = target;
//             info.personalities_count += 1;
//             break :inner personality_index;
//         };

//         record.personalityFunction = personality_index + 1;
//         UnwindEncoding.setPersonalityIndex(&record.compactUnwindEncoding, personality_index + 1);
//     }
// }

// pub fn calcSectionSize(info: UnwindInfo, macho_file: *MachO) !void {
//     const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
//     const sect = &macho_file.sections.items(.header)[sect_id];
//     sect.@"align" = 2;
//     sect.size = info.calcRequiredSize();
// }

// fn calcRequiredSize(info: UnwindInfo) usize {
//     var total_size: usize = 0;
//     total_size += @sizeOf(macho.unwind_info_section_header);
//     total_size +=
//         @as(usize, @intCast(info.common_encodings_count)) * @sizeOf(macho.compact_unwind_encoding_t);
//     total_size += @as(usize, @intCast(info.personalities_count)) * @sizeOf(u32);
//     total_size += (info.pages.items.len + 1) * @sizeOf(macho.unwind_info_section_header_index_entry);
//     total_size += info.lsdas.items.len * @sizeOf(macho.unwind_info_section_header_lsda_index_entry);
//     total_size += info.pages.items.len * second_level_page_bytes;
//     return total_size;
// }

// pub fn write(info: *UnwindInfo, macho_file: *MachO) !void {
//     const sect_id = macho_file.getSectionByName("__TEXT", "__unwind_info") orelse return;
//     const sect = &macho_file.sections.items(.header)[sect_id];
//     const seg_id = macho_file.sections.items(.segment_index)[sect_id];
//     const seg = macho_file.segments.items[seg_id];

//     const text_sect_id = macho_file.getSectionByName("__TEXT", "__text").?;
//     const text_sect = macho_file.sections.items(.header)[text_sect_id];

//     var personalities: [max_personalities]u32 = undefined;
//     const cpu_arch = macho_file.options.cpu_arch.?;

//     log.debug("Personalities:", .{});
//     for (info.personalities[0..info.personalities_count], 0..) |target, i| {
//         const atom_index = macho_file.getGotAtomIndexForSymbol(target).?;
//         const atom = macho_file.getAtom(atom_index);
//         const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
//         personalities[i] = @as(u32, @intCast(sym.n_value - seg.vmaddr));
//         log.debug("  {d}: 0x{x} ({s})", .{ i, personalities[i], macho_file.getSymbolName(target) });
//     }

//     for (info.records.items) |*rec| {
//         // Finalize missing address values
//         rec.rangeStart += text_sect.addr - seg.vmaddr;
//         if (rec.personalityFunction > 0) {
//             rec.personalityFunction = personalities[rec.personalityFunction - 1];
//         }

//         if (rec.compactUnwindEncoding > 0 and !UnwindEncoding.isDwarf(rec.compactUnwindEncoding, cpu_arch)) {
//             const lsda_target = @as(MachO.SymbolWithLoc, @bitCast(rec.lsda));
//             if (lsda_target.getFile()) |_| {
//                 const sym = macho_file.getSymbol(lsda_target);
//                 rec.lsda = sym.n_value - seg.vmaddr;
//             }
//         }
//     }

//     for (info.records.items, 0..) |record, i| {
//         log.debug("Unwind record at offset 0x{x}", .{i * @sizeOf(macho.compact_unwind_entry)});
//         log.debug("  start: 0x{x}", .{record.rangeStart});
//         log.debug("  length: 0x{x}", .{record.rangeLength});
//         log.debug("  compact encoding: 0x{x:0>8}", .{record.compactUnwindEncoding});
//         log.debug("  personality: 0x{x}", .{record.personalityFunction});
//         log.debug("  LSDA: 0x{x}", .{record.lsda});
//     }

//     var buffer = std.ArrayList(u8).init(info.gpa);
//     defer buffer.deinit();

//     const size = info.calcRequiredSize();
//     try buffer.ensureTotalCapacityPrecise(size);

//     var cwriter = std.io.countingWriter(buffer.writer());
//     const writer = cwriter.writer();

//     const common_encodings_offset: u32 = @sizeOf(macho.unwind_info_section_header);
//     const common_encodings_count: u32 = info.common_encodings_count;
//     const personalities_offset: u32 = common_encodings_offset + common_encodings_count * @sizeOf(u32);
//     const personalities_count: u32 = info.personalities_count;
//     const indexes_offset: u32 = personalities_offset + personalities_count * @sizeOf(u32);
//     const indexes_count: u32 = @as(u32, @intCast(info.pages.items.len + 1));

//     try writer.writeStruct(macho.unwind_info_section_header{
//         .commonEncodingsArraySectionOffset = common_encodings_offset,
//         .commonEncodingsArrayCount = common_encodings_count,
//         .personalityArraySectionOffset = personalities_offset,
//         .personalityArrayCount = personalities_count,
//         .indexSectionOffset = indexes_offset,
//         .indexCount = indexes_count,
//     });

//     try writer.writeAll(mem.sliceAsBytes(info.common_encodings[0..info.common_encodings_count]));
//     try writer.writeAll(mem.sliceAsBytes(personalities[0..info.personalities_count]));

//     const pages_base_offset = @as(u32, @intCast(size - (info.pages.items.len * second_level_page_bytes)));
//     const lsda_base_offset = @as(u32, @intCast(pages_base_offset -
//         (info.lsdas.items.len * @sizeOf(macho.unwind_info_section_header_lsda_index_entry))));
//     for (info.pages.items, 0..) |page, i| {
//         assert(page.count > 0);
//         const first_entry = info.records.items[page.start];
//         try writer.writeStruct(macho.unwind_info_section_header_index_entry{
//             .functionOffset = @as(u32, @intCast(first_entry.rangeStart)),
//             .secondLevelPagesSectionOffset = @as(u32, @intCast(pages_base_offset + i * second_level_page_bytes)),
//             .lsdaIndexArraySectionOffset = lsda_base_offset +
//                 info.lsdas_lookup.get(page.start).? * @sizeOf(macho.unwind_info_section_header_lsda_index_entry),
//         });
//     }

//     const last_entry = info.records.items[info.records.items.len - 1];
//     const sentinel_address = @as(u32, @intCast(last_entry.rangeStart + last_entry.rangeLength));
//     try writer.writeStruct(macho.unwind_info_section_header_index_entry{
//         .functionOffset = sentinel_address,
//         .secondLevelPagesSectionOffset = 0,
//         .lsdaIndexArraySectionOffset = lsda_base_offset +
//             @as(u32, @intCast(info.lsdas.items.len)) * @sizeOf(macho.unwind_info_section_header_lsda_index_entry),
//     });

//     for (info.lsdas.items) |record_id| {
//         const record = info.records.items[record_id];
//         try writer.writeStruct(macho.unwind_info_section_header_lsda_index_entry{
//             .functionOffset = @as(u32, @intCast(record.rangeStart)),
//             .lsdaOffset = @as(u32, @intCast(record.lsda)),
//         });
//     }

//     for (info.pages.items) |page| {
//         const start = cwriter.bytes_written;
//         try page.write(info, writer);
//         const nwritten = cwriter.bytes_written - start;
//         if (nwritten < second_level_page_bytes) {
//             try writer.writeByteNTimes(0, second_level_page_bytes - nwritten);
//         }
//     }

//     const padding = buffer.items.len - cwriter.bytes_written;
//     if (padding > 0) {
//         @memset(buffer.items[cwriter.bytes_written..], 0);
//     }

//     try macho_file.base.file.pwriteAll(buffer.items, sect.offset);
// }

// fn getRelocs(macho_file: *MachO, object_id: u32, record_id: usize) []const macho.relocation_info {
//     const object = &macho_file.objects.items[object_id];
//     assert(object.hasUnwindRecords());
//     const rel_pos = object.unwind_relocs_lookup[record_id].reloc;
//     const relocs = object.getRelocs(object.unwind_info_sect_id.?);
//     return relocs[rel_pos.start..][0..rel_pos.len];
// }

// fn isPersonalityFunction(record_id: usize, rel: macho.relocation_info) bool {
//     const base_offset = @as(i32, @intCast(record_id * @sizeOf(macho.compact_unwind_entry)));
//     const rel_offset = rel.r_address - base_offset;
//     return rel_offset == 16;
// }

// pub fn getPersonalityFunctionReloc(
//     macho_file: *MachO,
//     object_id: u32,
//     record_id: usize,
// ) ?macho.relocation_info {
//     const relocs = getRelocs(macho_file, object_id, record_id);
//     for (relocs) |rel| {
//         if (isPersonalityFunction(record_id, rel)) return rel;
//     }
//     return null;
// }

fn getOrPutPersonalityFunction(info: *UnwindInfo, sym_index: Symbol.Index) error{TooManyPersonalities}!u2 {
    comptime var index: u2 = 0;
    inline while (index < max_personalities) : (index += 1) {
        if (info.personalities[index] == sym_index) {
            return index;
        } else if (index == info.personalities_count) {
            info.personalities[index] = sym_index;
            info.personalities_count += 1;
            return index;
        }
    }
    return error.TooManyPersonalities;
}

// fn isLsda(record_id: usize, rel: macho.relocation_info) bool {
//     const base_offset = @as(i32, @intCast(record_id * @sizeOf(macho.compact_unwind_entry)));
//     const rel_offset = rel.r_address - base_offset;
//     return rel_offset == 24;
// }

// pub fn getLsdaReloc(macho_file: *MachO, object_id: u32, record_id: usize) ?macho.relocation_info {
//     const relocs = getRelocs(macho_file, object_id, record_id);
//     for (relocs) |rel| {
//         if (isLsda(record_id, rel)) return rel;
//     }
//     return null;
// }

fn appendCommonEncoding(info: *UnwindInfo, enc: Encoding) void {
    assert(info.common_encodings_count <= max_common_encodings);
    info.common_encodings[info.common_encodings_count] = enc;
    info.common_encodings_count += 1;
}

fn getCommonEncoding(info: UnwindInfo, enc: Encoding) ?u7 {
    comptime var index: u7 = 0;
    inline while (index < max_common_encodings) : (index += 1) {
        if (index >= info.common_encodings_count) return null;
        if (info.common_encodings[index].eql(enc)) {
            return index;
        }
    }
    return null;
}

pub const Encoding = extern struct {
    enc: macho.compact_unwind_encoding_t,

    pub fn getMode(enc: Encoding) u4 {
        comptime assert(macho.UNWIND_ARM64_MODE_MASK == macho.UNWIND_X86_64_MODE_MASK);
        return @as(u4, @truncate((enc.enc & macho.UNWIND_ARM64_MODE_MASK) >> 24));
    }

    pub fn isDwarf(enc: Encoding, macho_file: *MachO) bool {
        const mode = enc.getMode();
        return switch (macho_file.options.cpu_arch.?) {
            .aarch64 => @as(macho.UNWIND_ARM64_MODE, @enumFromInt(mode)) == .DWARF,
            .x86_64 => @as(macho.UNWIND_X86_64_MODE, @enumFromInt(mode)) == .DWARF,
            else => unreachable,
        };
    }

    pub fn setMode(enc: *Encoding, mode: anytype) void {
        enc.enc |= @as(u32, @intCast(@intFromEnum(mode))) << 24;
    }

    pub fn hasLsda(enc: Encoding) bool {
        const has_lsda = @as(u1, @truncate((enc.enc & macho.UNWIND_HAS_LSDA) >> 31));
        return has_lsda == 1;
    }

    pub fn setHasLsda(enc: *Encoding, has_lsda: bool) void {
        const mask = @as(u32, @intCast(@intFromBool(has_lsda))) << 31;
        enc.enc |= mask;
    }

    pub fn getPersonalityIndex(enc: Encoding) u2 {
        const index = @as(u2, @truncate((enc.enc & macho.UNWIND_PERSONALITY_MASK) >> 28));
        return index;
    }

    pub fn setPersonalityIndex(enc: *Encoding, index: u2) void {
        const mask = @as(u32, @intCast(index)) << 28;
        enc.enc |= mask;
    }

    pub fn getDwarfSectionOffset(enc: Encoding) u24 {
        const offset = @as(u24, @truncate(enc.enc));
        return offset;
    }

    pub fn setDwarfSectionOffset(enc: *Encoding, offset: u24) void {
        enc.enc |= offset;
    }

    pub fn eql(enc: Encoding, other: Encoding) bool {
        return enc.enc == other.enc;
    }

    pub fn format(
        enc: Encoding,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("0x{x:0>8}", .{enc.enc});
    }
};

pub const Record = struct {
    length: u32 = 0,
    enc: Encoding = .{ .enc = 0 },
    atom: Atom.Index = 0,
    atom_offset: u32 = 0,
    lsda: Atom.Index = 0,
    lsda_offset: u32 = 0,
    personality: ?Symbol.Index = null, // TODO make this zero-is-null
    fde: Fde.Index = 0, // TODO actually make FDE at 0 an invalid FDE
    file: File.Index = 0,
    alive: bool = true,

    pub fn getObject(rec: Record, macho_file: *MachO) *Object {
        return macho_file.getFile(rec.file).?.object;
    }

    pub fn getAtom(rec: Record, macho_file: *MachO) *Atom {
        return macho_file.getAtom(rec.atom).?;
    }

    pub fn getLsdaAtom(rec: Record, macho_file: *MachO) ?*Atom {
        return macho_file.getAtom(rec.lsda);
    }

    pub fn getPersonality(rec: Record, macho_file: *MachO) ?*Symbol {
        const personality = rec.personality orelse return null;
        return macho_file.getSymbol(personality);
    }

    pub fn getFde(rec: Record, macho_file: *MachO) ?Fde {
        if (!rec.enc.isDwarf(macho_file)) return null;
        return rec.getObject(macho_file).fdes.items[rec.fde];
    }

    pub fn getAtomAddress(rec: Record, macho_file: *MachO) u64 {
        const atom = rec.getAtom(macho_file);
        return atom.value + atom.off;
    }

    pub fn format(
        rec: Record,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = rec;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compileError("do not format UnwindInfo.Records directly");
    }

    pub fn fmt(rec: Record, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .rec = rec,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        rec: Record,
        macho_file: *MachO,
    };

    fn format2(
        ctx: FormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const rec = ctx.rec;
        const macho_file = ctx.macho_file;
        try writer.print("{x} : len({x})", .{
            rec.enc.enc, rec.length,
        });
        if (rec.enc.isDwarf(macho_file)) try writer.print(" : fde({d})", .{rec.fde});
        try writer.print(" : {s}", .{rec.getAtom(macho_file).getName(macho_file)});
        if (!rec.alive) try writer.writeAll(" : [*]");
    }

    pub const Index = u32;
};

const max_personalities = 3;
const max_common_encodings = 127;
const max_compact_encodings = 256;

const second_level_page_bytes = 0x1000;
const second_level_page_words = second_level_page_bytes / @sizeOf(u32);

const max_regular_second_level_entries =
    (second_level_page_bytes - @sizeOf(macho.unwind_info_regular_second_level_page_header)) /
    @sizeOf(macho.unwind_info_regular_second_level_entry);

const max_compressed_second_level_entries =
    (second_level_page_bytes - @sizeOf(macho.unwind_info_compressed_second_level_page_header)) /
    @sizeOf(u32);

const compressed_entry_func_offset_mask = ~@as(u24, 0);

const Page = struct {
    kind: enum { regular, compressed },
    start: Record.Index,
    count: u16,
    page_encodings: [max_compact_encodings]Record.Index = undefined,
    page_encodings_count: u9 = 0,

    fn appendPageEncoding(page: *Page, record_id: Record.Index) void {
        assert(page.page_encodings_count <= max_compact_encodings);
        page.page_encodings[page.page_encodings_count] = record_id;
        page.page_encodings_count += 1;
    }

    fn getPageEncoding(
        page: *const Page,
        info: *const UnwindInfo,
        enc: macho.compact_unwind_encoding_t,
    ) ?u8 {
        comptime var index: u9 = 0;
        inline while (index < max_compact_encodings) : (index += 1) {
            if (index >= page.page_encodings_count) return null;
            const record_id = page.page_encodings[index];
            const record = info.records.items[record_id];
            if (record.compactUnwindEncoding == enc) {
                return @as(u8, @intCast(index));
            }
        }
        return null;
    }

    fn format(
        page: *const Page,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = page;
        _ = unused_format_string;
        _ = options;
        _ = writer;
        @compileError("do not format Page directly; use page.fmtDebug()");
    }

    const DumpCtx = struct {
        page: *const Page,
        info: *const UnwindInfo,
    };

    fn dump(
        ctx: DumpCtx,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        comptime assert(unused_format_string.len == 0);
        try writer.writeAll("Page:\n");
        try writer.print("  kind: {s}\n", .{@tagName(ctx.page.kind)});
        try writer.print("  entries: {d} - {d}\n", .{
            ctx.page.start,
            ctx.page.start + ctx.page.count,
        });
        try writer.print("  encodings (count = {d})\n", .{ctx.page.page_encodings_count});
        for (ctx.page.page_encodings[0..ctx.page.page_encodings_count], 0..) |record_id, i| {
            const record = ctx.info.records.items[record_id];
            const enc = record.compactUnwindEncoding;
            try writer.print("    {d}: 0x{x:0>8}\n", .{ ctx.info.common_encodings_count + i, enc });
        }
    }

    fn fmtDebug(page: *const Page, info: *const UnwindInfo) std.fmt.Formatter(dump) {
        return .{ .data = .{
            .page = page,
            .info = info,
        } };
    }

    fn write(page: *const Page, info: *const UnwindInfo, writer: anytype) !void {
        switch (page.kind) {
            .regular => {
                try writer.writeStruct(macho.unwind_info_regular_second_level_page_header{
                    .entryPageOffset = @sizeOf(macho.unwind_info_regular_second_level_page_header),
                    .entryCount = page.count,
                });

                for (info.records.items[page.start..][0..page.count]) |record| {
                    try writer.writeStruct(macho.unwind_info_regular_second_level_entry{
                        .functionOffset = @as(u32, @intCast(record.rangeStart)),
                        .encoding = record.compactUnwindEncoding,
                    });
                }
            },
            .compressed => {
                const entry_offset = @sizeOf(macho.unwind_info_compressed_second_level_page_header) +
                    @as(u16, @intCast(page.page_encodings_count)) * @sizeOf(u32);
                try writer.writeStruct(macho.unwind_info_compressed_second_level_page_header{
                    .entryPageOffset = entry_offset,
                    .entryCount = page.count,
                    .encodingsPageOffset = @sizeOf(
                        macho.unwind_info_compressed_second_level_page_header,
                    ),
                    .encodingsCount = page.page_encodings_count,
                });

                for (page.page_encodings[0..page.page_encodings_count]) |record_id| {
                    const enc = info.records.items[record_id].compactUnwindEncoding;
                    try writer.writeInt(u32, enc, .little);
                }

                assert(page.count > 0);
                const first_entry = info.records.items[page.start];
                for (info.records.items[page.start..][0..page.count]) |record| {
                    const enc_index = blk: {
                        if (info.getCommonEncoding(record.compactUnwindEncoding)) |id| {
                            break :blk id;
                        }
                        const ncommon = info.common_encodings_count;
                        break :blk ncommon + page.getPageEncoding(info, record.compactUnwindEncoding).?;
                    };
                    const compressed = macho.UnwindInfoCompressedEntry{
                        .funcOffset = @as(u24, @intCast(record.rangeStart - first_entry.rangeStart)),
                        .encodingIndex = @as(u8, @intCast(enc_index)),
                    };
                    try writer.writeStruct(compressed);
                }
            },
        }
    }
};

const std = @import("std");
const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const fs = std.fs;
const leb = std.leb;
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const UnwindInfo = @This();
