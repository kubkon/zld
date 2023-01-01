const Object = @This();

const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const fs = std.fs;
const io = std.io;
const log = std.log.scoped(.macho);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const sort = std.sort;
const trace = @import("../tracy.zig").trace;
const unwind_info = @import("unwind_info.zig");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const AtomIndex = MachO.AtomIndex;
const DwarfInfo = @import("DwarfInfo.zig");
const LoadCommandIterator = macho.LoadCommandIterator;
const MachO = @import("../MachO.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;
const UnwindRecord = unwind_info.UnwindRecord;

name: []const u8,
mtime: u64,
contents: []align(@alignOf(u64)) const u8,

header: macho.mach_header_64 = undefined,

/// Symtab and strtab might not exist for empty object files so we use an optional
/// to signal this.
in_symtab: ?[]align(1) const macho.nlist_64 = null,
in_strtab: ?[]const u8 = null,

/// Output symtab is sorted so that we can easily reference symbols following each
/// other in address space.
/// The length of the symtab is at least of the input symtab length however there
/// can be trailing section symbols.
symtab: []macho.nlist_64 = undefined,
/// Can be undefined as set together with in_symtab.
source_symtab_lookup: []u32 = undefined,
/// Can be undefined as set together with in_symtab.
reverse_symtab_lookup: []u32 = undefined,
/// Can be undefined as set together with in_symtab.
source_address_lookup: []i64 = undefined,
/// Can be undefined as set together with in_symtab.
source_section_index_lookup: []i64 = undefined,
/// Can be undefined as set together with in_symtab.
strtab_lookup: []u32 = undefined,
/// Can be undefined as set together with in_symtab.
atom_by_index_table: []AtomIndex = undefined,
/// Can be undefined as set together with in_symtab.
globals_lookup: []i64 = undefined,
/// Can be undefined as set together with in_symtab.
relocs_lookup: []RelocEntry = undefined,

atoms: std.ArrayListUnmanaged(AtomIndex) = .{},

unwind_info_sect: ?macho.section_64 = null,
unwind_relocs_lookup: []RelocEntry = undefined,
exec_atoms: std.ArrayListUnmanaged(AtomIndex) = .{},
unwind_records_lookup: std.AutoHashMapUnmanaged(AtomIndex, u32) = .{},

const RelocEntry = struct { start: u32, len: u32 };

pub fn deinit(self: *Object, gpa: Allocator) void {
    self.atoms.deinit(gpa);
    gpa.free(self.name);
    gpa.free(self.contents);
    if (self.in_symtab) |_| {
        gpa.free(self.source_symtab_lookup);
        gpa.free(self.reverse_symtab_lookup);
        gpa.free(self.source_address_lookup);
        gpa.free(self.source_section_index_lookup);
        gpa.free(self.strtab_lookup);
        gpa.free(self.symtab);
        gpa.free(self.atom_by_index_table);
        gpa.free(self.globals_lookup);
        gpa.free(self.relocs_lookup);
    }
    if (self.unwind_info_sect) |_| {
        gpa.free(self.unwind_relocs_lookup);
    }
    self.exec_atoms.deinit(gpa);
    self.unwind_records_lookup.deinit(gpa);
}

pub fn parse(self: *Object, allocator: Allocator, cpu_arch: std.Target.Cpu.Arch) !void {
    const tracy = trace(@src());
    defer tracy.end();

    var stream = std.io.fixedBufferStream(self.contents);
    const reader = stream.reader();

    self.header = try reader.readStruct(macho.mach_header_64);

    if (self.header.filetype != macho.MH_OBJECT) {
        log.debug("invalid filetype: expected 0x{x}, found 0x{x}", .{
            macho.MH_OBJECT,
            self.header.filetype,
        });
        return error.NotObject;
    }

    const this_arch: std.Target.Cpu.Arch = switch (self.header.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => |value| {
            log.err("unsupported cpu architecture 0x{x}", .{value});
            return error.UnsupportedCpuArchitecture;
        },
    };
    if (this_arch != cpu_arch) {
        log.err("mismatched cpu architecture: expected {s}, found {s}", .{
            @tagName(cpu_arch),
            @tagName(this_arch),
        });
        return error.MismatchedCpuArchitecture;
    }

    var it = LoadCommandIterator{
        .ncmds = self.header.ncmds,
        .buffer = self.contents[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds],
    };
    const nsects = self.getSourceSections().len;
    const symtab = while (it.next()) |cmd| switch (cmd.cmd()) {
        .SYMTAB => break cmd.cast(macho.symtab_command).?,
        else => {},
    } else return;

    self.in_symtab = @ptrCast(
        [*]const macho.nlist_64,
        @alignCast(@alignOf(macho.nlist_64), &self.contents[symtab.symoff]),
    )[0..symtab.nsyms];
    self.in_strtab = self.contents[symtab.stroff..][0..symtab.strsize];

    self.symtab = try allocator.alloc(macho.nlist_64, self.in_symtab.?.len + nsects);
    self.source_symtab_lookup = try allocator.alloc(u32, self.in_symtab.?.len);
    self.reverse_symtab_lookup = try allocator.alloc(u32, self.in_symtab.?.len);
    self.strtab_lookup = try allocator.alloc(u32, self.in_symtab.?.len);
    self.globals_lookup = try allocator.alloc(i64, self.in_symtab.?.len);
    self.atom_by_index_table = try allocator.alloc(AtomIndex, self.in_symtab.?.len + nsects);
    self.relocs_lookup = try allocator.alloc(RelocEntry, self.in_symtab.?.len + nsects);
    // This is wasteful but we need to be able to lookup source symbol address after stripping and
    // allocating of sections.
    self.source_address_lookup = try allocator.alloc(i64, self.in_symtab.?.len);
    self.source_section_index_lookup = try allocator.alloc(i64, nsects);

    for (self.symtab) |*sym| {
        sym.* = .{
            .n_value = 0,
            .n_sect = 0,
            .n_desc = 0,
            .n_strx = 0,
            .n_type = 0,
        };
    }

    mem.set(i64, self.globals_lookup, -1);
    mem.set(AtomIndex, self.atom_by_index_table, 0);
    mem.set(i64, self.source_section_index_lookup, -1);
    mem.set(RelocEntry, self.relocs_lookup, .{
        .start = 0,
        .len = 0,
    });

    // You would expect that the symbol table is at least pre-sorted based on symbol's type:
    // local < extern defined < undefined. Unfortunately, this is not guaranteed! For instance,
    // the GO compiler does not necessarily respect that therefore we sort immediately by type
    // and address within.
    var sorted_all_syms = try std.ArrayList(SymbolAtIndex).initCapacity(allocator, self.in_symtab.?.len);
    defer sorted_all_syms.deinit();

    for (self.in_symtab.?) |_, index| {
        sorted_all_syms.appendAssumeCapacity(.{ .index = @intCast(u32, index) });
    }

    // We sort by type: defined < undefined, and
    // afterwards by address in each group. Normally, dysymtab should
    // be enough to guarantee the sort, but turns out not every compiler
    // is kind enough to specify the symbols in the correct order.
    sort.sort(SymbolAtIndex, sorted_all_syms.items, self, SymbolAtIndex.lessThan);

    for (sorted_all_syms.items) |sym_id, i| {
        const sym = sym_id.getSymbol(self);

        if (sym.sect() and self.source_section_index_lookup[sym.n_sect - 1] == -1) {
            self.source_section_index_lookup[sym.n_sect - 1] = @intCast(i64, i);
        }

        self.symtab[i] = sym;
        self.source_address_lookup[i] = if (sym.undf()) -1 else @intCast(i64, sym.n_value);
        self.source_symtab_lookup[i] = sym_id.index;
        self.reverse_symtab_lookup[sym_id.index] = @intCast(u32, i);

        const sym_name_len = mem.sliceTo(@ptrCast([*:0]const u8, self.in_strtab.?.ptr + sym.n_strx), 0).len + 1;
        self.strtab_lookup[i] = @intCast(u32, sym_name_len);
    }

    // Parse __LD,__compact_unwind if one exists.
    self.unwind_info_sect = self.getSourceSectionByName("__LD", "__compact_unwind");
    if (self.unwind_info_sect) |_| {
        self.unwind_relocs_lookup = try allocator.alloc(RelocEntry, self.getUnwindRecords().len);
        mem.set(RelocEntry, self.unwind_relocs_lookup, .{
            .start = 0,
            .len = 0,
        });
    }
}

const SymbolAtIndex = struct {
    index: u32,

    const Context = *const Object;

    fn getSymbol(self: SymbolAtIndex, ctx: Context) macho.nlist_64 {
        return ctx.in_symtab.?[self.index];
    }

    fn getSymbolName(self: SymbolAtIndex, ctx: Context) []const u8 {
        const off = self.getSymbol(ctx).n_strx;
        return mem.sliceTo(@ptrCast([*:0]const u8, ctx.in_strtab.?.ptr + off), 0);
    }

    /// Performs lexicographic-like check.
    /// * lhs and rhs defined
    ///   * if lhs == rhs
    ///     * if lhs.n_sect == rhs.n_sect
    ///       * ext < weak < local < temp
    ///     * lhs.n_sect < rhs.n_sect
    ///   * lhs < rhs
    /// * !rhs is undefined
    fn lessThan(ctx: Context, lhs_index: SymbolAtIndex, rhs_index: SymbolAtIndex) bool {
        const lhs = lhs_index.getSymbol(ctx);
        const rhs = rhs_index.getSymbol(ctx);
        if (lhs.sect() and rhs.sect()) {
            if (lhs.n_value == rhs.n_value) {
                if (lhs.n_sect == rhs.n_sect) {
                    if (lhs.ext() and rhs.ext()) {
                        if ((lhs.pext() or lhs.weakDef()) and (rhs.pext() or rhs.weakDef())) {
                            return false;
                        } else return rhs.pext() or rhs.weakDef();
                    } else {
                        const lhs_name = lhs_index.getSymbolName(ctx);
                        const lhs_temp = mem.startsWith(u8, lhs_name, "l") or mem.startsWith(u8, lhs_name, "L");
                        const rhs_name = rhs_index.getSymbolName(ctx);
                        const rhs_temp = mem.startsWith(u8, rhs_name, "l") or mem.startsWith(u8, rhs_name, "L");
                        if (lhs_temp and rhs_temp) {
                            return false;
                        } else return rhs_temp;
                    }
                } else return lhs.n_sect < rhs.n_sect;
            } else return lhs.n_value < rhs.n_value;
        } else if (lhs.undf() and rhs.undf()) {
            return false;
        } else return rhs.undf();
    }

    fn lessThanByNStrx(ctx: Context, lhs: SymbolAtIndex, rhs: SymbolAtIndex) bool {
        return lhs.getSymbol(ctx).n_strx < rhs.getSymbol(ctx).n_strx;
    }
};

fn filterSymbolsBySection(symbols: []macho.nlist_64, n_sect: u8) struct {
    index: u32,
    len: u32,
} {
    const FirstMatch = struct {
        n_sect: u8,

        pub fn predicate(pred: @This(), symbol: macho.nlist_64) bool {
            return symbol.n_sect == pred.n_sect;
        }
    };
    const FirstNonMatch = struct {
        n_sect: u8,

        pub fn predicate(pred: @This(), symbol: macho.nlist_64) bool {
            return symbol.n_sect != pred.n_sect;
        }
    };

    const index = MachO.lsearch(macho.nlist_64, symbols, FirstMatch{
        .n_sect = n_sect,
    });
    const len = MachO.lsearch(macho.nlist_64, symbols[index..], FirstNonMatch{
        .n_sect = n_sect,
    });

    return .{ .index = @intCast(u32, index), .len = @intCast(u32, len) };
}

fn filterSymbolsByAddress(symbols: []macho.nlist_64, start_addr: u64, end_addr: u64) struct {
    index: u32,
    len: u32,
} {
    const Predicate = struct {
        addr: u64,

        pub fn predicate(pred: @This(), symbol: macho.nlist_64) bool {
            return symbol.n_value >= pred.addr;
        }
    };

    const index = MachO.lsearch(macho.nlist_64, symbols, Predicate{
        .addr = start_addr,
    });
    const len = MachO.lsearch(macho.nlist_64, symbols[index..], Predicate{
        .addr = end_addr,
    });

    return .{ .index = @intCast(u32, index), .len = @intCast(u32, len) };
}

const SortedSection = struct {
    header: macho.section_64,
    id: u8,
};

fn sectionLessThanByAddress(ctx: void, lhs: SortedSection, rhs: SortedSection) bool {
    _ = ctx;
    if (lhs.header.addr == rhs.header.addr) {
        return lhs.id < rhs.id;
    }
    return lhs.header.addr < rhs.header.addr;
}

pub fn splitIntoAtoms(self: *Object, macho_file: *MachO, object_id: u31) !void {
    log.debug("splitting object({d}, {s}) into atoms", .{ object_id, self.name });

    try self.splitRegularSections(macho_file, object_id);
    try self.parseUnwindInfo(macho_file, object_id);
}

pub fn splitRegularSections(self: *Object, macho_file: *MachO, object_id: u31) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.allocator;

    const sections = self.getSourceSections();
    for (sections) |sect, id| {
        if (sect.isDebug()) continue;
        const out_sect_id = (try macho_file.getOutputSection(sect)) orelse {
            log.debug("  unhandled section '{s},{s}'", .{ sect.segName(), sect.sectName() });
            continue;
        };
        if (sect.size == 0) continue;

        const sect_id = @intCast(u8, id);
        const sym = self.getSectionAliasSymbolPtr(sect_id);
        sym.* = .{
            .n_strx = 0,
            .n_type = macho.N_SECT,
            .n_sect = out_sect_id + 1,
            .n_desc = 0,
            .n_value = sect.addr,
        };
    }

    if (self.in_symtab == null) {
        for (sections) |sect, id| {
            if (sect.isDebug()) continue;
            const out_sect_id = (try macho_file.getOutputSection(sect)) orelse continue;
            if (sect.size == 0) continue;

            const sect_id = @intCast(u8, id);
            const sym_index = self.getSectionAliasSymbolIndex(sect_id);
            const atom_index = try self.createAtomFromSubsection(
                macho_file,
                object_id,
                sym_index,
                0,
                0,
                sect.size,
                sect.@"align",
                out_sect_id,
            );
            macho_file.addAtomToSection(atom_index);
        }
        return;
    }

    // Well, shit, sometimes compilers skip the dysymtab load command altogether, meaning we
    // have to infer the start of undef section in the symtab ourselves.
    const iundefsym = blk: {
        const dysymtab = self.parseDysymtab() orelse {
            var iundefsym: usize = self.in_symtab.?.len;
            while (iundefsym > 0) : (iundefsym -= 1) {
                const sym = self.symtab[iundefsym - 1];
                if (sym.sect()) break;
            }
            break :blk iundefsym;
        };
        break :blk dysymtab.iundefsym;
    };

    // We only care about defined symbols, so filter every other out.
    const symtab = try gpa.dupe(macho.nlist_64, self.symtab[0..iundefsym]);
    defer gpa.free(symtab);

    const subsections_via_symbols = self.header.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0;

    // Sort section headers by address.
    var sorted_sections = try gpa.alloc(SortedSection, sections.len);
    defer gpa.free(sorted_sections);

    for (sections) |sect, id| {
        sorted_sections[id] = .{ .header = sect, .id = @intCast(u8, id) };
    }

    std.sort.sort(SortedSection, sorted_sections, {}, sectionLessThanByAddress);

    var sect_sym_index: u32 = 0;
    for (sorted_sections) |section| {
        const sect = section.header;
        if (sect.isDebug()) continue;

        const sect_id = section.id;
        log.debug("splitting section '{s},{s}' into atoms", .{ sect.segName(), sect.sectName() });

        // Get output segment/section in the final artifact.
        const out_sect_id = (try macho_file.getOutputSection(sect)) orelse continue;

        log.debug("  output sect({d}, '{s},{s}')", .{
            out_sect_id + 1,
            macho_file.sections.items(.header)[out_sect_id].segName(),
            macho_file.sections.items(.header)[out_sect_id].sectName(),
        });

        const cpu_arch = macho_file.options.target.cpu_arch.?;
        const sect_loc = filterSymbolsBySection(symtab[sect_sym_index..], sect_id + 1);
        const sect_start_index = sect_sym_index + sect_loc.index;

        sect_sym_index += sect_loc.len;

        if (sect.size == 0) continue;
        if (subsections_via_symbols and sect_loc.len > 0) {
            // If the first nlist does not match the start of the section,
            // then we need to encapsulate the memory range [section start, first symbol)
            // as a temporary symbol and insert the matching Atom.
            const first_sym = symtab[sect_start_index];
            if (first_sym.n_value > sect.addr) {
                const sym_index = self.getSectionAliasSymbolIndex(sect_id);
                const atom_size = first_sym.n_value - sect.addr;
                const atom_index = try self.createAtomFromSubsection(
                    macho_file,
                    object_id,
                    sym_index,
                    0,
                    0,
                    atom_size,
                    sect.@"align",
                    out_sect_id,
                );
                if (!sect.isZerofill()) {
                    try self.cacheRelocs(macho_file, atom_index);
                }
                macho_file.addAtomToSection(atom_index);
            }

            var next_sym_index = sect_start_index;
            while (next_sym_index < sect_start_index + sect_loc.len) {
                const next_sym = symtab[next_sym_index];
                const addr = next_sym.n_value;
                const atom_loc = filterSymbolsByAddress(symtab[next_sym_index..], addr, addr + 1);
                assert(atom_loc.len > 0);
                const atom_sym_index = atom_loc.index + next_sym_index;
                const nsyms_trailing = atom_loc.len - 1;
                next_sym_index += atom_loc.len;

                const atom_size = if (next_sym_index < sect_start_index + sect_loc.len)
                    symtab[next_sym_index].n_value - addr
                else
                    sect.addr + sect.size - addr;

                const atom_align = if (addr > 0)
                    math.min(@ctz(addr), sect.@"align")
                else
                    sect.@"align";

                const atom_index = try self.createAtomFromSubsection(
                    macho_file,
                    object_id,
                    atom_sym_index,
                    atom_sym_index + 1,
                    nsyms_trailing,
                    atom_size,
                    atom_align,
                    out_sect_id,
                );

                // TODO rework this at the relocation level
                if (cpu_arch == .x86_64 and addr == sect.addr) {
                    // In x86_64 relocs, it can so happen that the compiler refers to the same
                    // atom by both the actual assigned symbol and the start of the section. In this
                    // case, we need to link the two together so add an alias.
                    const alias_index = self.getSectionAliasSymbolIndex(sect_id);
                    self.atom_by_index_table[alias_index] = atom_index;
                }
                if (!sect.isZerofill()) {
                    try self.cacheRelocs(macho_file, atom_index);
                }
                macho_file.addAtomToSection(atom_index);
            }
        } else {
            const alias_index = self.getSectionAliasSymbolIndex(sect_id);
            const atom_index = try self.createAtomFromSubsection(
                macho_file,
                object_id,
                alias_index,
                sect_start_index,
                sect_loc.len,
                sect.size,
                sect.@"align",
                out_sect_id,
            );
            if (!sect.isZerofill()) {
                try self.cacheRelocs(macho_file, atom_index);
            }
            macho_file.addAtomToSection(atom_index);
        }
    }
}

fn createAtomFromSubsection(
    self: *Object,
    macho_file: *MachO,
    object_id: u31,
    sym_index: u32,
    inner_sym_index: u32,
    inner_nsyms_trailing: u32,
    size: u64,
    alignment: u32,
    out_sect_id: u8,
) !AtomIndex {
    const gpa = macho_file.base.allocator;
    const atom_index = try macho_file.createEmptyAtom(sym_index, size, alignment);
    const atom = macho_file.getAtomPtr(atom_index);
    atom.inner_sym_index = inner_sym_index;
    atom.inner_nsyms_trailing = inner_nsyms_trailing;
    atom.file = object_id;
    self.symtab[sym_index].n_sect = out_sect_id + 1;

    log.debug("creating ATOM(%{d}, '{s}') in sect({d}, '{s},{s}') in object({d})", .{
        sym_index,
        self.getSymbolName(sym_index),
        out_sect_id + 1,
        macho_file.sections.items(.header)[out_sect_id].segName(),
        macho_file.sections.items(.header)[out_sect_id].sectName(),
        object_id,
    });

    try self.atoms.append(gpa, atom_index);
    self.atom_by_index_table[sym_index] = atom_index;

    var it = Atom.getInnerSymbolsIterator(macho_file, atom_index);
    while (it.next()) |sym_loc| {
        const inner = macho_file.getSymbolPtr(sym_loc);
        inner.n_sect = out_sect_id + 1;
        self.atom_by_index_table[sym_loc.sym_index] = atom_index;
    }

    const out_sect = macho_file.sections.items(.header)[out_sect_id];
    if (out_sect.isCode() and
        mem.eql(u8, "__TEXT", out_sect.segName()) and
        mem.eql(u8, "__text", out_sect.sectName()))
    {
        // TODO currently assuming a single section for executable machine code
        try self.exec_atoms.append(gpa, atom_index);
    }

    return atom_index;
}

fn filterRelocs(
    relocs: []align(1) const macho.relocation_info,
    start_addr: u64,
    end_addr: u64,
) RelocEntry {
    const Predicate = struct {
        addr: u64,

        pub fn predicate(self: @This(), rel: macho.relocation_info) bool {
            return rel.r_address >= self.addr;
        }
    };
    const LPredicate = struct {
        addr: u64,

        pub fn predicate(self: @This(), rel: macho.relocation_info) bool {
            return rel.r_address < self.addr;
        }
    };

    const start = MachO.bsearch(macho.relocation_info, relocs, Predicate{ .addr = end_addr });
    const len = MachO.lsearch(macho.relocation_info, relocs[start..], LPredicate{ .addr = start_addr });

    return .{ .start = @intCast(u32, start), .len = @intCast(u32, len) };
}

fn cacheRelocs(self: *Object, macho_file: *MachO, atom_index: AtomIndex) !void {
    const atom = macho_file.getAtom(atom_index);

    const source_sect = if (self.getSourceSymbol(atom.sym_index)) |source_sym| blk: {
        const source_sect = self.getSourceSection(source_sym.n_sect - 1);
        assert(!source_sect.isZerofill());
        break :blk source_sect;
    } else blk: {
        // If there was no matching symbol present in the source symtab, this means
        // we are dealing with either an entire section, or part of it, but also
        // starting at the beginning.
        const nbase = @intCast(u32, self.in_symtab.?.len);
        const sect_id = @intCast(u16, atom.sym_index - nbase);
        const source_sect = self.getSourceSection(sect_id);
        assert(!source_sect.isZerofill());
        break :blk source_sect;
    };

    const relocs = self.getRelocs(source_sect);

    self.relocs_lookup[atom.sym_index] = if (self.getSourceSymbol(atom.sym_index)) |source_sym| blk: {
        const offset = source_sym.n_value - source_sect.addr;
        break :blk filterRelocs(relocs, offset, offset + atom.size);
    } else filterRelocs(relocs, 0, atom.size);
}

fn parseUnwindInfo(self: *Object, macho_file: *MachO, object_id: u31) !void {
    const sect = self.unwind_info_sect orelse return;

    _ = try macho_file.initSection("__TEXT", "__unwind_info", .{});

    try self.unwind_records_lookup.ensureTotalCapacity(
        macho_file.base.allocator,
        @intCast(u32, self.exec_atoms.items.len),
    );

    const relocs = self.getRelocs(sect);
    const unwind_records = self.getUnwindRecords();
    for (unwind_records) |record, record_id| {
        const enc = try macho.UnwindEncodingArm64.fromU32(record.compactUnwindEncoding);
        if (enc == .dwarf) {
            log.err("TODO: handle DWARF CFI as compact unwind encoding value", .{});
            return error.HandleDwarfCompactEncoding;
        }
        const offset = record_id * @sizeOf(macho.compact_unwind_entry);
        const rel_pos = filterRelocs(
            relocs,
            offset,
            offset + @sizeOf(macho.compact_unwind_entry),
        );
        assert(rel_pos.len > 0); // TODO convert to an error as the unwind info is malformed
        self.unwind_relocs_lookup[record_id] = rel_pos;

        // Find function symbol that this record describes
        const rel = relocs[rel_pos.start..][rel_pos.len - 1];
        const target = unwind_info.parseRelocTarget(macho_file, record, record_id, object_id, rel);
        assert(target.getFile() == object_id);
        const atom_index = self.getAtomIndexForSymbol(target.sym_index).?;
        self.unwind_records_lookup.putAssumeCapacityNoClobber(atom_index, @intCast(u32, record_id));
    }
}

pub fn getSourceSymbol(self: Object, index: u32) ?macho.nlist_64 {
    const symtab = self.in_symtab.?;
    if (index >= symtab.len) return null;
    const mapped_index = self.source_symtab_lookup[index];
    return symtab[mapped_index];
}

pub fn getSourceSection(self: Object, index: u16) macho.section_64 {
    const sections = self.getSourceSections();
    assert(index < sections.len);
    return sections[index];
}

pub fn getSourceSectionByName(self: Object, segname: []const u8, sectname: []const u8) ?macho.section_64 {
    const sections = self.getSourceSections();
    for (sections) |sect| {
        if (mem.eql(u8, segname, sect.segName()) and mem.eql(u8, sectname, sect.sectName()))
            return sect;
    } else return null;
}

pub fn getSourceSections(self: Object) []const macho.section_64 {
    var it = LoadCommandIterator{
        .ncmds = self.header.ncmds,
        .buffer = self.contents[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds],
    };
    while (it.next()) |cmd| switch (cmd.cmd()) {
        .SEGMENT_64 => {
            return cmd.getSections();
        },
        else => {},
    } else unreachable;
}

pub fn parseDataInCode(self: Object) ?[]const macho.data_in_code_entry {
    var it = LoadCommandIterator{
        .ncmds = self.header.ncmds,
        .buffer = self.contents[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds],
    };
    while (it.next()) |cmd| {
        switch (cmd.cmd()) {
            .DATA_IN_CODE => {
                const dice = cmd.cast(macho.linkedit_data_command).?;
                const ndice = @divExact(dice.datasize, @sizeOf(macho.data_in_code_entry));
                return @ptrCast(
                    [*]const macho.data_in_code_entry,
                    @alignCast(@alignOf(macho.data_in_code_entry), &self.contents[dice.dataoff]),
                )[0..ndice];
            },
            else => {},
        }
    } else return null;
}

fn parseDysymtab(self: Object) ?macho.dysymtab_command {
    var it = LoadCommandIterator{
        .ncmds = self.header.ncmds,
        .buffer = self.contents[@sizeOf(macho.mach_header_64)..][0..self.header.sizeofcmds],
    };
    while (it.next()) |cmd| {
        switch (cmd.cmd()) {
            .DYSYMTAB => {
                return cmd.cast(macho.dysymtab_command).?;
            },
            else => {},
        }
    } else return null;
}

pub fn parseDwarfInfo(self: Object) DwarfInfo {
    var di = DwarfInfo{
        .debug_info = &[0]u8{},
        .debug_abbrev = &[0]u8{},
        .debug_str = &[0]u8{},
    };
    for (self.getSourceSections()) |sect| {
        if (!sect.isDebug()) continue;
        const sectname = sect.sectName();
        if (mem.eql(u8, sectname, "__debug_info")) {
            di.debug_info = self.getSectionContents(sect);
        } else if (mem.eql(u8, sectname, "__debug_abbrev")) {
            di.debug_abbrev = self.getSectionContents(sect);
        } else if (mem.eql(u8, sectname, "__debug_str")) {
            di.debug_str = self.getSectionContents(sect);
        }
    }
    return di;
}

pub fn getSectionContents(self: Object, sect: macho.section_64) []const u8 {
    const size = @intCast(usize, sect.size);
    return self.contents[sect.offset..][0..size];
}

pub fn getSectionAliasSymbolIndex(self: Object, sect_id: u8) u32 {
    const start = @intCast(u32, self.in_symtab.?.len);
    return start + sect_id;
}

pub fn getSectionAliasSymbol(self: *Object, sect_id: u8) macho.nlist_64 {
    return self.symtab[self.getSectionAliasSymbolIndex(sect_id)];
}

pub fn getSectionAliasSymbolPtr(self: *Object, sect_id: u8) *macho.nlist_64 {
    return &self.symtab[self.getSectionAliasSymbolIndex(sect_id)];
}

pub fn getRelocs(self: Object, sect: macho.section_64) []align(1) const macho.relocation_info {
    if (sect.nreloc == 0) return &[0]macho.relocation_info{};
    return @ptrCast([*]align(1) const macho.relocation_info, self.contents.ptr + sect.reloff)[0..sect.nreloc];
}

pub fn getSymbolName(self: Object, index: u32) []const u8 {
    const strtab = self.in_strtab.?;
    const sym = self.symtab[index];

    if (self.getSourceSymbol(index) == null) {
        assert(sym.n_strx == 0);
        return "";
    }

    const start = sym.n_strx;
    const len = self.strtab_lookup[index];

    return strtab[start..][0 .. len - 1 :0];
}

pub fn getAtomIndexForSymbol(self: Object, sym_index: u32) ?AtomIndex {
    const atom_index = self.atom_by_index_table[sym_index];
    if (atom_index == 0) return null;
    return atom_index;
}

pub fn getUnwindRecords(self: Object) []align(1) const macho.compact_unwind_entry {
    const sect = self.unwind_info_sect orelse return &[0]macho.compact_unwind_entry{};
    const data = self.getSectionContents(sect);
    const num_entries = @divExact(data.len, @sizeOf(macho.compact_unwind_entry));
    return @ptrCast([*]align(1) const macho.compact_unwind_entry, data)[0..num_entries];
}
