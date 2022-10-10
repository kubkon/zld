const std = @import("std");
const log = std.log.scoped(.thunks);
const macho = std.macho;
const math = std.math;
const mem = std.mem;

const aarch64 = @import("../aarch64.zig");

const Atom = @import("Atom.zig");
const AtomIndex = MachO.AtomIndex;
const MachO = @import("../MachO.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;

const ThunkIndex = u32;

/// Branch instruction has 26 bits immediate but 4 byte aligned.
const jump_bits = @bitSizeOf(i28);

const max_distance = (1 << (jump_bits - 1));

/// A branch will need an extender if its target is larger than
/// `2^(jump_bits - 1) - margin` where margin is some arbitrary number.
/// mold uses 5MiB margin, while ld64 uses 4MiB margin. We will follow mold
/// and assume margin to be 5MiB.
const max_allowed_distance = max_distance - 0x500_000;

const group_size = max_allowed_distance / 10;

pub const Thunk = struct {
    start_index: AtomIndex,
    len: usize,

    pub fn getStartAtomIndex(self: Thunk) ?AtomIndex {
        if (self.len == 0) return null;
        return self.start_index;
    }

    pub fn getEndAtomIndex(self: Thunk, macho_file: *MachO) ?AtomIndex {
        if (self.len == 0) return null;

        var atom_index = self.start_index;
        var count: usize = 0;
        while (true) {
            const atom = macho_file.getAtom(atom_index);
            if (count == self.len) return atom_index;
            count += 1;
            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }

        return null;
    }

    pub fn getSize(self: Thunk) u64 {
        return 12 * self.len;
    }

    pub fn getAlignment() u32 {
        return @alignOf(u32);
    }
};

pub fn createThunks(macho_file: *MachO, sect_id: u8, reverse_lookups: [][]u32) !void {
    const header = &macho_file.sections.items(.header)[sect_id];
    if (header.size == 0) return;

    const gpa = macho_file.base.allocator;
    const first_atom_index = macho_file.sections.items(.first_atom_index)[sect_id];

    header.size = 0;
    header.@"align" = 0;

    var atom_count: u32 = 0;

    {
        var atom_index = first_atom_index;
        while (true) {
            const atom = macho_file.getAtom(atom_index);
            const sym = macho_file.getSymbolPtr(atom.getSymbolWithLoc());
            sym.n_value = 0;
            atom_count += 1;

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    var allocated = std.AutoHashMap(AtomIndex, void).init(gpa);
    defer allocated.deinit();
    try allocated.ensureTotalCapacity(atom_count);

    var group_start = first_atom_index;
    var group_end = first_atom_index;
    var offset: u64 = 0;

    const group_start_atom = macho_file.getAtom(group_start);

    while (true) {
        const atom = macho_file.getAtom(group_end);
        macho_file.logAtom(group_end, log);
        offset = mem.alignForwardGeneric(u64, offset, try math.powi(u32, 2, atom.alignment));

        const sym = macho_file.getSymbolPtr(atom.getSymbolWithLoc());
        sym.n_value = offset;
        offset += atom.size;

        header.@"align" = @maximum(header.@"align", atom.alignment);

        allocated.putAssumeCapacityNoClobber(group_end, {});

        const group_start_sym = macho_file.getSymbol(group_start_atom.getSymbolWithLoc());
        if (offset - group_start_sym.n_value >= max_allowed_distance) break;

        if (atom.next_index) |next_index| {
            group_end = next_index;
        } else break;
    }

    log.debug("GROUP END at {d}", .{group_end});

    // Insert thunk at group_end
    const thunk_index = @intCast(u32, macho_file.thunks.items.len);
    try macho_file.thunks.append(gpa, .{ .start_index = undefined, .len = 0 });

    // Scan relocs in the group and create trampolines for any unreachable callsite.
    var atom_index = group_start;
    while (true) {
        const atom = macho_file.getAtom(atom_index);
        try scanRelocs(
            macho_file,
            atom_index,
            reverse_lookups[atom.file.?],
            allocated,
            thunk_index,
            group_end,
        );

        if (atom_index == group_end) break;

        if (atom.next_index) |next_index| {
            atom_index = next_index;
        } else break;
    }

    offset = mem.alignForwardGeneric(u64, offset, Thunk.getAlignment());
    allocateThunk(macho_file, thunk_index, offset, header);
    offset += macho_file.thunks.items[thunk_index].getSize();

    // Allocate the rest of the atoms.
    // TODO: for now, assume need for only one thunk.
    if (macho_file.getAtom(group_end).next_index) |first_after| {
        atom_index = first_after;

        while (true) {
            const atom = macho_file.getAtom(atom_index);
            macho_file.logAtom(atom_index, log);
            offset = mem.alignForwardGeneric(u64, offset, try math.powi(u32, 2, atom.alignment));

            const sym = macho_file.getSymbolPtr(atom.getSymbolWithLoc());
            sym.n_value = offset;
            offset += atom.size;

            header.@"align" = @maximum(header.@"align", atom.alignment);

            allocated.putAssumeCapacityNoClobber(atom_index, {});

            if (atom.next_index) |next_index| {
                atom_index = next_index;
            } else break;
        }
    }

    header.size = @intCast(u32, offset);
}

fn allocateThunk(
    macho_file: *MachO,
    thunk_index: ThunkIndex,
    base_offset: u64,
    header: *macho.section_64,
) void {
    const thunk = macho_file.thunks.items[thunk_index];
    if (thunk.len == 0) return;

    const first_atom_index = thunk.getStartAtomIndex().?;
    const end_atom_index = thunk.getEndAtomIndex(macho_file);

    var atom_index = first_atom_index;
    var offset = base_offset;
    while (true) {
        const atom = macho_file.getAtom(atom_index);
        macho_file.logAtom(atom_index, log);
        offset = mem.alignForwardGeneric(u64, offset, Thunk.getAlignment());

        const sym = macho_file.getSymbolPtr(atom.getSymbolWithLoc());
        sym.n_value = offset;
        offset += atom.size;

        header.@"align" = @maximum(header.@"align", atom.alignment);

        if (end_atom_index) |ei| {
            if (ei == atom_index) break;
        }

        if (atom.next_index) |next_index| {
            atom_index = next_index;
        } else break;
    }
}

fn scanRelocs(
    macho_file: *MachO,
    atom_index: AtomIndex,
    reverse_lookup: []u32,
    allocated: std.AutoHashMap(AtomIndex, void),
    thunk_index: ThunkIndex,
    group_end: AtomIndex,
) !void {
    const atom = macho_file.getAtom(atom_index);
    const object = macho_file.objects.items[atom.file.?];

    const base_offset = if (object.getSourceSymbol(atom.sym_index)) |source_sym| blk: {
        const source_sect = object.getSourceSection(source_sym.n_sect - 1);
        break :blk @intCast(i32, source_sym.n_value - source_sect.addr);
    } else 0;

    const relocs = Atom.getAtomRelocs(macho_file, atom_index);
    for (relocs) |rel| {
        if (!relocNeedsThunk(rel)) continue;

        const target = Atom.parseRelocTarget(macho_file, atom_index, rel, reverse_lookup) catch unreachable;
        if (isReachable(macho_file, atom_index, rel, base_offset, target, allocated)) continue;

        log.debug("{x}: source = {s}@{x}, target = {s}@{x} unreachable", .{
            rel.r_address - base_offset,
            macho_file.getSymbolName(atom.getSymbolWithLoc()),
            macho_file.getSymbol(atom.getSymbolWithLoc()).n_value,
            macho_file.getSymbolName(target),
            macho_file.getSymbol(target).n_value,
        });

        const gpa = macho_file.base.allocator;
        const target_sym = macho_file.getSymbol(target);

        if (target_sym.undf()) {
            const actual_target = macho_file.stubs.get(target).?;
            const gop = try macho_file.thunk_table.getOrPut(gpa, .{
                .sym_index = actual_target,
                .file = null,
            });
            if (!gop.found_existing) {
                const thunk_atom_index = try createThunkAtom(macho_file, thunk_index, group_end);
                const thunk_atom = macho_file.getAtom(thunk_atom_index);
                gop.value_ptr.* = thunk_atom.sym_index;
            }
        } else {
            const gop = try macho_file.thunk_table.getOrPut(gpa, target);
            if (!gop.found_existing) {
                const thunk_atom_index = try createThunkAtom(macho_file, thunk_index, group_end);
                const thunk_atom = macho_file.getAtom(thunk_atom_index);
                gop.value_ptr.* = thunk_atom.sym_index;
            }
        }
    }
}

inline fn relocNeedsThunk(rel: macho.relocation_info) bool {
    const rel_type = @intToEnum(macho.reloc_type_arm64, rel.r_type);
    return rel_type == .ARM64_RELOC_BRANCH26;
}

fn isReachable(
    macho_file: *MachO,
    atom_index: AtomIndex,
    rel: macho.relocation_info,
    base_offset: i32,
    target: SymbolWithLoc,
    allocated: std.AutoHashMap(AtomIndex, void),
) bool {
    if (macho_file.getStubsAtomIndexForSymbol(target)) |_| return false;

    const source_atom = macho_file.getAtom(atom_index);
    const source_sym = macho_file.getSymbol(source_atom.getSymbolWithLoc());

    const target_atom_index = macho_file.getAtomIndexForSymbol(target).?;
    const target_atom = macho_file.getAtom(target_atom_index);
    const target_sym = macho_file.getSymbol(target_atom.getSymbolWithLoc());

    if (source_sym.n_sect != target_sym.n_sect) return false;

    if (!allocated.contains(target_atom_index)) return false;

    const source_addr = source_sym.n_value + @intCast(u32, rel.r_address - base_offset);
    const target_addr = Atom.getRelocTargetAddress(macho_file, rel, target, false) catch unreachable;
    _ = Atom.calcPcRelativeDisplacementArm64(source_addr, target_addr) catch
        return false;

    return true;
}

fn createThunkAtom(macho_file: *MachO, thunk_index: ThunkIndex, first_before: AtomIndex) !AtomIndex {
    const gpa = macho_file.base.allocator;
    const sym_index = try macho_file.allocateSymbol();
    const atom_index = try macho_file.createEmptyAtom(sym_index, @sizeOf(u32) * 3, 2);
    const sym = macho_file.getSymbolPtr(.{ .sym_index = sym_index, .file = null });
    sym.n_type = macho.N_SECT;

    const sect_id = macho_file.getSectionByName("__TEXT", "__text") orelse unreachable;
    sym.n_sect = sect_id + 1;

    try macho_file.atom_by_index_table.putNoClobber(gpa, sym_index, atom_index);

    const thunk = &macho_file.thunks.items[thunk_index];
    const atom = macho_file.getAtomPtr(atom_index);

    if (thunk.getEndAtomIndex(macho_file)) |end_atom_index| {
        const end_atom = macho_file.getAtomPtr(end_atom_index);
        const prev_atom = macho_file.getAtomPtr(end_atom.prev_index.?);
        prev_atom.next_index = atom_index;
        atom.prev_index = end_atom.prev_index.?;
        atom.next_index = end_atom_index;
        end_atom.prev_index = atom_index;
    } else {
        const first_before_atom = macho_file.getAtomPtr(first_before);
        if (first_before_atom.next_index) |first_after_index| {
            const first_after_atom = macho_file.getAtomPtr(first_after_index);
            first_after_atom.prev_index = atom_index;
            atom.next_index = first_after_index;
        }
        first_before_atom.next_index = atom_index;
        atom.prev_index = first_before;
        thunk.start_index = atom_index;
    }

    thunk.len += 1;

    return atom_index;
}

pub fn writeThunkCode(macho_file: *MachO, atom_index: AtomIndex, writer: anytype) !void {
    const atom = macho_file.getAtom(atom_index);
    const sym = macho_file.getSymbol(atom.getSymbolWithLoc());
    const source_addr = sym.n_value;
    const target_addr = for (macho_file.thunk_table.keys()) |target| {
        const sym_index = macho_file.thunk_table.get(target).?;
        if (sym_index == atom.sym_index) break macho_file.getSymbol(target).n_value;
    } else unreachable;

    const pages = Atom.calcNumberOfPages(source_addr, target_addr);
    try writer.writeIntLittle(u32, aarch64.Instruction.adrp(.x16, pages).toU32());
    const off = try Atom.calcPageOffset(target_addr, .arithmetic);
    try writer.writeIntLittle(u32, aarch64.Instruction.add(.x16, .x16, off, false).toU32());
    try writer.writeIntLittle(u32, aarch64.Instruction.br(.x16).toU32());
}
