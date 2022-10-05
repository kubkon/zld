const std = @import("std");
const log = std.log.scoped(.thunks);
const macho = std.macho;
const math = std.math;
const mem = std.mem;

const Atom = @import("Atom.zig");
const AtomIndex = MachO.AtomIndex;
const MachO = @import("../MachO.zig");
const SymbolWithLoc = MachO.SymbolWithLoc;

/// Branch instruction has 26 bits immediate but 4 byte aligned.
const jump_bits = @bitSizeOf(i28);

pub const max_distance = (1 << (jump_bits - 1));

/// A branch will need an extender if its target is larger than
/// `2^(jump_bits - 1) - margin` where margin is some arbitrary number.
/// mold uses 5MiB margin, while ld64 uses 4MiB margin. We will follow mold
/// and assume margin to be 5MiB.
const max_allowed_distance = max_distance - 0x500_000;

const group_size = max_allowed_distance / 10;

pub fn createThunks(macho_file: *MachO, sect_id: u8, reverse_lookups: [][]u32) !void {
    const header = &macho_file.sections.items(.header)[sect_id];
    if (header.size == 0) return;

    _ = reverse_lookups;
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
) bool {
    if (macho_file.getStubsAtomIndexForSymbol(target)) |_| return false;

    const source_atom = macho_file.getAtom(atom_index);
    const source_sym = macho_file.getSymbol(source_atom.getSymbolWithLoc());

    const target_atom_index = macho_file.getAtomIndexForSymbol(target).?;
    const target_atom = macho_file.getAtom(target_atom_index);
    const target_sym = macho_file.getSymbol(target_atom.getSymbolWithLoc());

    if (source_sym.n_sect != target_sym.n_sect) return false;

    if (target_sym.n_value == @bitCast(u64, -1)) return false;

    const source_addr = source_sym.n_value + @intCast(u32, rel.r_address - base_offset);
    const target_addr = try Atom.getRelocTargetAddress(macho_file, rel, target, false);
    _ = Atom.calcPcRelativeDisplacementArm64(source_addr, target_addr) catch
        return false;

    return true;
}
