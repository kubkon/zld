const std = @import("std");
const math = std.math;

const MachO = @import("../MachO.zig");

/// Branch instruction has 26 bits immediate but 4 byte aligned.
const jump_bits = @bitSizeOf(i28);

/// A branch will need an extender if its target is larger than
/// `2^(jump_bits - 1) - margin` where margin is some arbitrary number.
/// mold uses 5MiB margin, while ld64 uses 4MiB margin. We will follow mold
/// and assume margin to be 5MiB.
const max_distance: i64 = math.powi(2, jump_bits - 1) - 0x500_000;

pub fn createThunks(macho_file: *MachO, sect_id: u8, reverse_lookups: [][]u32) !void {
    _ = macho_file;
    _ = sect_id;
    _ = reverse_lookups;
    return error.TODOThunks;
}
