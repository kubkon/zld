const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const log = std.log.scoped(.macho);
const macho = std.macho;
const mem = std.mem;
const native_endian = builtin.target.cpu.arch.endian();

const MachO = @import("../MachO.zig");

fn readFatStruct(reader: anytype, comptime T: type) !T {
    // Fat structures (fat_header & fat_arch) are always written and read to/from
    // disk in big endian order.
    var res = try reader.readStruct(T);
    if (native_endian != std.builtin.Endian.Big) {
        mem.byteSwapAllFields(T, &res);
    }
    return res;
}

pub fn isFatLibrary(file: std.fs.File) bool {
    const reader = file.reader();
    const hdr = readFatStruct(reader, macho.fat_header) catch return false;
    defer file.seekTo(0) catch {};
    return hdr.magic == macho.FAT_MAGIC;
}

pub const Arch = struct {
    tag: std.Target.Cpu.Arch,
    offset: u64,
};

pub fn parseArchs(file: std.fs.File, buffer: *[2]Arch) ![]const Arch {
    const fat_header = try readFatStruct(file.reader(), macho.fat_header);
    assert(fat_header.magic == macho.FAT_MAGIC);

    var count: usize = 0;
    var fat_arch_index: u32 = 0;
    while (fat_arch_index < fat_header.nfat_arch) : (fat_arch_index += 1) {
        const fat_arch = try readFatStruct(file.reader(), macho.fat_arch);
        // If we come across an architecture that we do not know how to handle, that's
        // fine because we can keep looking for one that might match.
        const arch: std.Target.Cpu.Arch = switch (fat_arch.cputype) {
            macho.CPU_TYPE_ARM64 => .aarch64,
            macho.CPU_TYPE_X86_64 => .x86_64,
            else => continue,
        };
        buffer[count] = .{ .tag = arch, .offset = fat_arch.offset };
        count += 1;
    }

    return buffer[0..count];
}
