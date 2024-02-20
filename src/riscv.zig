pub fn writeSetSub6(comptime op: enum { set, sub }, code: *[1]u8, addend: anytype) void {
    const mask: u8 = 0b11_000000;
    const actual: i8 = @truncate(addend);
    var value: u8 = mem.readInt(u8, code, .little);
    switch (op) {
        .set => value = (value & mask) | @as(u8, @bitCast(actual & ~mask)),
        .sub => value = (value & mask) | (@as(u8, @bitCast(@as(i8, @bitCast(value)) -| actual)) & ~mask),
    }
    mem.writeInt(u8, code, value, .little);
}

pub fn writeAddend(
    comptime Int: type,
    comptime op: enum { add, sub },
    code: *[@typeInfo(Int).Int.bits / 8]u8,
    value: anytype,
) void {
    var V: Int = mem.readInt(Int, code, .little);
    const addend: Int = @truncate(value);
    switch (op) {
        .add => V +|= addend, // TODO: I think saturating arithmetic is correct here
        .sub => V -|= addend,
    }
    mem.writeInt(Int, code, V, .little);
}

pub fn writeInstU(code: *[4]u8, value: u32) void {
    const inst_mask: u32 = 0b00000000000000000000_11111_1111111;
    const val_mask: u32 = 0xffff_f000;
    var inst = mem.readInt(u32, code, .little);
    inst &= inst_mask;
    const compensated: u32 = @bitCast(@as(i32, @bitCast(value)) + 0x800);
    inst |= (compensated & val_mask);
    mem.writeInt(u32, code, inst, .little);
}

pub fn writeInstI(code: *[4]u8, value: u32) void {
    const inst_mask: u32 = 0b00000000000_11111_111_11111_1111111;
    const val_mask: u32 = 0b111_11111111;
    var inst = mem.readInt(u32, code, .little);
    inst &= inst_mask;
    inst |= ((value & val_mask) << 20);
    mem.writeInt(u32, code, inst, .little);
}

pub fn writeInstS(code: *[4]u8, value: u32) void {
    const inst_mask: u32 = 0b0000000_11111_11111_111_11111_1111111;
    const val_mask: u32 = 0b111_1111;
    var inst = mem.readInt(u32, code, .little);
    inst &= inst_mask;
    inst |= ((value & val_mask) << 25);
    mem.writeInt(u32, code, inst, .little);
}

const mem = std.mem;
const std = @import("std");
