/// General purpose registers in the AArch64 instruction set
pub const Register = enum(u7) {
    // zig fmt: off
    // 64-bit registers
    x0, x1, x2, x3, x4, x5, x6, x7,
    x8, x9, x10, x11, x12, x13, x14, x15,
    x16, x17, x18, x19, x20, x21, x22, x23,
    x24, x25, x26, x27, x28, x29, x30, xzr,

    // 32-bit registers
    w0, w1, w2, w3, w4, w5, w6, w7,
    w8, w9, w10, w11, w12, w13, w14, w15,
    w16, w17, w18, w19, w20, w21, w22, w23,
    w24, w25, w26, w27, w28, w29, w30, wzr,

    // Stack pointer
    sp, wsp,
    // zig fmt: on

    pub fn id(self: Register) u6 {
        return switch (@intFromEnum(self)) {
            0...63 => return @as(u6, @as(u5, @truncate(@intFromEnum(self)))),
            64...65 => 32,
            else => unreachable,
        };
    }

    pub fn enc(self: Register) u5 {
        return switch (@intFromEnum(self)) {
            0...63 => return @as(u5, @truncate(@intFromEnum(self))),
            64...65 => 31,
            else => unreachable,
        };
    }

    /// Returns the bit-width of the register.
    pub fn size(self: Register) u7 {
        return switch (@intFromEnum(self)) {
            0...31 => 64,
            32...63 => 32,
            64 => 64,
            65 => 32,
            else => unreachable,
        };
    }
};

/// Scalar floating point registers in the aarch64 instruction set
pub const FloatingPointRegister = enum(u8) {
    // zig fmt: off
    // 128-bit registers
    q0, q1, q2, q3, q4, q5, q6, q7,
    q8, q9, q10, q11, q12, q13, q14, q15,
    q16, q17, q18, q19, q20, q21, q22, q23,
    q24, q25, q26, q27, q28, q29, q30, q31,

    // 64-bit registers
    d0, d1, d2, d3, d4, d5, d6, d7,
    d8, d9, d10, d11, d12, d13, d14, d15,
    d16, d17, d18, d19, d20, d21, d22, d23,
    d24, d25, d26, d27, d28, d29, d30, d31,

    // 32-bit registers
    s0, s1, s2, s3, s4, s5, s6, s7,
    s8, s9, s10, s11, s12, s13, s14, s15,
    s16, s17, s18, s19, s20, s21, s22, s23,
    s24, s25, s26, s27, s28, s29, s30, s31,

    // 16-bit registers
    h0, h1, h2, h3, h4, h5, h6, h7,
    h8, h9, h10, h11, h12, h13, h14, h15,
    h16, h17, h18, h19, h20, h21, h22, h23,
    h24, h25, h26, h27, h28, h29, h30, h31,

    // 8-bit registers
    b0, b1, b2, b3, b4, b5, b6, b7,
    b8, b9, b10, b11, b12, b13, b14, b15,
    b16, b17, b18, b19, b20, b21, b22, b23,
    b24, b25, b26, b27, b28, b29, b30, b31,

    // zig fmt: on

    pub fn id(self: FloatingPointRegister) u5 {
        return @as(u5, @truncate(@intFromEnum(self)));
    }

    /// Returns the bit-width of the register.
    pub fn size(self: FloatingPointRegister) u8 {
        return switch (@intFromEnum(self)) {
            0...31 => 128,
            32...63 => 64,
            64...95 => 32,
            96...127 => 16,
            128...159 => 8,
            else => unreachable,
        };
    }
};

/// Represents an instruction in the AArch64 instruction set
pub const Instruction = union(enum) {
    pc_relative_address: packed struct {
        rd: u5,
        immhi: u19,
        fixed: u5 = 0b10000,
        immlo: u2,
        op: u1,
    },
    load_store_register: packed struct {
        rt: u5,
        rn: u5,
        offset: u12,
        opc: u2,
        op1: u2,
        v: u1,
        fixed: u3 = 0b111,
        size: u2,
    },
    load_store_register_pair: packed struct {
        rt1: u5,
        rn: u5,
        rt2: u5,
        imm7: u7,
        load: u1,
        encoding: u2,
        fixed: u5 = 0b101_0_0,
        opc: u2,
    },
    load_literal: packed struct {
        rt: u5,
        imm19: u19,
        fixed: u6 = 0b011_0_00,
        opc: u2,
    },
    exception_generation: packed struct {
        ll: u2,
        op2: u3,
        imm16: u16,
        opc: u3,
        fixed: u8 = 0b1101_0100,
    },
    unconditional_branch_register: packed struct {
        op4: u5,
        rn: u5,
        op3: u6,
        op2: u5,
        opc: u4,
        fixed: u7 = 0b1101_011,
    },
    unconditional_branch_immediate: packed struct {
        imm26: u26,
        fixed: u5 = 0b00101,
        op: u1,
    },
    no_operation: packed struct {
        fixed: u32 = 0b1101010100_0_00_011_0010_0000_000_11111,
    },
    add_subtract_immediate: packed struct {
        rd: u5,
        rn: u5,
        imm12: u12,
        sh: u1,
        fixed: u6 = 0b100010,
        s: u1,
        op: u1,
        sf: u1,
    },
    move_wide_immediate: packed struct {
        rd: u5,
        imm16: u16,
        hw: u2,
        fixed: u6 = 0b100101,
        opc: u2,
        sf: u1,
    },

    pub fn toU32(self: Instruction) u32 {
        return switch (self) {
            .pc_relative_address => |v| @as(u32, @bitCast(v)),
            .load_store_register => |v| @as(u32, @bitCast(v)),
            .load_store_register_pair => |v| @as(u32, @bitCast(v)),
            .load_literal => |v| @as(u32, @bitCast(v)),
            .exception_generation => |v| @as(u32, @bitCast(v)),
            .unconditional_branch_register => |v| @as(u32, @bitCast(v)),
            .unconditional_branch_immediate => |v| @as(u32, @bitCast(v)),
            .no_operation => |v| @as(u32, @bitCast(v)),
            .add_subtract_immediate => |v| @as(u32, @bitCast(v)),
            .move_wide_immediate => |v| @as(u32, @bitCast(v)),
        };
    }

    fn pcRelativeAddress(rd: Register, imm21: i21, op: u1) Instruction {
        assert(rd.size() == 64);
        const imm21_u = @as(u21, @bitCast(imm21));
        return Instruction{
            .pc_relative_address = .{
                .rd = rd.enc(),
                .immlo = @as(u2, @truncate(imm21_u)),
                .immhi = @as(u19, @truncate(imm21_u >> 2)),
                .op = op,
            },
        };
    }

    pub const LoadStoreOffsetImmediate = union(enum) {
        post_index: i9,
        pre_index: i9,
        unsigned: u12,
    };

    pub const LoadStoreOffsetRegister = struct {
        rm: u5,
        shift: union(enum) {
            uxtw: u2,
            lsl: u2,
            sxtw: u2,
            sxtx: u2,
        },
    };

    /// Represents the offset operand of a load or store instruction.
    /// Data can be loaded from memory with either an immediate offset
    /// or an offset that is stored in some register.
    pub const LoadStoreOffset = union(enum) {
        immediate: LoadStoreOffsetImmediate,
        register: LoadStoreOffsetRegister,

        pub const none = LoadStoreOffset{
            .immediate = .{ .unsigned = 0 },
        };

        pub fn toU12(self: LoadStoreOffset) u12 {
            return switch (self) {
                .immediate => |imm_type| switch (imm_type) {
                    .post_index => |v| (@as(u12, @intCast(@as(u9, @bitCast(v)))) << 2) + 1,
                    .pre_index => |v| (@as(u12, @intCast(@as(u9, @bitCast(v)))) << 2) + 3,
                    .unsigned => |v| v,
                },
                .register => |r| switch (r.shift) {
                    .uxtw => |v| (@as(u12, @intCast(r.rm)) << 6) + (@as(u12, @intCast(v)) << 2) + 16 + 2050,
                    .lsl => |v| (@as(u12, @intCast(r.rm)) << 6) + (@as(u12, @intCast(v)) << 2) + 24 + 2050,
                    .sxtw => |v| (@as(u12, @intCast(r.rm)) << 6) + (@as(u12, @intCast(v)) << 2) + 48 + 2050,
                    .sxtx => |v| (@as(u12, @intCast(r.rm)) << 6) + (@as(u12, @intCast(v)) << 2) + 56 + 2050,
                },
            };
        }

        pub fn imm(offset: u12) LoadStoreOffset {
            return .{
                .immediate = .{ .unsigned = offset },
            };
        }

        pub fn imm_post_index(offset: i9) LoadStoreOffset {
            return .{
                .immediate = .{ .post_index = offset },
            };
        }

        pub fn imm_pre_index(offset: i9) LoadStoreOffset {
            return .{
                .immediate = .{ .pre_index = offset },
            };
        }

        pub fn reg(rm: Register) LoadStoreOffset {
            return .{
                .register = .{
                    .rm = rm.enc(),
                    .shift = .{
                        .lsl = 0,
                    },
                },
            };
        }

        pub fn reg_uxtw(rm: Register, shift: u2) LoadStoreOffset {
            assert(rm.size() == 32 and (shift == 0 or shift == 2));
            return .{
                .register = .{
                    .rm = rm.enc(),
                    .shift = .{
                        .uxtw = shift,
                    },
                },
            };
        }

        pub fn reg_lsl(rm: Register, shift: u2) LoadStoreOffset {
            assert(rm.size() == 64 and (shift == 0 or shift == 3));
            return .{
                .register = .{
                    .rm = rm.enc(),
                    .shift = .{
                        .lsl = shift,
                    },
                },
            };
        }

        pub fn reg_sxtw(rm: Register, shift: u2) LoadStoreOffset {
            assert(rm.size() == 32 and (shift == 0 or shift == 2));
            return .{
                .register = .{
                    .rm = rm.enc(),
                    .shift = .{
                        .sxtw = shift,
                    },
                },
            };
        }

        pub fn reg_sxtx(rm: Register, shift: u2) LoadStoreOffset {
            assert(rm.size() == 64 and (shift == 0 or shift == 3));
            return .{
                .register = .{
                    .rm = rm.enc(),
                    .shift = .{
                        .sxtx = shift,
                    },
                },
            };
        }
    };

    /// Which kind of load/store to perform
    const LoadStoreVariant = enum {
        /// 32 bits or 64 bits
        str,
        /// 8 bits, zero-extended
        strb,
        /// 16 bits, zero-extended
        strh,
        /// 32 bits or 64 bits
        ldr,
        /// 8 bits, zero-extended
        ldrb,
        /// 16 bits, zero-extended
        ldrh,
        /// 8 bits, sign extended
        ldrsb,
        /// 16 bits, sign extended
        ldrsh,
        /// 32 bits, sign extended
        ldrsw,
    };

    fn loadStoreRegister(
        rt: Register,
        rn: Register,
        offset: LoadStoreOffset,
        variant: LoadStoreVariant,
    ) Instruction {
        assert(rn.size() == 64);
        assert(rn.id() != Register.xzr.id());

        const off = offset.toU12();

        const op1: u2 = blk: {
            switch (offset) {
                .immediate => |imm| switch (imm) {
                    .unsigned => break :blk 0b01,
                    else => {},
                },
                else => {},
            }
            break :blk 0b00;
        };

        const opc: u2 = blk: {
            switch (variant) {
                .ldr, .ldrh, .ldrb => break :blk 0b01,
                .str, .strh, .strb => break :blk 0b00,
                .ldrsb,
                .ldrsh,
                => switch (rt.size()) {
                    32 => break :blk 0b11,
                    64 => break :blk 0b10,
                    else => unreachable, // unexpected register size
                },
                .ldrsw => break :blk 0b10,
            }
        };

        const size: u2 = blk: {
            switch (variant) {
                .ldr, .str => switch (rt.size()) {
                    32 => break :blk 0b10,
                    64 => break :blk 0b11,
                    else => unreachable, // unexpected register size
                },
                .ldrsw => break :blk 0b10,
                .ldrh, .ldrsh, .strh => break :blk 0b01,
                .ldrb, .ldrsb, .strb => break :blk 0b00,
            }
        };

        return Instruction{
            .load_store_register = .{
                .rt = rt.enc(),
                .rn = rn.enc(),
                .offset = off,
                .opc = opc,
                .op1 = op1,
                .v = 0,
                .size = size,
            },
        };
    }

    fn loadStoreRegisterPair(
        rt1: Register,
        rt2: Register,
        rn: Register,
        offset: i9,
        encoding: u2,
        load: bool,
    ) Instruction {
        assert(rn.size() == 64);
        assert(rn.id() != Register.xzr.id());

        switch (rt1.size()) {
            32 => {
                assert(-256 <= offset and offset <= 252);
                const imm7 = @as(u7, @truncate(@as(u9, @bitCast(offset >> 2))));
                return Instruction{
                    .load_store_register_pair = .{
                        .rt1 = rt1.enc(),
                        .rn = rn.enc(),
                        .rt2 = rt2.enc(),
                        .imm7 = imm7,
                        .load = @intFromBool(load),
                        .encoding = encoding,
                        .opc = 0b00,
                    },
                };
            },
            64 => {
                assert(-512 <= offset and offset <= 504);
                const imm7 = @as(u7, @truncate(@as(u9, @bitCast(offset >> 3))));
                return Instruction{
                    .load_store_register_pair = .{
                        .rt1 = rt1.enc(),
                        .rn = rn.enc(),
                        .rt2 = rt2.enc(),
                        .imm7 = imm7,
                        .load = @intFromBool(load),
                        .encoding = encoding,
                        .opc = 0b10,
                    },
                };
            },
            else => unreachable, // unexpected register size
        }
    }

    fn loadLiteral(rt: Register, imm19: u19) Instruction {
        return Instruction{
            .load_literal = .{
                .rt = rt.enc(),
                .imm19 = imm19,
                .opc = switch (rt.size()) {
                    32 => 0b00,
                    64 => 0b01,
                    else => unreachable, // unexpected register size
                },
            },
        };
    }

    fn exceptionGeneration(
        opc: u3,
        op2: u3,
        ll: u2,
        imm16: u16,
    ) Instruction {
        return Instruction{
            .exception_generation = .{
                .ll = ll,
                .op2 = op2,
                .imm16 = imm16,
                .opc = opc,
            },
        };
    }

    fn unconditionalBranchRegister(
        opc: u4,
        op2: u5,
        op3: u6,
        rn: Register,
        op4: u5,
    ) Instruction {
        assert(rn.size() == 64);

        return Instruction{
            .unconditional_branch_register = .{
                .op4 = op4,
                .rn = rn.enc(),
                .op3 = op3,
                .op2 = op2,
                .opc = opc,
            },
        };
    }

    fn unconditionalBranchImmediate(
        op: u1,
        offset: i28,
    ) Instruction {
        return Instruction{
            .unconditional_branch_immediate = .{
                .imm26 = @as(u26, @bitCast(@as(i26, @intCast(offset >> 2)))),
                .op = op,
            },
        };
    }

    fn addSubtractImmediate(
        op: u1,
        s: u1,
        rd: Register,
        rn: Register,
        imm12: u12,
        shift: bool,
    ) Instruction {
        assert(rd.size() == rn.size());
        assert(rn.id() != Register.xzr.id());

        return Instruction{
            .add_subtract_immediate = .{
                .rd = rd.enc(),
                .rn = rn.enc(),
                .imm12 = imm12,
                .sh = @intFromBool(shift),
                .s = s,
                .op = op,
                .sf = switch (rd.size()) {
                    32 => 0b0,
                    64 => 0b1,
                    else => unreachable, // unexpected register size
                },
            },
        };
    }

    fn moveWideImmediate(opc: u2, rd: Register, imm16: u16, shift: u6) Instruction {
        assert(shift % 16 == 0);
        assert(!(rd.size() == 32 and shift > 16));
        assert(!(rd.size() == 64 and shift > 48));

        return Instruction{
            .move_wide_immediate = .{
                .rd = rd.enc(),
                .imm16 = imm16,
                .hw = @as(u2, @intCast(shift / 16)),
                .opc = opc,
                .sf = switch (rd.size()) {
                    32 => 0,
                    64 => 1,
                    else => unreachable, // unexpected register size
                },
            },
        };
    }

    pub fn movz(rd: Register, imm16: u16, shift: u6) Instruction {
        return moveWideImmediate(0b10, rd, imm16, shift);
    }

    pub fn movk(rd: Register, imm16: u16, shift: u6) Instruction {
        return moveWideImmediate(0b11, rd, imm16, shift);
    }

    pub fn adr(rd: Register, imm21: i21) Instruction {
        return pcRelativeAddress(rd, imm21, 0b0);
    }

    pub fn adrp(rd: Register, imm21: i21) Instruction {
        return pcRelativeAddress(rd, imm21, 0b1);
    }

    pub fn ldrLiteral(rt: Register, literal: u19) Instruction {
        return loadLiteral(rt, literal);
    }

    pub fn ldr(rt: Register, rn: Register, offset: LoadStoreOffset) Instruction {
        return loadStoreRegister(rt, rn, offset, .ldr);
    }

    pub const LoadStorePairOffset = struct {
        encoding: enum(u2) {
            post_index = 0b01,
            signed = 0b10,
            pre_index = 0b11,
        },
        offset: i9,

        pub fn none() LoadStorePairOffset {
            return .{ .encoding = .signed, .offset = 0 };
        }

        pub fn post_index(imm: i9) LoadStorePairOffset {
            return .{ .encoding = .post_index, .offset = imm };
        }

        pub fn pre_index(imm: i9) LoadStorePairOffset {
            return .{ .encoding = .pre_index, .offset = imm };
        }

        pub fn signed(imm: i9) LoadStorePairOffset {
            return .{ .encoding = .signed, .offset = imm };
        }
    };

    pub fn stp(rt1: Register, rt2: Register, rn: Register, offset: LoadStorePairOffset) Instruction {
        return loadStoreRegisterPair(rt1, rt2, rn, offset.offset, @intFromEnum(offset.encoding), false);
    }

    pub fn brk(imm16: u16) Instruction {
        return exceptionGeneration(0b001, 0b000, 0b00, imm16);
    }

    pub fn br(rn: Register) Instruction {
        return unconditionalBranchRegister(0b0000, 0b11111, 0b000000, rn, 0b00000);
    }

    pub fn b(offset: i28) Instruction {
        return unconditionalBranchImmediate(0, offset);
    }

    pub fn nop() Instruction {
        return Instruction{ .no_operation = .{} };
    }

    pub fn add(rd: Register, rn: Register, imm: u12, shift: bool) Instruction {
        return addSubtractImmediate(0b0, 0b0, rd, rn, imm, shift);
    }
};

pub inline fn isArithmeticOp(inst: *const [4]u8) bool {
    const group_decode = @as(u5, @truncate(inst[3]));
    return ((group_decode >> 2) == 4);
}

pub fn writeAddImmInst(value: u12, code: *[4]u8) void {
    var inst = Instruction{
        .add_subtract_immediate = mem.bytesToValue(std.meta.TagPayload(
            Instruction,
            Instruction.add_subtract_immediate,
        ), code),
    };
    inst.add_subtract_immediate.imm12 = value;
    mem.writeInt(u32, code, inst.toU32(), .little);
}

pub fn writeLoadStoreRegInst(value: u12, code: *[4]u8) void {
    var inst: Instruction = .{
        .load_store_register = mem.bytesToValue(std.meta.TagPayload(
            Instruction,
            Instruction.load_store_register,
        ), code),
    };
    inst.load_store_register.offset = value;
    mem.writeInt(u32, code, inst.toU32(), .little);
}

pub fn calcNumberOfPages(saddr: u64, taddr: u64) error{Overflow}!i21 {
    const spage = math.cast(i32, saddr >> 12) orelse return error.Overflow;
    const tpage = math.cast(i32, taddr >> 12) orelse return error.Overflow;
    const pages = math.cast(i21, tpage - spage) orelse return error.Overflow;
    return pages;
}

pub fn writeAdrpInst(pages: u21, code: *[4]u8) void {
    var inst = Instruction{
        .pc_relative_address = mem.bytesToValue(std.meta.TagPayload(
            Instruction,
            Instruction.pc_relative_address,
        ), code),
    };
    inst.pc_relative_address.immhi = @as(u19, @truncate(pages >> 2));
    inst.pc_relative_address.immlo = @as(u2, @truncate(pages));
    mem.writeInt(u32, code, inst.toU32(), .little);
}

pub fn writeBranchImm(disp: i28, code: *[4]u8) void {
    var inst = Instruction{
        .unconditional_branch_immediate = mem.bytesToValue(std.meta.TagPayload(
            Instruction,
            Instruction.unconditional_branch_immediate,
        ), code),
    };
    inst.unconditional_branch_immediate.imm26 = @as(u26, @truncate(@as(u28, @bitCast(disp >> 2))));
    mem.writeInt(u32, code, inst.toU32(), .little);
}

const std = @import("std");
const builtin = @import("builtin");
const math = std.math;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
