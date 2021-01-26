pub const Arm64 = struct {
    pub const Branch = packed struct {
        imm26: u26,
        fixed: u5 = 0b00101,
        link: u1,
    };

    pub const BranchRegister = packed struct {
        _1: u5 = 0b0000_0,
        rn: u5,
        _2: u11 = 0b1111_1000_000,
        link: u1,
        _3: u10 = 0b1101_0110_00,
    };

    pub const Address = packed struct {
        rd: u5,
        immhi: u19,
        fixed: u5 = 0b10000,
        immlo: u2,
        op: u1,
    };

    pub const LoadRegister = packed struct {
        rt: u5,
        rn: u5,
        offset: u12,
        opc: u2,
        op1: u2,
        fixed: u4 = 0b111_0,
        size: u2,
    };

    pub const LoadLiteral = packed struct {
        rt: u5,
        imm19: u19,
        fixed: u6 = 0b011_0_00,
        opc: u2,
    };
};
