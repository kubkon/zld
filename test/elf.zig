pub const Case = struct {
    build_root: []const u8,
    import: type,
};

pub const cases = [_]Case{
    .{
        .build_root = "test/elf/dso-ifunc",
        .import = @import("elf/dso-ifunc/build.zig"),
    },
};
